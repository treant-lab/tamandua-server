defmodule TamanduaServer.Detection.DNSBlocklist do
  @moduledoc """
  Tenant-scoped DNS blocklist persistence.

  This module is the durable source of truth. Every operation canonicalizes
  the organization, enters a transaction-local tenant context, and includes
  an explicit organization predicate.
  """

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Detection.DNSBlocklistEntry

  @default_list_limit 10_001
  @default_max_domains 500
  @hard_max_domains 2_000
  @default_max_reason_bytes 1_024
  @hard_max_reason_bytes 4_096
  @default_max_blocked_by_bytes 255
  @hard_max_blocked_by_bytes 512
  @default_max_source_bytes 64
  @hard_max_source_bytes 128
  @max_domain_bytes 253

  def list_entries(organization_id, limit \\ @default_list_limit)

  def list_entries(organization_id, limit) when is_integer(limit) and limit > 0 do
    with {:ok, organization_id} <- canonical_organization_id(organization_id) do
      entries =
        MultiTenant.with_organization(organization_id, fn ->
          DNSBlocklistEntry
          |> where([e], e.organization_id == ^organization_id and e.active == true)
          |> order_by([e], desc: e.updated_at)
          |> limit(^limit)
          |> Repo.all()
        end)

      {:ok, entries}
    end
  rescue
    _ -> {:error, :blocklist_unavailable}
  end

  def list_entries(_organization_id, _limit), do: {:error, :invalid_blocklist_request}

  def find_active_entry(organization_id, domains) when is_list(domains) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id) do
      normalized_domains =
        domains
        |> Enum.map(&normalize_domain/1)
        |> Enum.reject(&(&1 == ""))
        |> Enum.uniq()

      entry =
        MultiTenant.with_organization(organization_id, fn ->
          DNSBlocklistEntry
          |> where(
            [e],
            e.organization_id == ^organization_id and e.active == true and
              e.normalized_domain in ^normalized_domains
          )
          |> order_by([e], desc: e.updated_at)
          |> limit(1)
          |> Repo.one()
        end)

      {:ok, entry}
    end
  rescue
    _ -> {:error, :blocklist_unavailable}
  end

  def find_active_entry(_organization_id, _domains),
    do: {:error, :invalid_blocklist_request}

  def add_entries(organization_id, domains, reason, blocked_by, source \\ "manual")

  def add_entries(organization_id, domains, reason, blocked_by, source) when is_list(domains) do
    with {:ok, organization_id} <- canonical_organization_id(organization_id),
         {:ok, normalized} <- prepare_batch(domains, reason, blocked_by, source) do
      now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

      applied =
        MultiTenant.with_organization(organization_id, fn ->
          rows =
            Enum.map(normalized, fn domain ->
              %{
                id: Ecto.UUID.generate(),
                organization_id: organization_id,
                domain: domain,
                normalized_domain: domain,
                reason: reason,
                blocked_by: blocked_by,
                source: source,
                active: true,
                inserted_at: now,
                updated_at: now
              }
            end)

          {count, returned} =
            Repo.insert_all(DNSBlocklistEntry, rows,
              on_conflict:
                {:replace, [:domain, :reason, :blocked_by, :source, :active, :updated_at]},
              conflict_target: [:organization_id, :normalized_domain],
              returning: [:normalized_domain]
            )

          applied = Enum.map(returned, & &1.normalized_domain) |> Enum.sort()

          if count == length(normalized) and applied == Enum.sort(normalized) do
            applied
          else
            Repo.rollback(:incomplete_blocklist_batch)
          end
        end)

      {:ok, applied}
    end
  rescue
    _ -> {:error, :blocklist_unavailable}
  end

  def add_entries(_organization_id, _domains, _reason, _blocked_by, _source),
    do: {:error, :invalid_blocklist_request}

  def remove_entry(organization_id, domain) do
    normalized_domain = normalize_domain(domain)

    with {:ok, organization_id} <- canonical_organization_id(organization_id),
         false <- invalid_domain?(normalized_domain) do
      query =
        from(e in DNSBlocklistEntry,
          where:
            e.organization_id == ^organization_id and
              e.normalized_domain == ^normalized_domain and
              e.active == true
        )

      MultiTenant.with_organization(organization_id, fn ->
        case Repo.update_all(query, set: [active: false, updated_at: DateTime.utc_now()]) do
          {0, _} -> {:error, :not_found}
          {_count, _} -> :ok
        end
      end)
    else
      true -> {:error, :invalid_domain}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :blocklist_unavailable}
  end

  @spec active_for_domain?(term(), term()) :: {:ok, boolean()} | {:error, atom()}
  def active_for_domain?(organization_id, domain) do
    case find_active_entry(organization_id, [domain]) do
      {:ok, entry} -> {:ok, entry != nil}
      {:error, reason} -> {:error, reason}
    end
  end

  def normalize_domain(domain) when is_binary(domain) do
    domain
    |> String.trim()
    |> String.trim_trailing(".")
    |> String.downcase()
  end

  def normalize_domain(_), do: ""

  @doc false
  def prepare_batch(domains, reason, blocked_by, source) when is_list(domains) do
    limits = mutation_limits()

    cond do
      domains == [] ->
        {:error, :empty_domains}

      length(domains) > limits.max_domains ->
        {:error, :too_many_domains}

      not bounded_binary?(reason, limits.max_reason_bytes) ->
        {:error, :reason_too_large}

      not bounded_binary?(blocked_by, limits.max_blocked_by_bytes) ->
        {:error, :blocked_by_too_large}

      not bounded_binary?(source, limits.max_source_bytes) ->
        {:error, :source_too_large}

      true ->
        normalized = domains |> Enum.map(&normalize_domain/1) |> Enum.uniq()

        if Enum.any?(normalized, &invalid_domain?/1),
          do: {:error, :invalid_domain},
          else: {:ok, normalized}
    end
  end

  def prepare_batch(_domains, _reason, _blocked_by, _source),
    do: {:error, :invalid_blocklist_request}

  @doc false
  def mutation_limits do
    config = Application.get_env(:tamandua_server, :dns_blocklist_mutations, [])

    %{
      max_domains: bounded_config(config, :max_domains, @default_max_domains, @hard_max_domains),
      max_reason_bytes:
        bounded_config(
          config,
          :max_reason_bytes,
          @default_max_reason_bytes,
          @hard_max_reason_bytes
        ),
      max_blocked_by_bytes:
        bounded_config(
          config,
          :max_blocked_by_bytes,
          @default_max_blocked_by_bytes,
          @hard_max_blocked_by_bytes
        ),
      max_source_bytes:
        bounded_config(
          config,
          :max_source_bytes,
          @default_max_source_bytes,
          @hard_max_source_bytes
        )
    }
  end

  defp invalid_domain?(domain) do
    domain == "" or byte_size(domain) > @max_domain_bytes or not valid_dns_name?(domain)
  end

  # Blocklist values are dispatched to endpoint agents, which write them to
  # the hosts file. Accept only an ASCII DNS name so control characters,
  # whitespace, wildcards and hosts-file line injection never cross that
  # trust boundary.
  defp valid_dns_name?(domain) do
    domain
    |> String.split(".", trim: false)
    |> Enum.all?(fn label ->
      byte_size(label) in 1..63 and
        Regex.match?(~r/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, label)
    end)
  end

  defp bounded_binary?(value, max_bytes),
    do: is_binary(value) and byte_size(value) <= max_bytes

  defp bounded_config(config, key, default, hard_max) do
    case Keyword.get(config, key, default) do
      value when is_integer(value) and value > 0 -> min(value, hard_max)
      _invalid -> default
    end
  end

  defp canonical_organization_id(organization_id) do
    case Ecto.UUID.cast(organization_id) do
      {:ok, canonical} -> {:ok, canonical}
      :error -> {:error, :invalid_organization}
    end
  end
end
