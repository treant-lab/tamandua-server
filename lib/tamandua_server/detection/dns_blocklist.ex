defmodule TamanduaServer.Detection.DNSBlocklist do
  @moduledoc """
  Tenant-scoped DNS blocklist persistence.

  The DNS analyzer keeps an ETS cache for fast runtime matching. This module is
  the durable source of truth and always scopes entries by organization.
  """

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Detection.DNSBlocklistEntry

  def list_entries(nil), do: []

  def list_entries(organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      DNSBlocklistEntry
      |> where([e], e.organization_id == ^organization_id and e.active == true)
      |> order_by([e], desc: e.updated_at)
      |> Repo.all()
    end)
  end

  def list_active_entries do
    MultiTenant.with_bypass(fn ->
      DNSBlocklistEntry
      |> where([e], e.active == true)
      |> Repo.all()
    end)
  end

  def add_entries(organization_id, domains, reason, blocked_by, source \\ "manual")

  def add_entries(nil, _domains, _reason, _blocked_by, _source), do: {:error, :missing_organization}

  def add_entries(organization_id, domains, reason, blocked_by, source) when is_list(domains) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    normalized =
      domains
      |> Enum.map(&normalize_domain/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()

    count =
      MultiTenant.with_organization(organization_id, fn ->
        Enum.count(normalized, fn domain ->
          attrs = %{
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

          %DNSBlocklistEntry{}
          |> DNSBlocklistEntry.changeset(attrs)
          |> Repo.insert(
            on_conflict: [
              set: [
                domain: domain,
                reason: reason,
                blocked_by: blocked_by,
                source: source,
                active: true,
                updated_at: now
              ]
            ],
            conflict_target: [:organization_id, :normalized_domain]
          )
          |> case do
            {:ok, _entry} -> true
            {:error, _changeset} -> false
          end
        end)
      end)

    {:ok, count}
  end

  def remove_entry(nil, _domain), do: {:error, :missing_organization}

  def remove_entry(organization_id, domain) do
    normalized_domain = normalize_domain(domain)

    query =
      from e in DNSBlocklistEntry,
        where:
          e.organization_id == ^organization_id and
            e.normalized_domain == ^normalized_domain and
            e.active == true

    MultiTenant.with_organization(organization_id, fn ->
      case Repo.update_all(query, set: [active: false, updated_at: DateTime.utc_now()]) do
        {0, _} -> {:error, :not_found}
        {_count, _} -> :ok
      end
    end)
  rescue
    e -> {:error, Exception.message(e)}
  end

  def active_for_domain?(nil, _domain), do: false

  def active_for_domain?(organization_id, domain) do
    normalized_domain = normalize_domain(domain)

    MultiTenant.with_organization(organization_id, fn ->
      query =
        from e in DNSBlocklistEntry,
          where:
            e.organization_id == ^organization_id and
              e.normalized_domain == ^normalized_domain and
              e.active == true,
          select: 1,
          limit: 1

      Repo.one(query) != nil
    end)
  rescue
    _ -> false
  end

  def normalize_domain(domain) when is_binary(domain) do
    domain
    |> String.trim()
    |> String.trim_trailing(".")
    |> String.downcase()
  end

  def normalize_domain(_), do: ""
end
