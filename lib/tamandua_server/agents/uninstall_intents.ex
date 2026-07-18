defmodule TamanduaServer.Agents.UninstallIntents do
  @moduledoc """
  Issues and atomically consumes short-lived, one-time uninstall authorities.

  The intent row is the authoritative audit record. Raw nonces and idempotency
  keys are validated at the boundary, hashed immediately, and never persisted.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Agents.{Agent, AgentUninstallIntent, TokenManager}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @action "agent_uninstall"
  @ttl_seconds 300
  @reasons ~w(operator_requested device_retirement incident_response agent_replacement)
  @platforms ~w(windows linux macos)
  @consumers ~w(native_cli windows_msi)
  @verifier_version "uninstall_intent_v1"

  @spec issue(String.t(), String.t(), String.t(), map()) ::
          {:ok, AgentUninstallIntent.t(), :created | :replay}
          | {:error, atom() | Ecto.Changeset.t()}
  def issue(organization_id, agent_id, issued_by_user_id, attrs) when is_map(attrs) do
    with {:ok, organization_id} <- canonical_uuid(organization_id, :tenant_context_required),
         {:ok, agent_id} <- canonical_uuid(agent_id, :agent_not_found),
         {:ok, issued_by_user_id} <- canonical_uuid(issued_by_user_id, :issuer_invalid),
         {:ok, reason} <- allowlisted(attrs[:reason] || attrs["reason"], @reasons),
         {:ok, idempotency_digest} <-
           optional_idempotency_digest(attrs[:idempotency_key] || attrs["idempotency_key"]) do
      run_in_tenant(organization_id, fn ->
        issue_in_tenant(
          organization_id,
          agent_id,
          issued_by_user_id,
          reason,
          idempotency_digest
        )
      end)
    end
  end

  def issue(_organization_id, _agent_id, _issued_by_user_id, _attrs),
    do: {:error, :request_invalid}

  @spec consume(String.t(), String.t(), pos_integer(), String.t(), map()) ::
          {:ok, map()} | {:error, atom()}
  def consume(organization_id, agent_id, token_generation, raw_token, attrs)
      when is_binary(raw_token) and is_map(attrs) do
    with {:ok, organization_id} <- canonical_uuid(organization_id, :unauthorized),
         {:ok, agent_id} <- canonical_uuid(agent_id, :unauthorized),
         {:ok, token_generation} <- positive_integer(token_generation),
         {:ok, canonical_nonce, nonce_digest} <-
           nonce_digest(attrs[:nonce] || attrs["nonce"]),
         {:ok, verifier_version} <-
           exact_value(
             attrs[:verifier_version] || attrs["verifier_version"],
             @verifier_version
           ),
         {:ok, platform} <- allowlisted(attrs[:platform] || attrs["platform"], @platforms),
         {:ok, consumer} <- allowlisted(attrs[:consumer] || attrs["consumer"], @consumers) do
      run_in_tenant(organization_id, fn ->
        case TokenManager.validate_token_in_current_tenant(
               raw_token,
               organization_id,
               agent_id,
               token_generation
             ) do
          {:ok, _claims} ->
            consume_in_tenant(
              organization_id,
              agent_id,
              token_generation,
              canonical_nonce,
              nonce_digest,
              verifier_version,
              platform,
              consumer
            )

          {:error, :database_error} ->
            {:error, :store_unavailable}

          {:error, _reason} ->
            {:error, :unauthorized}
        end
      end)
    end
  end

  def consume(_organization_id, _agent_id, _token_generation, _raw_token, _attrs),
    do: {:error, :request_invalid}

  defp issue_in_tenant(
         organization_id,
         agent_id,
         issued_by_user_id,
         reason,
         idempotency_digest
       ) do
    agent =
      from(a in Agent,
        where: a.id == ^agent_id and a.organization_id == ^organization_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    issuer_exists? =
      from(u in User,
        where: u.id == ^issued_by_user_id and u.organization_id == ^organization_id,
        select: true
      )
      |> Repo.one()

    cond do
      is_nil(agent) ->
        {:error, :agent_not_found}

      issuer_exists? != true ->
        {:error, :issuer_invalid}

      true ->
        case find_idempotent_intent(organization_id, agent_id, idempotency_digest) do
          %AgentUninstallIntent{} = existing ->
            idempotent_replay(existing, issued_by_user_id, reason)

          nil ->
            supersede_pending(organization_id, agent_id)
            insert_pending(organization_id, agent_id, issued_by_user_id, reason, idempotency_digest)
        end
    end
  end

  defp find_idempotent_intent(_organization_id, _agent_id, nil), do: nil

  defp find_idempotent_intent(organization_id, agent_id, digest) do
    Repo.one(
      from(i in AgentUninstallIntent,
        where:
          i.organization_id == ^organization_id and i.agent_id == ^agent_id and
            i.action == @action and i.idempotency_key_sha256 == ^digest
      )
    )
  end

  defp idempotent_replay(intent, issued_by_user_id, reason) do
    exact_request? =
      intent.issued_by_user_id == issued_by_user_id and intent.reason == reason and
        intent.action == @action

    active? =
      intent.state == "pending" and DateTime.compare(intent.expires_at, now()) == :gt

    if exact_request? and active?,
      do: {:ok, intent, :replay},
      else: {:error, :idempotency_conflict}
  end

  defp supersede_pending(organization_id, agent_id) do
    now = now()

    from(i in AgentUninstallIntent,
      where:
        i.organization_id == ^organization_id and i.agent_id == ^agent_id and
          i.action == @action and i.state == "pending"
    )
    |> Repo.update_all(
      set: [state: "superseded", superseded_at: now, updated_at: now]
    )
  end

  defp insert_pending(organization_id, agent_id, issued_by_user_id, reason, idempotency_digest) do
    issued_at = now()
    expires_at = DateTime.add(issued_at, @ttl_seconds, :second)

    %AgentUninstallIntent{}
    |> AgentUninstallIntent.issue_changeset(%{
      organization_id: organization_id,
      agent_id: agent_id,
      issued_by_user_id: issued_by_user_id,
      action: @action,
      reason: reason,
      idempotency_key_sha256: idempotency_digest,
      state: "pending",
      issued_at: issued_at,
      expires_at: expires_at
    })
    |> Repo.insert()
    |> case do
      {:ok, intent} -> {:ok, intent, :created}
      {:error, changeset} -> throw({:uninstall_intent_error, changeset})
    end
  end

  defp consume_in_tenant(
         organization_id,
         agent_id,
         token_generation,
         canonical_nonce,
         nonce_digest,
         verifier_version,
         platform,
         consumer
       ) do
    consumed_at = now()

    query =
      from(i in AgentUninstallIntent,
        where:
          i.organization_id == ^organization_id and i.agent_id == ^agent_id and
            i.action == @action and i.state == "pending" and i.expires_at > ^consumed_at,
        select: %{id: i.id, expires_at: i.expires_at}
      )

    case Repo.update_all(query,
           set: [
             state: "consumed",
             nonce_sha256: nonce_digest,
             verifier_version: verifier_version,
             platform: platform,
             consumer: consumer,
             token_generation: token_generation,
             consumed_at: consumed_at,
             updated_at: consumed_at
           ]
         ) do
      {1, [%{id: intent_id, expires_at: expires_at}]} ->
        {:ok,
         %{
           id: intent_id,
           organization_id: organization_id,
           agent_id: agent_id,
           action: @action,
           state: "consumed",
           expires_at: expires_at,
           consumed_at: consumed_at,
           nonce: canonical_nonce,
           token_generation: token_generation,
           verifier_version: verifier_version,
           platform: platform,
           consumer: consumer
         }}

      {0, []} ->
        classify_unavailable(organization_id, agent_id, consumed_at)

      _unexpected ->
        {:error, :store_unavailable}
    end
  rescue
    Ecto.ConstraintError -> throw({:uninstall_intent_error, :unavailable})
  end

  defp classify_unavailable(organization_id, agent_id, now) do
    latest =
      Repo.one(
        from(i in AgentUninstallIntent,
          where:
            i.organization_id == ^organization_id and i.agent_id == ^agent_id and
              i.action == @action,
          order_by: [desc: i.issued_at],
          limit: 1,
          select: %{state: i.state, expires_at: i.expires_at}
        )
      )

    case latest do
      %{state: "consumed"} -> {:error, :already_consumed}
      %{state: "pending", expires_at: expires_at} ->
        if DateTime.compare(expires_at, now) in [:lt, :eq],
          do: {:error, :expired},
          else: {:error, :unavailable}

      _ -> {:error, :unavailable}
    end
  end

  defp run_in_tenant(organization_id, fun) do
    MultiTenant.with_organization(organization_id, fun)
  rescue
    _error ->
      Logger.error("Agent uninstall intent store operation failed")
      {:error, :store_unavailable}
  catch
    {:uninstall_intent_error, reason} -> {:error, reason}
  end

  defp optional_idempotency_digest(nil), do: {:ok, nil}

  defp optional_idempotency_digest(value) when is_binary(value) do
    if byte_size(value) in 16..128 and value == String.trim(value) and
         String.printable?(value) do
      {:ok, :crypto.hash(:sha256, value)}
    else
      {:error, :request_invalid}
    end
  end

  defp optional_idempotency_digest(_value), do: {:error, :request_invalid}

  defp nonce_digest(value) when is_binary(value) do
    with {:ok, decoded} <- Base.url_decode64(value, padding: false),
         true <- byte_size(decoded) == 32,
         true <- Base.url_encode64(decoded, padding: false) == value do
      {:ok, value, :crypto.hash(:sha256, decoded)}
    else
      _ -> {:error, :request_invalid}
    end
  end

  defp nonce_digest(_value), do: {:error, :request_invalid}

  defp exact_value(value, expected) when value == expected, do: {:ok, value}
  defp exact_value(_value, _expected), do: {:error, :request_invalid}

  defp allowlisted(value, allowlist) when is_binary(value) do
    if value in allowlist, do: {:ok, value}, else: {:error, :request_invalid}
  end

  defp allowlisted(_value, _allowlist), do: {:error, :request_invalid}

  defp positive_integer(value) when is_integer(value) and value > 0, do: {:ok, value}
  defp positive_integer(_value), do: {:error, :unauthorized}

  defp canonical_uuid(value, error) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, error}
    end
  end

  defp canonical_uuid(_value, error), do: {:error, error}

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:microsecond)
end
