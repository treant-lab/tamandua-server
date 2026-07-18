defmodule TamanduaServer.Workers.RetentionOrganizationDiscovery do
  @moduledoc """
  Bounded organization discovery for screen/evidence retention workers.

  The separate authority identity is the only discovery path. When that
  identity is disabled or unavailable, discovery fails closed and retention
  workers perform no cross-tenant discovery.
  """

  alias TamanduaServer.{AuthorityAccess, AuthorityRepo}

  @maximum_limit 1_000
  @telemetry_event [:tamandua, :retention, :organization_discovery]

  @spec discover(DateTime.t()) :: {:ok, [Ecto.UUID.t()]} | {:error, atom()}
  def discover(as_of \\ DateTime.utc_now())

  def discover(%DateTime{} = as_of) do
    if AuthorityRepo.enabled?() do
      discover_with_authority(as_of)
    else
      emit(:disabled, :error, :authority_repo_disabled)
      {:error, :authority_repo_disabled}
    end
  end

  def discover(_as_of), do: {:error, :invalid_retention_discovery_request}

  @doc false
  def normalize_organization_ids(organization_ids, limit \\ @maximum_limit)

  def normalize_organization_ids(organization_ids, limit)
      when is_list(organization_ids) and is_integer(limit) and limit > 0 and
             limit <= @maximum_limit do
    organization_ids
    |> Enum.reduce([], fn organization_id, canonical_ids ->
      case Ecto.UUID.cast(organization_id) do
        {:ok, canonical_id} -> [canonical_id | canonical_ids]
        :error -> canonical_ids
      end
    end)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.take(limit)
  end

  def normalize_organization_ids(_organization_ids, _limit), do: []

  defp discover_with_authority(as_of) do
    case AuthorityAccess.discover_screen_evidence_retention_due_organization_ids(
           as_of,
           @maximum_limit
         ) do
      organization_ids when is_list(organization_ids) ->
        case validate_authority_organization_ids(organization_ids) do
          {:ok, canonical_ids} ->
            {:ok, canonical_ids}

          {:error, reason} ->
            emit(:authority, :error, reason)
            {:error, reason}
        end

      {:error, reason} when is_atom(reason) ->
        emit(:authority, :error, reason)
        {:error, reason}

      _unexpected ->
        emit(:authority, :error, :invalid_authority_response)
        {:error, :invalid_authority_response}
    end
  end

  defp validate_authority_organization_ids(organization_ids)
       when length(organization_ids) <= @maximum_limit do
    organization_ids
    |> Enum.reduce_while([], fn organization_id, canonical_ids ->
      case Ecto.UUID.cast(organization_id) do
        {:ok, canonical_id} -> {:cont, [canonical_id | canonical_ids]}
        :error -> {:halt, :invalid}
      end
    end)
    |> case do
      :invalid ->
        {:error, :invalid_authority_response}

      canonical_ids ->
        {:ok, canonical_ids |> Enum.uniq() |> Enum.sort()}
    end
  end

  defp validate_authority_organization_ids(_organization_ids),
    do: {:error, :invalid_authority_response}

  defp emit(mode, status, reason) do
    :telemetry.execute(
      @telemetry_event,
      %{count: 1},
      %{mode: mode, status: status, reason: reason, maximum_limit: @maximum_limit}
    )
  end
end
