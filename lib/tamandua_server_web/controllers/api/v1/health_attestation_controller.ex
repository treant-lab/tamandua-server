defmodule TamanduaServerWeb.API.V1.HealthAttestationController do
  @moduledoc """
  API controller for health attestations.

  Health attestations provide privacy-preserving on-chain proofs that an
  endpoint was monitored for a given time window, including aggregate security
  metrics (alert counts by severity).

  ## Agent-level Attestation Endpoints

  - `GET /api/v1/health-attestations` - List recent attestations
  - `GET /api/v1/health-attestations/:id` - Get a specific attestation
  - `POST /api/v1/health-attestations` - Create a new attestation for an agent
  - `POST /api/v1/health-attestations/:id/attest` - Submit an attestation to Solana
  - `POST /api/v1/health-attestations/create-and-attest` - Create and immediately submit
  - `GET /api/v1/health-attestations/stats` - Get attestation statistics
  - `GET /api/v1/health-attestations/verify/:id` - Verify an attestation's hash
  - `GET /api/v1/health-attestations/agent/:agent_id/latest` - Get latest for an agent
  - `GET /api/v1/health-attestations/pseudonym/:pseudonym` - Get by pseudonym (public)

  ## Fleet-level "Proof of Health" Endpoints (Hackathon)

  - `GET /api/v1/health-attestations/fleet/status` - Get aggregate fleet health status
  - `POST /api/v1/health-attestations/fleet/attest` - Manually trigger fleet attestation to Solana
  - `GET /api/v1/health-attestations/fleet/latest` - Get last fleet attestation
  - `GET /api/v1/health-attestations/fleet/enabled` - Check if fleet attestation is enabled
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Solana.HealthAttestations
  alias TamanduaServer.Solana.HealthAttestation
  alias TamanduaServer.Solana.FleetHealthAttestation
  alias TamanduaServer.Solana.Client, as: SolanaClient
  alias TamanduaServer.Agents
  alias TamanduaServer.Repo
  import Ecto.Query

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Lists recent health attestations.

  ## Query Parameters

  - `limit` - Maximum number of results (default: 20, max: 100)
  - `offset` - Offset for pagination (default: 0)
  - `attested_only` - If "true", only return attestations submitted to Solana

  ## Response

      {
        "data": [
          {
            "id": "uuid",
            "agent_pseudonym": "abc123def456",
            "window_hours": 24,
            "critical_alerts": 0,
            "high_alerts": 2,
            "medium_alerts": 5,
            "low_alerts": 10,
            "last_seen": "2026-05-08T12:00:00Z",
            "policy_profile": "balanced",
            "health_hash": "sha256...",
            "solana_signature": "5abc...",
            "attested_at": "2026-05-08T12:00:00Z",
            "solscan_url": "https://solscan.io/tx/...",
            "inserted_at": "2026-05-08T11:00:00Z"
          }
        ],
        "meta": {
          "total": 100,
          "limit": 20,
          "offset": 0
        }
      }
  """
  def index(conn, params) do
    org_id = current_organization_id(conn)
    limit = parse_limit(params["limit"])
    offset = parse_offset(params["offset"])
    attested_only = params["attested_only"] == "true"

    opts = [
      limit: limit,
      offset: offset,
      attested_only: attested_only
    ]

    with {:ok, org_id} <- require_organization(org_id) do
      attestations = HealthAttestations.list_attestations_for_org(org_id, opts)

      json(conn, %{
        data: Enum.map(attestations, &serialize/1),
        meta: %{
          limit: limit,
          offset: offset,
          attested_only: attested_only
        }
      })
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  @doc """
  Gets a specific health attestation by ID.

  ## Response

      {
        "data": {
          "id": "uuid",
          "agent_pseudonym": "abc123def456",
          ...
        }
      }
  """
  def show(conn, %{"id" => id}) do
    org_id = current_organization_id(conn)

    case get_attestation_for_org(id, org_id) do
      nil ->
        conn
        |> put_status(if(is_nil(org_id), do: :bad_request, else: :not_found))
        |> json(%{error: "Health attestation not found"})

      attestation ->
        json(conn, %{data: serialize(attestation)})
    end
  end

  @doc """
  Creates a new health attestation for an agent.

  This gathers the agent's last 24 hours of data (or custom window) and
  creates an attestation record. The attestation is not yet submitted to
  Solana - use the `/attest` endpoint for that.

  ## Request Body

      {
        "agent_id": "uuid",
        "window_hours": 24  // optional, default 24
      }

  ## Response

      {
        "data": {
          "id": "uuid",
          "agent_pseudonym": "abc123def456",
          ...
        }
      }
  """
  def create(conn, %{"agent_id" => agent_id} = params) do
    window_hours = params["window_hours"] || 24
    opts = [window_hours: window_hours]
    org_id = current_organization_id(conn)

    with {:ok, org_id} <- require_organization(org_id),
         {:ok, _agent} <- Agents.get_agent_for_org(org_id, agent_id),
         result <- HealthAttestations.create_attestation(agent_id, opts) do
      case result do
      {:ok, attestation} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize(attestation)})

      {:error, :agent_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> put_view(TamanduaServerWeb.ChangesetJSON)
        |> render(:error, changeset: changeset)

      {:error, reason} ->
        Logger.error("[HealthAttestationController] Failed to create attestation: #{inspect(reason)}")

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to create attestation", reason: inspect(reason)})
      end
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  def create(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "agent_id is required"})
  end

  @doc """
  Submits an attestation to the Solana blockchain.

  ## Response

      {
        "data": {
          "id": "uuid",
          "solana_signature": "5abc...",
          "attested_at": "2026-05-08T12:00:00Z",
          "solscan_url": "https://solscan.io/tx/..."
        }
      }
  """
  def attest(conn, %{"id" => id}) do
    org_id = current_organization_id(conn)

    case get_attestation_for_org(id, org_id) do
      nil ->
        conn
        |> put_status(if(is_nil(org_id), do: :bad_request, else: :not_found))
        |> json(%{error: "Health attestation not found"})

      %{solana_signature: sig} when not is_nil(sig) ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "Attestation already submitted to Solana", solana_signature: sig})

      attestation ->
        case HealthAttestations.attest_to_solana(attestation) do
          {:ok, updated} ->
            json(conn, %{
              data: serialize(updated),
              message: "Attestation submitted to Solana successfully"
            })

          {:error, :solana_disabled} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{error: "Solana integration is disabled"})

          {:error, reason} ->
            Logger.error("[HealthAttestationController] Solana attestation failed: #{inspect(reason)}")

            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to submit to Solana", reason: inspect(reason)})
        end
    end
  end

  @doc """
  Creates an attestation and immediately submits it to Solana.

  Convenience endpoint that combines create + attest in one call.

  ## Request Body

      {
        "agent_id": "uuid",
        "window_hours": 24  // optional
      }

  ## Response

      {
        "data": {
          "id": "uuid",
          "solana_signature": "5abc...",
          ...
        }
      }
  """
  def create_and_attest(conn, %{"agent_id" => agent_id} = params) do
    window_hours = params["window_hours"] || 24
    opts = [window_hours: window_hours]
    org_id = current_organization_id(conn)

    with {:ok, org_id} <- require_organization(org_id),
         {:ok, _agent} <- Agents.get_agent_for_org(org_id, agent_id),
         result <- HealthAttestations.create_and_attest(agent_id, opts) do
      case result do
      {:ok, attestation} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: serialize(attestation),
          message: "Attestation created and submitted to Solana"
        })

      {:error, :agent_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:error, :solana_disabled} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Solana integration is disabled"})

      {:error, reason} ->
        Logger.error("[HealthAttestationController] create_and_attest failed: #{inspect(reason)}")

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to create or attest", reason: inspect(reason)})
      end
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  def create_and_attest(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "agent_id is required"})
  end

  @doc """
  Gets attestation statistics for the current organization.

  ## Response

      {
        "data": {
          "total": 100,
          "attested": 80,
          "pending": 20,
          "avg_critical": 0.5,
          "avg_high": 2.3,
          "total_critical": 50,
          "total_high": 230
        }
      }
  """
  def stats(conn, _params) do
    org_id = current_organization_id(conn)

    if org_id do
      stats = HealthAttestations.get_stats_for_org(org_id)
      json(conn, %{data: stats})
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Organization context required"})
    end
  end

  @doc """
  Verifies a health attestation's hash.

  ## Response

      {
        "valid": true,
        "health_hash": "sha256...",
        "computed_hash": "sha256..."
      }
  """
  def verify(conn, %{"id" => id}) do
    org_id = current_organization_id(conn)

    case get_attestation_for_org(id, org_id) do
      nil ->
        conn
        |> put_status(if(is_nil(org_id), do: :bad_request, else: :not_found))
        |> json(%{error: "Health attestation not found"})

      attestation ->
        valid = HealthAttestations.verify_health_hash(attestation)

        json(conn, %{
          valid: valid,
          health_hash: attestation.health_hash,
          attestation: serialize(attestation)
        })
    end
  end

  @doc """
  Gets the latest attestation for an agent by agent_id.

  ## Response

      {
        "data": { ... } | null
      }
  """
  def latest_for_agent(conn, %{"agent_id" => agent_id}) do
    org_id = current_organization_id(conn)

    with {:ok, org_id} <- require_organization(org_id),
         {:ok, _agent} <- Agents.get_agent_for_org(org_id, agent_id) do
      case HealthAttestations.get_latest_for_agent(agent_id) do
        nil ->
          json(conn, %{data: nil})

        %{organization_id: ^org_id} = attestation ->
          json(conn, %{data: serialize(attestation)})

        _ ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "Health attestation not found"})
      end
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  @doc """
  Gets the latest attestation by pseudonym (for public verification).

  ## Response

      {
        "data": { ... } | null
      }
  """
  def by_pseudonym(conn, %{"pseudonym" => pseudonym}) do
    case HealthAttestations.get_latest_by_pseudonym(pseudonym) do
      nil ->
        json(conn, %{data: nil})

      attestation ->
        # Return only public fields for pseudonym lookup
        json(conn, %{
          data: %{
            agent_pseudonym: attestation.agent_pseudonym,
            window_hours: attestation.window_hours,
            critical_alerts: attestation.critical_alerts,
            high_alerts: attestation.high_alerts,
            medium_alerts: attestation.medium_alerts,
            low_alerts: attestation.low_alerts,
            policy_profile: attestation.policy_profile,
            health_hash: attestation.health_hash,
            solana_signature: attestation.solana_signature,
            attested_at: format_datetime(attestation.attested_at),
            solscan_url: HealthAttestations.solscan_url(attestation)
          }
        })
    end
  end

  # Private helpers

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      conn.assigns[:organization_id] ||
      get_in(conn.assigns, [:current_user, Access.key(:organization_id)])
  end

  defp require_organization(nil), do: {:error, :organization_required}
  defp require_organization(org_id), do: {:ok, org_id}

  defp error_status(:organization_required), do: :bad_request
  defp error_status(:not_found), do: :not_found
  defp error_status(_), do: :unprocessable_entity

  defp get_attestation_for_org(_id, nil), do: nil

  defp get_attestation_for_org(id, org_id) do
    Repo.one(
      from a in HealthAttestation,
        where: a.id == ^id and a.organization_id == ^org_id,
        limit: 1
    )
  end

  defp serialize(%HealthAttestation{} = attestation) do
    %{
      id: attestation.id,
      agent_pseudonym: attestation.agent_pseudonym,
      window_hours: attestation.window_hours,
      critical_alerts: attestation.critical_alerts,
      high_alerts: attestation.high_alerts,
      medium_alerts: attestation.medium_alerts,
      low_alerts: attestation.low_alerts,
      last_seen: format_datetime(attestation.last_seen),
      policy_profile: attestation.policy_profile,
      health_hash: attestation.health_hash,
      solana_signature: attestation.solana_signature,
      attested_at: format_datetime(attestation.attested_at),
      solscan_url: HealthAttestations.solscan_url(attestation),
      inserted_at: format_datetime(attestation.inserted_at),
      updated_at: format_datetime(attestation.updated_at)
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)

  defp parse_limit(nil), do: 20
  defp parse_limit(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> min(max(n, 1), 100)
      :error -> 20
    end
  end
  defp parse_limit(val) when is_integer(val), do: min(max(val, 1), 100)

  defp parse_offset(nil), do: 0
  defp parse_offset(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> max(n, 0)
      :error -> 0
    end
  end
  defp parse_offset(val) when is_integer(val), do: max(val, 0)

  # ===========================================================================
  # Fleet Health Attestation Endpoints (Proof of Health)
  # ===========================================================================

  @doc """
  Gets the current fleet health status.

  Returns aggregate health metrics for all connected agents without
  creating an attestation.

  ## Response

      {
        "data": {
          "timestamp": "2026-05-08T12:00:00Z",
          "total_agents": 50,
          "healthy_agents": 45,
          "offline_agents": 3,
          "isolated_agents": 2,
          "coverage_percentage": 90.0,
          "average_health_score": 85,
          "critical_count": 1,
          "warning_count": 5,
          "os_distribution": {"windows": 30, "linux": 15, "macos": 5},
          "version_distribution": {"1.0.0": 40, "0.9.0": 10}
        }
      }
  """
  def fleet_status(conn, _params) do
    case FleetHealthAttestation.get_fleet_status() do
      {:ok, status} ->
        json(conn, %{
          data: %{
            timestamp: format_datetime(status.timestamp),
            total_agents: status.total_agents,
            healthy_agents: status.healthy_agents,
            offline_agents: status.offline_agents,
            isolated_agents: status.isolated_agents,
            coverage_percentage: status.coverage_percentage,
            average_health_score: status.average_health_score,
            critical_count: status.critical_count,
            warning_count: status.warning_count,
            os_distribution: status.os_distribution,
            version_distribution: status.version_distribution
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to get fleet status", reason: inspect(reason)})
    end
  end

  @doc """
  Triggers a fleet health attestation and submits it to Solana.

  This endpoint manually triggers the "Proof of Health" attestation,
  which aggregates health data from all connected agents and publishes
  it to Solana devnet.

  ## Response

      {
        "data": {
          "signature": "5abc123...",
          "solscan_url": "https://solscan.io/tx/5abc123...?cluster=devnet",
          "attestation": {
            "schema": "tamandua.fleet_health",
            "version": 1,
            "type": "fleet_health_proof",
            "timestamp": "2026-05-08T12:00:00Z",
            "fleet_hash": "abc123...",
            "metrics": {
              "total_agents": 50,
              "healthy_agents": 45,
              "coverage_percentage": 90.0,
              ...
            }
          }
        },
        "message": "Fleet health attestation submitted to Solana"
      }
  """
  def fleet_attest(conn, _params) do
    case FleetHealthAttestation.attest_now() do
      {:ok, result} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: %{
            signature: result.signature,
            solscan_url: SolanaClient.solscan_url(result.signature),
            attestation: serialize_fleet_attestation(result.attestation)
          },
          message: "Fleet health attestation submitted to Solana"
        })

      {:error, :no_agents} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "No agents connected", message: "Cannot create attestation without connected agents"})

      {:error, :solana_disabled} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Solana integration is disabled"})

      {:error, reason} ->
        Logger.error("[HealthAttestationController] Fleet attestation failed: #{inspect(reason)}")

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to create fleet attestation", reason: inspect(reason)})
    end
  end

  @doc """
  Gets the last successful fleet health attestation.

  ## Response

      {
        "data": {
          "signature": "5abc123...",
          "attested_at": "2026-05-08T12:00:00Z",
          "solscan_url": "https://solscan.io/tx/...",
          "attestation": { ... }
        }
      }
  """
  def fleet_last_attestation(conn, _params) do
    case FleetHealthAttestation.get_last_attestation() do
      {:ok, result} ->
        json(conn, %{
          data: %{
            signature: result.signature,
            attested_at: format_datetime(result.attested_at),
            solscan_url: SolanaClient.solscan_url(result.signature),
            attestation: serialize_fleet_attestation(result.attestation)
          }
        })

      {:error, :no_attestation} ->
        json(conn, %{data: nil, message: "No fleet attestation has been created yet"})
    end
  end

  @doc """
  Checks if fleet health attestation is enabled.

  ## Response

      {
        "enabled": true,
        "solana_enabled": true
      }
  """
  def fleet_enabled(conn, _params) do
    json(conn, %{
      enabled: FleetHealthAttestation.enabled?(),
      solana_enabled: SolanaClient.enabled?()
    })
  end

  defp serialize_fleet_attestation(attestation) when is_map(attestation) do
    %{
      schema: attestation[:schema] || attestation["schema"],
      version: attestation[:version] || attestation["version"],
      type: attestation[:type] || attestation["type"],
      timestamp: format_datetime(attestation[:timestamp] || attestation["timestamp"]),
      fleet_hash: attestation[:fleet_hash] || attestation["fleet_hash"],
      metrics: attestation[:metrics] || attestation["metrics"],
      distributions: attestation[:distributions] || attestation["distributions"]
    }
  end
  defp serialize_fleet_attestation(nil), do: nil
end
