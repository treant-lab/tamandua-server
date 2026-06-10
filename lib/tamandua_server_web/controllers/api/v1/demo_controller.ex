defmodule TamanduaServerWeb.API.V1.DemoController do
  @moduledoc """
  Demo controller for triggering detection scenarios.

  Provides a single endpoint for hackathon demonstrations that:
  1. Generates a synthetic telemetry event
  2. Creates an alert through the detection pipeline
  3. Triggers Solana blockchain attestation
  4. Returns the alert with transaction details

  **Admin-only access required.**

  ## Endpoint

      POST /api/v1/demo/trigger-detection

  ## Request Body

      {
        "scenario": "browser_credential_theft",
        "severity": "high",              // optional override
        "rule_author_pubkey": "..."      // optional for bounty
      }

  ## Response

      {
        "success": true,
        "alert_id": "uuid",
        "title": "Demo: Browser Credential Theft Detected",
        "severity": "high",
        "mitre_technique": "T1555.003",
        "manifest_hash": "abc123...",
        "blockchain_tx_id": "5xyz...",
        "solscan_url": "https://solscan.io/tx/..."
      }
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Demo.ScenarioGenerator
  alias TamanduaServer.Alerts
  alias TamanduaServer.Solana.{Attestation, Client}
  alias TamanduaServer.Audit

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Trigger a demo detection scenario.

  Creates a synthetic event, generates an alert, and attests it on Solana.
  """
  def trigger_detection(conn, params) do
    with :ok <- verify_admin(conn),
         {:ok, scenario} <- validate_scenario(params),
         {:ok, result} <- execute_demo(conn, scenario, params) do
      log_demo_trigger(conn, scenario, result)

      json(conn, result)
    else
      {:error, :unauthorized} ->
        conn
        |> put_status(:forbidden)
        |> json(%{
          error: "Admin access required",
          message: "This endpoint requires admin privileges"
        })

      {:error, :invalid_scenario} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          error: "Invalid scenario",
          message: "Scenario must be one of: #{Enum.join(ScenarioGenerator.available_scenarios(), ", ")}",
          available_scenarios: ScenarioGenerator.available_scenarios()
        })

      {:error, reason} ->
        Logger.error("[Demo] Failed to execute demo: #{inspect(reason)}")
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: "Demo execution failed",
          reason: inspect(reason)
        })
    end
  end

  # ── Authorization ──────────────────────────────────────────────────

  defp verify_admin(conn) do
    user = conn.assigns[:current_user]

    cond do
      is_nil(user) ->
        {:error, :unauthorized}

      user.role in ["admin", "superadmin"] ->
        :ok

      # Also check for demo mode flag (for hackathon)
      Application.get_env(:tamandua_server, :demo_mode, false) ->
        :ok

      true ->
        {:error, :unauthorized}
    end
  end

  # ── Validation ─────────────────────────────────────────────────────

  defp validate_scenario(%{"scenario" => scenario}) when is_binary(scenario) do
    if scenario in ScenarioGenerator.available_scenarios() do
      {:ok, scenario}
    else
      {:error, :invalid_scenario}
    end
  end

  defp validate_scenario(_), do: {:error, :invalid_scenario}

  # ── Demo Execution ─────────────────────────────────────────────────

  defp execute_demo(conn, scenario, params) do
    organization_id = conn.assigns[:current_organization_id] || demo_org_id()
    severity = params["severity"]
    rule_author_pubkey = params["rule_author_pubkey"]

    opts = [
      organization_id: organization_id,
      severity: severity,
      rule_author_pubkey: rule_author_pubkey
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    # Generate alert attributes
    case ScenarioGenerator.generate_alert_attrs(scenario, opts) do
      {:ok, attrs} ->
        # Create the alert
        case Alerts.create_alert(attrs) do
          {:ok, alert} ->
            # Trigger attestation asynchronously but wait for result
            attestation_result = attest_alert(alert)

            # Build response
            build_response(alert, attestation_result)

          {:error, changeset} ->
            Logger.error("[Demo] Failed to create alert: #{inspect(changeset)}")
            {:error, {:alert_creation_failed, changeset}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp attest_alert(alert) do
    if Client.enabled?() do
      case Attestation.attest_alert(alert) do
        {:ok, tx_id} ->
          # Update alert with blockchain tx
          Alerts.update_alert(alert, %{
            blockchain_tx_id: tx_id,
            blockchain_attested_at: DateTime.utc_now()
          })

          manifest = Attestation.build_public_manifest(alert)
          manifest_hash = Attestation.compute_manifest_hash(manifest) |> Base.encode16(case: :lower)

          {:ok, %{
            tx_id: tx_id,
            manifest_hash: manifest_hash,
            solscan_url: Client.solscan_url(tx_id)
          }}

        {:error, reason} ->
          Logger.warning("[Demo] Attestation failed: #{inspect(reason)}")
          {:error, reason}
      end
    else
      Logger.info("[Demo] Solana integration disabled, skipping attestation")
      {:disabled, nil}
    end
  end

  defp build_response(alert, attestation_result) do
    mitre_technique =
      case alert.mitre_techniques do
        [t | _] -> t
        _ -> Map.get(alert.detection_metadata || %{}, :mitre_technique, "UNKNOWN")
      end

    base_response = %{
      success: true,
      alert_id: alert.id,
      title: alert.title,
      severity: alert.severity,
      mitre_technique: mitre_technique,
      threat_class: get_in(alert.detection_metadata || %{}, [:threat_class]) || "endpoint_threat",
      created_at: DateTime.to_iso8601(alert.inserted_at)
    }

    response = case attestation_result do
      {:ok, %{tx_id: tx_id, manifest_hash: manifest_hash, solscan_url: solscan_url}} ->
        Map.merge(base_response, %{
          blockchain_tx_id: tx_id,
          manifest_hash: manifest_hash,
          solscan_url: solscan_url,
          attestation_status: "attested"
        })

      {:disabled, _} ->
        Map.merge(base_response, %{
          blockchain_tx_id: nil,
          manifest_hash: nil,
          solscan_url: nil,
          attestation_status: "disabled",
          warning: "Solana integration is disabled"
        })

      {:error, reason} ->
        Map.merge(base_response, %{
          blockchain_tx_id: nil,
          manifest_hash: nil,
          solscan_url: nil,
          attestation_status: "failed",
          warning: "Attestation failed: #{inspect(reason)}"
        })
    end

    {:ok, response}
  end

  # ── Audit Logging ──────────────────────────────────────────────────

  defp log_demo_trigger(conn, scenario, result) do
    user = conn.assigns[:current_user]

    if user do
      Audit.log(%{
        user_id: user.id,
        user_email: user.email,
        action: "demo_trigger",
        entity_type: "demo",
        entity_id: result[:alert_id],
        details: %{
          scenario: scenario,
          blockchain_tx_id: result[:blockchain_tx_id],
          attestation_status: result[:attestation_status]
        },
        ip_address: request_metadata(conn)[:ip_address],
        user_agent: request_metadata(conn)[:user_agent]
      })
    end
  rescue
    e ->
      Logger.warning("[Demo] Failed to log audit event: #{Exception.message(e)}")
  end

  defp request_metadata(conn) do
    %{
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn),
      request_id: Logger.metadata()[:request_id]
    }
  end

  defp get_client_ip(conn) do
    conn.remote_ip |> :inet.ntoa() |> to_string()
  rescue
    _ -> "unknown"
  end

  defp get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      _ -> "unknown"
    end
  end

  # Generate a demo organization ID for testing without org context
  defp demo_org_id do
    # Use a consistent demo org ID so alerts can be found
    "00000000-0000-0000-0000-000000000001"
  end
end
