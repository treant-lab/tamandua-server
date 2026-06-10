defmodule TamanduaServer.Workers.AttestationWorker do
  @moduledoc """
  Oban worker for submitting incident attestations to Solana.

  This worker processes attestation jobs for critical and high-severity alerts,
  creating tamper-evident on-chain proofs of security incidents.

  ## Features

  - Reliable retry with exponential backoff (3 attempts)
  - Unique job constraint to prevent duplicate attestations
  - Automatic bounty payment for rule authors
  - PubSub broadcast on successful attestation

  ## Privacy Guarantees

  Only redacted, privacy-safe data goes on-chain:
  - Incident hash (SHA256 of alert metadata, no raw telemetry)
  - Pseudonymized org/agent IDs (SHA256 hashes)
  - MITRE technique IDs
  - Severity level
  - Public IOCs only (no hostnames, usernames, paths, internal IPs)

  ## Usage

      # Enqueue an attestation job for an alert
      AttestationWorker.enqueue(alert_id)

      # Or with options
      AttestationWorker.enqueue(alert_id, priority: 1)
  """

  use Oban.Worker,
    queue: :blockchain,
    max_attempts: 3,
    unique: [period: 300, fields: [:args, :queue]]

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Solana.{Attestation, Bounty, Client}

  @doc """
  Enqueue an attestation job for an alert.

  ## Options

  - `:priority` - Job priority (0-3, lower is higher priority, default: 1)
  - `:schedule_in` - Delay in seconds before processing (default: 0)

  ## Examples

      # Immediate attestation
      AttestationWorker.enqueue(alert_id)

      # Delayed attestation
      AttestationWorker.enqueue(alert_id, schedule_in: 60)

      # High priority attestation for critical alerts
      AttestationWorker.enqueue(alert_id, priority: 0)
  """
  @spec enqueue(String.t(), keyword()) :: {:ok, Oban.Job.t()} | {:error, term()}
  def enqueue(alert_id, opts \\ []) do
    if Client.enabled?() do
      priority = Keyword.get(opts, :priority, 1)
      schedule_in = Keyword.get(opts, :schedule_in, 0)

      job_args = %{
        "alert_id" => alert_id,
        "enqueued_at" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      job_opts = [priority: priority]

      job_opts =
        if schedule_in > 0 do
          Keyword.put(job_opts, :schedule_in, schedule_in)
        else
          job_opts
        end

      job_args
      |> new(job_opts)
      |> Oban.insert()
    else
      Logger.debug("[AttestationWorker] Solana disabled, skipping attestation for alert #{alert_id}")
      {:error, :solana_disabled}
    end
  end

  @doc """
  Enqueue attestation for an alert struct directly.

  Validates that the alert meets attestation criteria before enqueuing.
  """
  @spec enqueue_for_alert(Alert.t(), keyword()) :: {:ok, Oban.Job.t()} | {:error, term()}
  def enqueue_for_alert(%Alert{} = alert, opts \\ []) do
    cond do
      not is_nil(alert.blockchain_tx_id) ->
        Logger.debug("[AttestationWorker] Alert #{alert.id} already attested, skipping")
        {:error, :already_attested}

      alert.severity not in ["medium", "high", "critical"] ->
        Logger.debug("[AttestationWorker] Alert #{alert.id} severity #{alert.severity} not eligible for attestation")
        {:error, :severity_not_eligible}

      true ->
        # Set priority based on severity
        priority =
          case alert.severity do
            "critical" -> 0
            "high" -> 1
            _ -> 2
          end

        enqueue(alert.id, Keyword.put_new(opts, :priority, priority))
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"alert_id" => alert_id}, attempt: attempt}) do
    Logger.info("[AttestationWorker] Processing attestation for alert #{alert_id} (attempt #{attempt})")

    case Repo.get(Alert, alert_id) do
      nil ->
        Logger.warning("[AttestationWorker] Alert #{alert_id} not found")
        {:discard, :alert_not_found}

      %Alert{blockchain_tx_id: tx_id} when is_binary(tx_id) ->
        Logger.info("[AttestationWorker] Alert #{alert_id} already attested: #{tx_id}")
        :ok

      %Alert{} = alert ->
        submit_attestation(alert)
    end
  end

  # Submit the attestation to Solana and update the alert
  defp submit_attestation(%Alert{} = alert) do
    case Attestation.attest_alert(alert) do
      {:ok, tx_signature} ->
        attested_at = DateTime.utc_now()
        manifest = Attestation.build_public_manifest(alert)

        # Build updates with attestation data
        updates = %{
          blockchain_tx_id: tx_signature,
          blockchain_attested_at: attested_at,
          incident_hash: manifest.incident_hash,
          manifest_hash: Attestation.compute_manifest_hash(manifest) |> Base.encode16(case: :lower),
          attestation_tlp: manifest.tlp,
          attestation_ioc_count: manifest.ioc_count,
          attestation_ioc_types: manifest.ioc_types,
          attestation_redacted_ioc_count: manifest.redacted_ioc_count,
          attestation_confidence: manifest.confidence,
          attestation_threat_class: manifest.threat_class,
          attestation_malware_family: manifest.malware_family,
          public_manifest: manifest
        }

        # Attempt bounty payment if rule author is specified
        updates =
          case maybe_pay_bounty(alert) do
            {:ok, bounty_info} ->
              Map.merge(updates, %{
                bounty_tx_id: bounty_info.tx_signature,
                bounty_amount_lamports: bounty_info.amount_lamports,
                bounty_paid_at: DateTime.utc_now()
              })

            _ ->
              updates
          end

        # Persist the attestation to the database
        case alert |> Alert.changeset(updates) |> Repo.update() do
          {:ok, updated_alert} ->
            # Broadcast attestation event
            Phoenix.PubSub.broadcast(
              TamanduaServer.PubSub,
              "alerts:attested",
              {:alert_attested, updated_alert}
            )

            Logger.info("""
            [AttestationWorker] Alert attested successfully
              Alert ID: #{alert.id}
              TX: #{tx_signature}
              Severity: #{alert.severity}
              MITRE: #{inspect(alert.mitre_techniques)}
              Solscan: #{Client.solscan_url(tx_signature)}
            """)

            :ok

          {:error, changeset} ->
            Logger.error("[AttestationWorker] Failed to persist attestation: #{inspect(changeset.errors)}")
            {:error, :persistence_failed}
        end

      {:error, :solana_disabled} ->
        Logger.debug("[AttestationWorker] Solana disabled, discarding job")
        {:discard, :solana_disabled}

      {:error, reason} ->
        Logger.error("[AttestationWorker] Attestation failed for alert #{alert.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Attempt to pay a detection bounty to the rule author
  defp maybe_pay_bounty(%Alert{rule_author_pubkey: pubkey} = alert)
       when is_binary(pubkey) and byte_size(pubkey) > 0 do
    case Bounty.pay_bounty(alert, pubkey) do
      {:ok, _} = result ->
        result

      {:error, reason} ->
        Logger.warning("[AttestationWorker] Bounty payment failed for alert #{alert.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp maybe_pay_bounty(_alert), do: :skip
end
