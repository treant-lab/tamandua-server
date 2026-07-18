defmodule TamanduaServer.Quarantine.ModelVault do
  @moduledoc """
  Model Vault - Server-side management of quarantined AI/ML models.

  This module handles:
  - Storage and retrieval of quarantine receipts
  - Recovery key management (encrypted storage)
  - Audit logging of quarantine/restore actions
  - Dashboard restore functionality with authorization

  ## Architecture

  When a malicious model is detected on an agent:
  1. Agent quarantines the model (encrypts, moves to vault)
  2. Agent sends receipt with recovery key to server
  3. Server stores receipt and encrypts recovery key
  4. Analyst can review and initiate restore via dashboard
  5. Server validates authorization, returns recovery key to agent
  6. Agent decrypts and restores model

  ## Security

  - Recovery keys are encrypted at rest using AES-256-GCM
  - Keys are derived from server secret + receipt ID
  - Restore operations require explicit authorization
  - All actions are audit logged
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Audit

  @ets_table :model_vault_receipts
  @audit_log_table :model_vault_audit

  # Server secret for key derivation (in production, use proper secret management)
  @server_secret_env "MODEL_VAULT_SECRET"
  @default_secret "tamandua-model-vault-dev-secret-change-in-production"

  ## Types

  @type receipt_id :: String.t()
  @type agent_id :: String.t()

  @type quarantine_receipt :: %{
          receipt_id: receipt_id(),
          agent_id: agent_id(),
          organization_id: String.t() | nil,
          original_path: String.t(),
          sha256: String.t(),
          model_format: String.t(),
          quarantined_at: DateTime.t(),
          reason: String.t(),
          detection_info: map() | nil,
          recovery_key_encrypted: binary(),
          recovery_key_iv: binary(),
          can_restore: boolean(),
          is_deleted: boolean(),
          affected_processes: list(map()),
          restoration_history: list(map())
        }

  @type audit_entry :: %{
          id: String.t(),
          receipt_id: receipt_id(),
          agent_id: agent_id(),
          action: String.t(),
          actor: String.t(),
          timestamp: DateTime.t(),
          details: map(),
          success: boolean()
        }

  ## Client API

  @doc """
  Starts the ModelVault GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Stores a quarantine receipt from an agent.

  The recovery key is encrypted before storage.
  """
  @spec store_receipt(map()) :: {:ok, receipt_id()} | {:error, term()}
  def store_receipt(receipt) do
    GenServer.call(__MODULE__, {:store_receipt, receipt})
  end

  @doc """
  Gets a quarantine receipt by ID.
  """
  @spec get_receipt(receipt_id()) :: {:ok, quarantine_receipt()} | {:error, :not_found}
  def get_receipt(receipt_id) do
    GenServer.call(__MODULE__, {:get_receipt, receipt_id})
  end

  @doc """
  Lists all quarantine receipts, optionally filtered by agent or organization.
  """
  @spec list_receipts(keyword()) :: list(quarantine_receipt())
  def list_receipts(opts \\ []) do
    GenServer.call(__MODULE__, {:list_receipts, opts})
  end

  @doc """
  Lists quarantine receipts for a specific agent.
  """
  @spec list_agent_receipts(agent_id()) :: list(quarantine_receipt())
  def list_agent_receipts(agent_id) do
    list_receipts(agent_id: agent_id)
  end

  @doc """
  Lists quarantine receipts for a specific organization.
  """
  @spec list_org_receipts(String.t()) :: list(quarantine_receipt())
  def list_org_receipts(organization_id) do
    list_receipts(organization_id: organization_id)
  end

  @doc """
  Initiates a restore operation.

  Validates authorization and returns the decrypted recovery key
  to be sent to the agent.

  ## Parameters

  - receipt_id: The quarantine receipt ID
  - restore_path: Path where the model should be restored
  - actor: The user/system initiating the restore
  - authorization: Authorization context (user token, role, etc.)
  """
  @spec initiate_restore(receipt_id(), String.t(), String.t(), map()) ::
          {:ok, String.t()} | {:error, term()}
  def initiate_restore(receipt_id, restore_path, actor, authorization) do
    GenServer.call(__MODULE__, {:initiate_restore, receipt_id, restore_path, actor, authorization})
  end

  @doc """
  Marks a receipt as deleted (model permanently removed from agent vault).
  """
  @spec mark_deleted(receipt_id(), String.t()) :: :ok | {:error, term()}
  def mark_deleted(receipt_id, actor) do
    GenServer.call(__MODULE__, {:mark_deleted, receipt_id, actor})
  end

  @doc """
  Updates restoration history for a receipt.
  """
  @spec record_restoration(receipt_id(), map()) :: :ok | {:error, term()}
  def record_restoration(receipt_id, restoration_record) do
    GenServer.call(__MODULE__, {:record_restoration, receipt_id, restoration_record})
  end

  @doc """
  Gets audit log entries for a receipt.
  """
  @spec get_audit_log(receipt_id()) :: list(audit_entry())
  def get_audit_log(receipt_id) do
    GenServer.call(__MODULE__, {:get_audit_log, receipt_id})
  end

  @doc """
  Gets statistics about quarantined models.
  """
  @spec get_stats(keyword()) :: map()
  def get_stats(opts \\ []) do
    GenServer.call(__MODULE__, {:get_stats, opts})
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@ets_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@audit_log_table, [:bag, :named_table, :public, read_concurrency: true])

    Logger.info("ModelVault initialized")

    {:ok, %{server_secret: get_server_secret()}}
  end

  @impl true
  def handle_call({:store_receipt, receipt}, _from, state) do
    receipt_id = receipt["receipt_id"] || receipt[:receipt_id]
    agent_id = receipt["agent_id"] || receipt[:agent_id]
    recovery_key = receipt["recovery_key"] || receipt[:recovery_key]

    Logger.info("Storing quarantine receipt #{receipt_id} from agent #{agent_id}")

    # Decrypt recovery key from base64 if needed
    recovery_key_bytes =
      case Base.decode64(recovery_key) do
        {:ok, bytes} -> bytes
        :error -> recovery_key
      end

    # Encrypt recovery key for storage
    {encrypted_key, iv} = encrypt_recovery_key(recovery_key_bytes, receipt_id, state.server_secret)

    stored_receipt = %{
      receipt_id: receipt_id,
      agent_id: agent_id,
      organization_id: receipt["organization_id"] || receipt[:organization_id],
      original_path: receipt["original_path"] || receipt[:original_path],
      sha256: receipt["sha256"] || receipt[:sha256],
      model_format: receipt["model_format"] || receipt[:model_format] || "unknown",
      quarantined_at: parse_datetime(receipt["quarantined_at"] || receipt[:quarantined_at]),
      reason: receipt["reason"] || receipt[:reason] || "security_scan_failed",
      detection_info: receipt["detection_info"] || receipt[:detection_info],
      recovery_key_encrypted: encrypted_key,
      recovery_key_iv: iv,
      can_restore: true,
      is_deleted: false,
      affected_processes: receipt["affected_processes"] || receipt[:affected_processes] || [],
      restoration_history: []
    }

    :ets.insert(@ets_table, {receipt_id, stored_receipt})

    # Audit log
    log_audit(receipt_id, agent_id, "quarantine", "agent", %{
      original_path: stored_receipt.original_path,
      sha256: stored_receipt.sha256,
      reason: stored_receipt.reason
    }, true)

    {:reply, {:ok, receipt_id}, state}
  end

  @impl true
  def handle_call({:get_receipt, receipt_id}, _from, state) do
    case :ets.lookup(@ets_table, receipt_id) do
      [{^receipt_id, receipt}] ->
        # Return receipt without the encrypted key
        safe_receipt = Map.drop(receipt, [:recovery_key_encrypted, :recovery_key_iv])
        {:reply, {:ok, safe_receipt}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_receipts, opts}, _from, state) do
    all_receipts =
      :ets.tab2list(@ets_table)
      |> Enum.map(fn {_id, receipt} ->
        Map.drop(receipt, [:recovery_key_encrypted, :recovery_key_iv])
      end)

    filtered =
      all_receipts
      |> filter_by_agent(opts[:agent_id])
      |> filter_by_org(opts[:organization_id])
      |> filter_deleted(opts[:include_deleted] || false)

    {:reply, filtered, state}
  end

  @impl true
  def handle_call({:initiate_restore, receipt_id, restore_path, actor, authorization}, _from, state) do
    case :ets.lookup(@ets_table, receipt_id) do
      [{^receipt_id, receipt}] ->
        cond do
          receipt.is_deleted ->
            log_audit(receipt_id, receipt.agent_id, "restore_attempt", actor, %{
              error: "model_deleted"
            }, false)
            {:reply, {:error, :model_deleted}, state}

          not receipt.can_restore ->
            log_audit(receipt_id, receipt.agent_id, "restore_attempt", actor, %{
              error: "restore_disabled"
            }, false)
            {:reply, {:error, :restore_disabled}, state}

          not authorized?(authorization, receipt) ->
            log_audit(receipt_id, receipt.agent_id, "restore_attempt", actor, %{
              error: "unauthorized"
            }, false)
            {:reply, {:error, :unauthorized}, state}

          true ->
            # Decrypt recovery key
            recovery_key =
              decrypt_recovery_key(
                receipt.recovery_key_encrypted,
                receipt.recovery_key_iv,
                receipt_id,
                state.server_secret
              )

            # Encode as base64 for transmission
            recovery_key_b64 = Base.encode64(recovery_key)

            # Log successful restore initiation
            log_audit(receipt_id, receipt.agent_id, "restore_initiated", actor, %{
              restore_path: restore_path,
              authorization: Map.get(authorization, :method, "unknown")
            }, true)

            Logger.info("Restore initiated for receipt #{receipt_id} by #{actor}")

            {:reply, {:ok, recovery_key_b64}, state}
        end

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:mark_deleted, receipt_id, actor}, _from, state) do
    case :ets.lookup(@ets_table, receipt_id) do
      [{^receipt_id, receipt}] ->
        updated_receipt = %{receipt | is_deleted: true, can_restore: false}
        :ets.insert(@ets_table, {receipt_id, updated_receipt})

        log_audit(receipt_id, receipt.agent_id, "deleted", actor, %{}, true)
        Logger.info("Receipt #{receipt_id} marked as deleted by #{actor}")

        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:record_restoration, receipt_id, restoration_record}, _from, state) do
    case :ets.lookup(@ets_table, receipt_id) do
      [{^receipt_id, receipt}] ->
        updated_history = receipt.restoration_history ++ [restoration_record]
        updated_receipt = %{receipt | restoration_history: updated_history}
        :ets.insert(@ets_table, {receipt_id, updated_receipt})

        log_audit(receipt_id, receipt.agent_id, "restoration_recorded", "agent", %{
          success: restoration_record["success"] || restoration_record[:success],
          restore_path: restoration_record["restore_path"] || restoration_record[:restore_path]
        }, true)

        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_audit_log, receipt_id}, _from, state) do
    entries =
      :ets.lookup(@audit_log_table, receipt_id)
      |> Enum.map(fn {_id, entry} -> entry end)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})

    {:reply, entries, state}
  end

  @impl true
  def handle_call({:get_stats, opts}, _from, state) do
    all_receipts = :ets.tab2list(@ets_table) |> Enum.map(fn {_id, r} -> r end)

    filtered =
      all_receipts
      |> filter_by_agent(opts[:agent_id])
      |> filter_by_org(opts[:organization_id])

    stats = %{
      total_quarantined: length(Enum.filter(filtered, &(not &1.is_deleted))),
      total_deleted: length(Enum.filter(filtered, & &1.is_deleted)),
      total_restored: length(Enum.filter(filtered, &(length(&1.restoration_history) > 0))),
      by_reason: group_by_reason(filtered),
      by_format: group_by_format(filtered),
      recent_quarantines: get_recent(filtered, 10)
    }

    {:reply, stats, state}
  end

  ## Private Functions

  defp get_server_secret do
    @server_secret_env
    |> System.get_env()
    |> case do
      secret when is_binary(secret) and secret != "" -> secret
      _ -> require_dev_secret!()
    end
    |> then(&:crypto.hash(:sha256, &1))
  end

  # Fail closed in production: a missing MODEL_VAULT_SECRET must never silently
  # fall back to a publicly-known constant (which would let anyone decrypt the
  # recovery keys protecting quarantined models). The dev default is only used
  # outside :prod.
  defp require_dev_secret! do
    if Application.get_env(:tamandua_server, :env) == :prod do
      raise "#{@server_secret_env} environment variable must be set in production"
    else
      @default_secret
    end
  end

  defp encrypt_recovery_key(key, receipt_id, server_secret) do
    # Derive a unique key for this receipt
    derived_key = derive_key(server_secret, receipt_id)
    iv = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        derived_key,
        iv,
        key,
        receipt_id,
        true
      )

    # Combine ciphertext and tag
    {ciphertext <> tag, iv}
  end

  defp decrypt_recovery_key(encrypted, iv, receipt_id, server_secret) do
    derived_key = derive_key(server_secret, receipt_id)

    # Split ciphertext and tag
    tag_size = 16
    ciphertext_size = byte_size(encrypted) - tag_size
    <<ciphertext::binary-size(ciphertext_size), tag::binary-size(tag_size)>> = encrypted

    :crypto.crypto_one_time_aead(
      :aes_256_gcm,
      derived_key,
      iv,
      ciphertext,
      receipt_id,
      tag,
      false
    )
  end

  defp derive_key(server_secret, receipt_id) do
    :crypto.mac(:hmac, :sha256, server_secret, "model-vault-key:" <> receipt_id)
  end

  defp authorized?(authorization, _receipt) do
    # Authorization logic - in production, check user roles, permissions, etc.
    case authorization do
      %{role: role} when role in ["admin", "analyst", "soc_manager"] ->
        true

      %{bypass: true} ->
        # For internal/automated operations
        true

      _ ->
        false
    end
  end

  defp log_audit(receipt_id, agent_id, action, actor, details, success) do
    entry = %{
      id: Ecto.UUID.generate(),
      receipt_id: receipt_id,
      agent_id: agent_id,
      action: action,
      actor: actor,
      timestamp: DateTime.utc_now(),
      details: details,
      success: success
    }

    :ets.insert(@audit_log_table, {receipt_id, entry})

    # Also log to main audit system
    try do
      Audit.log_action(
        String.to_atom("model_quarantine_#{action}"),
        Map.merge(details, %{receipt_id: receipt_id}),
        agent_id,
        actor
      )
    rescue
      _ -> :ok
    end
  end

  defp filter_by_agent(receipts, nil), do: receipts
  defp filter_by_agent(receipts, agent_id) do
    Enum.filter(receipts, &(&1.agent_id == agent_id))
  end

  defp filter_by_org(receipts, nil), do: receipts
  defp filter_by_org(receipts, org_id) do
    Enum.filter(receipts, &(&1.organization_id == org_id))
  end

  defp filter_deleted(receipts, true), do: receipts
  defp filter_deleted(receipts, false) do
    Enum.filter(receipts, &(not &1.is_deleted))
  end

  defp group_by_reason(receipts) do
    receipts
    |> Enum.filter(&(not &1.is_deleted))
    |> Enum.group_by(& &1.reason)
    |> Enum.map(fn {reason, list} -> {reason, length(list)} end)
    |> Map.new()
  end

  defp group_by_format(receipts) do
    receipts
    |> Enum.filter(&(not &1.is_deleted))
    |> Enum.group_by(& &1.model_format)
    |> Enum.map(fn {format, list} -> {format, length(list)} end)
    |> Map.new()
  end

  defp get_recent(receipts, count) do
    receipts
    |> Enum.filter(&(not &1.is_deleted))
    |> Enum.sort_by(& &1.quarantined_at, {:desc, DateTime})
    |> Enum.take(count)
    |> Enum.map(&Map.take(&1, [:receipt_id, :original_path, :sha256, :reason, :quarantined_at]))
  end

  defp parse_datetime(nil), do: DateTime.utc_now()
  defp parse_datetime(%DateTime{} = dt), do: dt
  defp parse_datetime(string) when is_binary(string) do
    case DateTime.from_iso8601(string) do
      {:ok, dt, _offset} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_datetime(_), do: DateTime.utc_now()
end
