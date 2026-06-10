defmodule Tamandua.Updates.UpdateServer do
  @moduledoc """
  Update distribution server for agent binaries.

  Provides HTTP endpoints for agents to:
  - Check for updates
  - Download full binaries
  - Download delta patches
  - Report update status

  Implements bandwidth throttling for large deployments.
  """

  use GenServer
  require Logger
  alias Tamandua.Updates.{VersionManager, BinarySigner, RolloutOrchestrator}
  alias Tamandua.Agents

  @type download_token :: String.t()

  defmodule DownloadState do
    @moduledoc false
    defstruct [
      :agent_id,
      :version,
      :platform,
      :arch,
      :type,  # :full or :delta
      :started_at,
      :bytes_transferred,
      :total_bytes,
      :throttle_rate  # bytes per second
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if an update is available for an agent.

  Returns update manifest if available, :up_to_date otherwise.
  """
  @spec check_update(String.t(), String.t(), atom(), atom()) ::
    {:ok, map()} | :up_to_date | {:error, term()}
  def check_update(agent_id, current_version, platform, arch) do
    GenServer.call(__MODULE__, {:check_update, agent_id, current_version, platform, arch})
  end

  @doc """
  Generate a download token for an agent to download an update.

  Tokens are single-use and expire after 1 hour.
  """
  @spec generate_download_token(String.t(), String.t(), atom(), atom(), :full | {:delta, String.t()}) ::
    {:ok, download_token()} | {:error, term()}
  def generate_download_token(agent_id, version, platform, arch, type) do
    GenServer.call(__MODULE__, {:generate_download_token, agent_id, version, platform, arch, type})
  end

  @doc """
  Verify a download token is valid.
  """
  @spec verify_download_token(download_token()) :: {:ok, map()} | {:error, :invalid_token}
  def verify_download_token(token) do
    GenServer.call(__MODULE__, {:verify_download_token, token})
  end

  @doc """
  Track download progress for throttling.
  """
  @spec track_download_progress(download_token(), non_neg_integer()) :: :ok
  def track_download_progress(token, bytes_transferred) do
    GenServer.cast(__MODULE__, {:track_download_progress, token, bytes_transferred})
  end

  @doc """
  Complete a download.
  """
  @spec complete_download(download_token()) :: :ok
  def complete_download(token) do
    GenServer.cast(__MODULE__, {:complete_download, token})
  end

  @doc """
  Report update status from an agent.
  """
  @spec report_update_status(String.t(), String.t(), :downloading | :installing | :verifying | :success | :failed, map()) :: :ok
  def report_update_status(agent_id, version, status, metadata \\ %{}) do
    GenServer.cast(__MODULE__, {:report_update_status, agent_id, version, status, metadata})
  end

  @doc """
  Get current download statistics.
  """
  @spec get_download_stats() :: map()
  def get_download_stats do
    GenServer.call(__MODULE__, :get_download_stats)
  end

  @doc """
  Set global bandwidth throttle (bytes per second per download).

  0 means unlimited.
  """
  @spec set_throttle_rate(non_neg_integer()) :: :ok
  def set_throttle_rate(bytes_per_second) do
    GenServer.call(__MODULE__, {:set_throttle_rate, bytes_per_second})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Schedule token cleanup every 10 minutes
    schedule_token_cleanup()

    state = %{
      download_tokens: %{},
      active_downloads: %{},
      download_stats: %{
        total_downloads: 0,
        active_downloads: 0,
        bytes_transferred: 0,
        success_count: 0,
        failure_count: 0
      },
      global_throttle_rate: get_default_throttle_rate()
    }

    Logger.info("Update Server started with throttle rate: #{state.global_throttle_rate} bytes/sec")
    {:ok, state}
  end

  @impl true
  def handle_call({:check_update, agent_id, current_version, platform, arch}, _from, state) do
    # Check if agent is eligible for update (rollout orchestrator)
    case RolloutOrchestrator.is_agent_eligible?(agent_id, platform, arch) do
      false ->
        {:reply, :up_to_date, state}

      true ->
        case VersionManager.check_update(current_version, platform, arch) do
          {:update_available, version, update_type} ->
            manifest = build_update_manifest(version, update_type)
            Logger.info("Update available for agent #{agent_id}: #{current_version} -> #{version.version}")
            {:reply, {:ok, manifest}, state}

          :up_to_date ->
            {:reply, :up_to_date, state}
        end
    end
  end

  @impl true
  def handle_call({:generate_download_token, agent_id, version, platform, arch, type}, _from, state) do
    # Generate secure random token
    token = generate_token()
    expires_at = DateTime.add(DateTime.utc_now(), 3600, :second)  # 1 hour

    token_data = %{
      agent_id: agent_id,
      version: version,
      platform: platform,
      arch: arch,
      type: type,
      expires_at: expires_at,
      used: false
    }

    state = put_in(state.download_tokens[token], token_data)
    Logger.info("Generated download token for agent #{agent_id}, version #{version}")

    {:reply, {:ok, token}, state}
  end

  @impl true
  def handle_call({:verify_download_token, token}, _from, state) do
    case Map.get(state.download_tokens, token) do
      nil ->
        {:reply, {:error, :invalid_token}, state}

      token_data ->
        cond do
          token_data.used ->
            {:reply, {:error, :token_already_used}, state}

          DateTime.compare(DateTime.utc_now(), token_data.expires_at) == :gt ->
            {:reply, {:error, :token_expired}, state}

          true ->
            # Mark token as used
            state = put_in(state.download_tokens[token].used, true)
            {:reply, {:ok, token_data}, state}
        end
    end
  end

  @impl true
  def handle_call(:get_download_stats, _from, state) do
    stats = Map.merge(state.download_stats, %{
      active_downloads: map_size(state.active_downloads),
      throttle_rate: state.global_throttle_rate
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_call({:set_throttle_rate, bytes_per_second}, _from, state) do
    Logger.info("Setting global throttle rate to #{bytes_per_second} bytes/sec")
    state = %{state | global_throttle_rate: bytes_per_second}
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:track_download_progress, token, bytes_transferred}, state) do
    case Map.get(state.active_downloads, token) do
      nil ->
        # New download, create tracking entry
        download_state = %DownloadState{
          started_at: DateTime.utc_now(),
          bytes_transferred: bytes_transferred,
          throttle_rate: state.global_throttle_rate
        }
        state = put_in(state.active_downloads[token], download_state)
        state = update_in(state.download_stats.bytes_transferred, &(&1 + bytes_transferred))
        {:noreply, state}

      download_state ->
        # Update existing download
        bytes_delta = bytes_transferred - download_state.bytes_transferred
        download_state = %{download_state | bytes_transferred: bytes_transferred}
        state = put_in(state.active_downloads[token], download_state)
        state = update_in(state.download_stats.bytes_transferred, &(&1 + bytes_delta))
        {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:complete_download, token}, state) do
    state = Map.update!(state, :active_downloads, &Map.delete(&1, token))
    state = update_in(state.download_stats.total_downloads, &(&1 + 1))
    Logger.debug("Download completed for token #{token}")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:report_update_status, agent_id, version, status, metadata}, state) do
    Logger.info("Agent #{agent_id} update status: #{status} (version #{version})")

    # Forward to rollout orchestrator for tracking
    RolloutOrchestrator.report_update_status(agent_id, version, status, metadata)

    # Update stats
    state = case status do
      :success ->
        update_in(state.download_stats.success_count, &(&1 + 1))
      :failed ->
        update_in(state.download_stats.failure_count, &(&1 + 1))
      _ ->
        state
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_tokens, state) do
    now = DateTime.utc_now()

    # Remove expired or used tokens
    tokens_to_remove = for {token, data} <- state.download_tokens,
                           data.used or DateTime.compare(now, data.expires_at) == :gt,
                           do: token

    state = Map.update!(state, :download_tokens, fn tokens ->
      Map.drop(tokens, tokens_to_remove)
    end)

    if length(tokens_to_remove) > 0 do
      Logger.debug("Cleaned up #{length(tokens_to_remove)} expired tokens")
    end

    schedule_token_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Helpers

  defp build_update_manifest(version, update_type) do
    base_manifest = %{
      version: version.version,
      platform: version.platform,
      arch: version.arch,
      checksum_sha256: version.checksum_sha256,
      signature_ed25519: version.signature_ed25519,
      size_bytes: version.size_bytes,
      critical: version.critical,
      release_notes: version.release_notes,
      min_version: version.min_version
    }

    case update_type do
      :full ->
        Map.put(base_manifest, :download_type, :full)

      {:delta, patch_url} ->
        base_manifest
        |> Map.put(:download_type, :delta)
        |> Map.put(:delta_patch_url, patch_url)
    end
  end

  defp generate_token do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  defp schedule_token_cleanup do
    Process.send_after(self(), :cleanup_tokens, :timer.minutes(10))
  end

  defp get_default_throttle_rate do
    # Default: 10 MB/s per download
    Application.get_env(:tamandua_server, :update_throttle_rate, 10_485_760)
  end
end
