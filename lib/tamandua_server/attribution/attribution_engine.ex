defmodule TamanduaServer.Attribution.AttributionEngine do
  @moduledoc """
  Attribution Engine

  Coordinates threat actor attribution using ML service.
  Manages attribution requests, caches results, enriches alerts with attribution metadata.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Repo

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  @attribution_cache_ttl 3600  # 1 hour

  # Client API

  @doc """
  Start the attribution engine
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Attribute a single alert to threat actor
  """
  def attribute_alert(alert_id) do
    GenServer.call(__MODULE__, {:attribute_alert, alert_id}, 30_000)
  end

  @doc """
  Attribute multiple alerts as a campaign
  """
  def attribute_campaign(alert_ids) do
    GenServer.call(__MODULE__, {:attribute_campaign, alert_ids}, 60_000)
  end

  @doc """
  Get attribution for alert (from cache or DB)
  """
  def get_attribution(alert_id) do
    GenServer.call(__MODULE__, {:get_attribution, alert_id})
  end

  @doc """
  Submit analyst feedback for attribution
  """
  def submit_feedback(alert_id, attribution_id, feedback) do
    GenServer.cast(__MODULE__, {:submit_feedback, alert_id, attribution_id, feedback})
  end

  @doc """
  Get attribution statistics
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting Attribution Engine")

    state = %{
      cache: %{},
      stats: %{
        total_attributions: 0,
        successful_attributions: 0,
        failed_attributions: 0,
        avg_confidence: 0.0,
        feedback_count: 0
      }
    }

    # Schedule periodic cleanup
    schedule_cache_cleanup()

    {:ok, state}
  end

  @impl true
  def handle_call({:attribute_alert, alert_id}, _from, state) do
    case do_attribute_alert(alert_id) do
      {:ok, attribution} ->
        new_state = update_stats(state, :success, attribution.confidence)
        {:reply, {:ok, attribution}, new_state}

      {:error, reason} = error ->
        new_state = update_stats(state, :failure, 0.0)
        Logger.error("Attribution failed for alert #{alert_id}: #{inspect(reason)}")
        {:reply, error, new_state}
    end
  end

  @impl true
  def handle_call({:attribute_campaign, alert_ids}, _from, state) do
    case do_attribute_campaign(alert_ids) do
      {:ok, attribution} ->
        new_state = update_stats(state, :success, attribution.confidence)
        {:reply, {:ok, attribution}, new_state}

      {:error, reason} = error ->
        new_state = update_stats(state, :failure, 0.0)
        Logger.error("Campaign attribution failed: #{inspect(reason)}")
        {:reply, error, new_state}
    end
  end

  @impl true
  def handle_call({:get_attribution, alert_id}, _from, state) do
    attribution =
      case Map.get(state.cache, alert_id) do
        nil -> load_attribution_from_db(alert_id)
        cached -> cached
      end

    {:reply, attribution, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_cast({:submit_feedback, alert_id, attribution_id, feedback}, state) do
    Task.start(fn ->
      submit_feedback_to_ml(alert_id, attribution_id, feedback)
    end)

    new_stats = Map.update!(state.stats, :feedback_count, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(:cleanup_cache, state) do
    new_cache = cleanup_expired_cache(state.cache)
    schedule_cache_cleanup()
    {:noreply, %{state | cache: new_cache}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp do_attribute_alert(alert_id) do
    with {:ok, alert} <- Alerts.get_alert(alert_id),
         {:ok, features} <- extract_alert_features(alert),
         {:ok, attribution} <- call_ml_service(features),
         {:ok, persisted} <- persist_attribution(alert_id, attribution) do
      # Enrich alert with attribution
      Alerts.update_alert(alert, %{
        threat_actor: attribution.primary_actor,
        attribution_confidence: attribution.confidence,
        attribution_id: persisted.id
      })

      {:ok, persisted}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp do_attribute_campaign(alert_ids) do
    with {:ok, alerts} <- load_alerts(alert_ids),
         {:ok, campaign_features} <- extract_campaign_features(alerts),
         {:ok, attribution} <- call_ml_service(campaign_features, :campaign),
         {:ok, persisted} <- persist_campaign_attribution(alert_ids, attribution) do
      # Update all alerts with campaign attribution
      Enum.each(alerts, fn alert ->
        Alerts.update_alert(alert, %{
          threat_actor: attribution.primary_actor,
          attribution_confidence: attribution.confidence,
          attribution_id: persisted.id,
          campaign_id: persisted.campaign_id
        })
      end)

      {:ok, persisted}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp extract_alert_features(alert) do
    features = %{
      # TTP features
      ttps: extract_ttps(alert),
      mitre_techniques: alert.mitre_techniques || [],

      # Tool features
      tools: extract_tools(alert),
      process_name: alert.process_name,
      command_line: alert.command_line,

      # Target features
      target_industry: alert.organization_industry,
      target_region: alert.organization_region,
      organization_size: alert.organization_size || 1,

      # Timing features
      timestamp: alert.inserted_at,

      # Infrastructure features
      src_ip: alert.src_ip,
      dst_ip: alert.dst_ip,
      domain: alert.domain,

      # Artifact features
      file_path: alert.file_path,
      file_hash: alert.file_hash,
      file_size: alert.file_size,
      entropy: alert.entropy,
      is_signed: alert.is_signed,
      signature_valid: alert.signature_valid,

      # Registry features
      registry_key: alert.registry_key,

      # Behavior features
      kill_chain_stage: alert.kill_chain_stage,
      remote_login: alert.metadata["remote_login"],
      privilege_elevation: alert.metadata["privilege_elevation"],
      lateral_movement: alert.metadata["lateral_movement"],

      # Communication features
      protocol: alert.protocol,
      bytes_sent: alert.bytes_sent,
      bytes_received: alert.bytes_received,
      beaconing: alert.metadata["beaconing"],

      # Malware features
      malware_family: alert.malware_family,
      yara_matches: alert.yara_matches || []
    }

    {:ok, features}
  end

  defp extract_campaign_features(alerts) do
    # Aggregate features across alerts
    features = %{
      ttps: alerts |> Enum.flat_map(&extract_ttps/1) |> Enum.uniq(),
      tools: alerts |> Enum.flat_map(&extract_tools/1) |> Enum.uniq(),
      target_industries: alerts |> Enum.map(& &1.organization_industry) |> Enum.uniq() |> Enum.reject(&is_nil/1),
      target_regions: alerts |> Enum.map(& &1.organization_region) |> Enum.uniq() |> Enum.reject(&is_nil/1),
      malware_families: alerts |> Enum.map(& &1.malware_family) |> Enum.uniq() |> Enum.reject(&is_nil/1),

      # Infrastructure
      infrastructure: %{
        ips: alerts |> Enum.flat_map(&[&1.src_ip, &1.dst_ip]) |> Enum.uniq() |> Enum.reject(&is_nil/1),
        domains: alerts |> Enum.map(& &1.domain) |> Enum.uniq() |> Enum.reject(&is_nil/1)
      },

      # Timing
      start_time: alerts |> Enum.map(& &1.inserted_at) |> Enum.min(DateTime),
      end_time: alerts |> Enum.map(& &1.inserted_at) |> Enum.max(DateTime),
      duration_hours: calculate_duration_hours(alerts),

      # Behavior patterns
      behavior_patterns: %{
        rapid_spread: alerts |> length() > 10,
        victim_count: alerts |> Enum.map(& &1.agent_id) |> Enum.uniq() |> length(),
        geographic_spread: alerts |> Enum.map(& &1.organization_region) |> Enum.uniq() |> length()
      },

      # C2 protocols
      c2_protocols: alerts |> Enum.map(& &1.protocol) |> Enum.uniq() |> Enum.reject(&is_nil/1),

      # Alert count
      alert_count: length(alerts)
    }

    {:ok, features}
  end

  defp extract_ttps(alert) do
    ttps = alert.mitre_techniques || []

    # Extract from detection rules
    ttps = if alert.sigma_rule_name do
      ttps ++ extract_ttps_from_sigma(alert.sigma_rule_name)
    else
      ttps
    end

    # Extract from YARA matches
    ttps = if alert.yara_matches do
      ttps ++ extract_ttps_from_yara(alert.yara_matches)
    else
      ttps
    end

    Enum.uniq(ttps)
  end

  defp extract_ttps_from_sigma(rule_name) do
    # Map common Sigma rules to TTPs
    cond do
      String.contains?(rule_name, "mimikatz") -> ["T1003", "T1003.001"]
      String.contains?(rule_name, "powershell") -> ["T1059", "T1059.001"]
      String.contains?(rule_name, "wmi") -> ["T1047"]
      String.contains?(rule_name, "psexec") -> ["T1021", "T1021.002"]
      String.contains?(rule_name, "scheduled_task") -> ["T1053", "T1053.005"]
      true -> []
    end
  end

  defp extract_ttps_from_yara(yara_matches) do
    yara_matches
    |> Enum.flat_map(fn match ->
      case match do
        %{"tags" => tags} when is_list(tags) ->
          tags
          |> Enum.filter(&String.starts_with?(&1, "T"))
          |> Enum.filter(&String.match?(&1, ~r/^T\d{4}/))

        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  defp extract_tools(alert) do
    tools = []

    # Extract from process name
    tools = if alert.process_name do
      tools ++ extract_tools_from_process(alert.process_name)
    else
      tools
    end

    # Extract from command line
    tools = if alert.command_line do
      tools ++ extract_tools_from_cmdline(alert.command_line)
    else
      tools
    end

    Enum.uniq(tools)
  end

  defp extract_tools_from_process(process_name) do
    process_lower = String.downcase(process_name)

    known_tools = [
      "mimikatz", "powershell", "cmd", "psexec", "wmic", "rundll32",
      "regsvr32", "mshta", "certutil", "bitsadmin"
    ]

    Enum.filter(known_tools, &String.contains?(process_lower, &1))
  end

  defp extract_tools_from_cmdline(cmdline) do
    cmdline_lower = String.downcase(cmdline)

    known_tools = [
      "invoke-mimikatz", "bloodhound", "sharphound", "rubeus",
      "crackmapexec", "impacket", "metasploit", "cobalt strike"
    ]

    Enum.filter(known_tools, &String.contains?(cmdline_lower, &1))
  end

  # The previous version wrapped min/max in a case with an unreachable
  # `_ -> 0.0` fallback (a {min, max} tuple always matches); its evident
  # intent was the empty-alerts case, which Enum.min_by/3 raised on before
  # the case could match. Handle it as an explicit function clause instead.
  defp calculate_duration_hours([]), do: 0.0

  defp calculate_duration_hours(alerts) do
    min_alert = Enum.min_by(alerts, & &1.inserted_at, DateTime)
    max_alert = Enum.max_by(alerts, & &1.inserted_at, DateTime)

    DateTime.diff(max_alert.inserted_at, min_alert.inserted_at, :second) / 3600.0
  end

  defp call_ml_service(features, type \\ :alert) do
    url = "#{@ml_service_url}/api/attribution/analyze"

    body = Jason.encode!(%{
      features: features,
      type: type
    })

    headers = [{"Content-Type", "application/json"}]

    case TamanduaServer.HttpClient.post(url, body, headers, timeout: 30_000, recv_timeout: 30_000) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, result} -> parse_attribution_response(result)
          {:error, reason} -> {:error, {:json_decode_error, reason}}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("ML service returned status #{status_code}: #{body}")
        {:error, {:ml_service_error, status_code}}

      {:error, reason} ->
        Logger.error("Failed to call ML service: #{inspect(reason)}")
        {:error, {:http_error, reason}}
    end
  end

  defp parse_attribution_response(result) do
    attribution = %{
      primary_actor: result["primary_attribution"]["threat_actor"],
      confidence: result["primary_attribution"]["confidence"],
      alternative_actors: result["alternative_attributions"] || [],
      explanation: result["primary_attribution"]["explanation"],
      feature_contributions: result["primary_attribution"]["feature_contributions"],
      timestamp: DateTime.utc_now()
    }

    {:ok, attribution}
  end

  defp persist_attribution(alert_id, attribution) do
    _attrs = %{
      alert_id: alert_id,
      threat_actor: attribution.primary_actor,
      confidence: attribution.confidence,
      alternative_actors: attribution.alternative_actors,
      explanation: attribution.explanation,
      feature_contributions: attribution.feature_contributions,
      inserted_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }

    changeset = TamanduaServer.Attribution.Attribution.changeset(
      %TamanduaServer.Attribution.Attribution{},
      attribution
    )
    case Repo.insert(changeset) do
      {:ok, record} -> {:ok, record}
      {:error, changeset_err} -> {:error, {:db_error, changeset_err}}
    end
  rescue
    _ ->
      # Fallback if schema doesn't exist yet
      {:ok, Map.merge(attribution, %{id: UUID.uuid4()})}
  end

  defp persist_campaign_attribution(alert_ids, attribution) do
    campaign_id = UUID.uuid4()

    attrs = %{
      campaign_id: campaign_id,
      alert_ids: alert_ids,
      threat_actor: attribution.primary_actor,
      confidence: attribution.confidence,
      alternative_actors: attribution.alternative_actors,
      explanation: attribution.explanation,
      alert_count: length(alert_ids),
      inserted_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }

    {:ok, Map.merge(attrs, %{id: UUID.uuid4()})}
  end

  defp load_attribution_from_db(_alert_id) do
    # Query from DB (placeholder)
    nil
  end

  defp load_alerts(alert_ids) do
    alerts =
      alert_ids
      |> Enum.map(&Alerts.get_alert/1)
      |> Enum.filter(fn
        {:ok, _alert} -> true
        _ -> false
      end)
      |> Enum.map(fn {:ok, alert} -> alert end)

    if length(alerts) > 0 do
      {:ok, alerts}
    else
      {:error, :no_alerts_found}
    end
  end

  defp submit_feedback_to_ml(alert_id, attribution_id, feedback) do
    url = "#{@ml_service_url}/api/attribution/feedback"

    body = Jason.encode!(%{
      alert_id: alert_id,
      attribution_id: attribution_id,
      feedback: feedback
    })

    headers = [{"Content-Type", "application/json"}]

    case TamanduaServer.HttpClient.post(url, body, headers) do
      {:ok, %{status_code: 200}} ->
        Logger.info("Feedback submitted for attribution #{attribution_id}")
        :ok

      {:error, reason} ->
        Logger.error("Failed to submit feedback: #{inspect(reason)}")
        :error
    end
  end

  defp update_stats(state, result, confidence) do
    new_stats =
      state.stats
      |> Map.update!(:total_attributions, &(&1 + 1))
      |> then(fn stats ->
        case result do
          :success ->
            stats
            |> Map.update!(:successful_attributions, &(&1 + 1))
            |> Map.update!(:avg_confidence, fn avg ->
              total = stats.successful_attributions + 1
              (avg * (total - 1) + confidence) / total
            end)

          :failure ->
            Map.update!(stats, :failed_attributions, &(&1 + 1))
        end
      end)

    %{state | stats: new_stats}
  end

  defp schedule_cache_cleanup do
    Process.send_after(self(), :cleanup_cache, @attribution_cache_ttl * 1000)
  end

  defp cleanup_expired_cache(cache) do
    now = System.system_time(:second)

    cache
    |> Enum.filter(fn {_key, value} ->
      value.timestamp
      |> DateTime.to_unix()
      |> Kernel.+(@attribution_cache_ttl)
      |> Kernel.>(now)
    end)
    |> Enum.into(%{})
  end
end
