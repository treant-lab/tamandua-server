defmodule TamanduaServer.Detection.ThresholdConfig do
  @moduledoc """
  Loads and provides access to externalized detection thresholds from YAML config.

  Thresholds are loaded from `config/detection_thresholds.yml` at startup and
  can be reloaded at runtime via `reload/0`. The YAML file is watched for changes
  and auto-reloaded in development mode.

  All threshold accessors fall back to hardcoded defaults if the config file
  is missing or malformed, ensuring the detection engine always has valid values.

  ## Usage

      # Get a specific threshold
      ThresholdConfig.get(:entropy, :dga_domain)
      # => 4.0

      # Get with custom default
      ThresholdConfig.get(:scores, :custom_threshold, 0.5)
      # => 0.5

      # Reload thresholds from disk
      ThresholdConfig.reload()

  ## Configuration File

  Thresholds are defined in `config/detection_thresholds.yml`:

      entropy:
        dga_domain:
          default: 4.0
          min: 3.0
          max: 5.0

  Each threshold specifies a default value and optional min/max for validation.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.PresetResolver

  @ets_table :detection_threshold_config
  @config_path Path.join([:code.priv_dir(:tamandua_server), "..", "..", "..", "config", "detection_thresholds.yml"])

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get a threshold value by category and key.

  ## Parameters
    - category: The threshold category (e.g., :entropy, :frequency, :scores)
    - key: The specific threshold key within the category
    - default: Optional fallback if threshold not found (uses hardcoded default if nil)

  ## Examples

      iex> ThresholdConfig.get(:entropy, :dga_domain)
      4.0

      iex> ThresholdConfig.get(:scores, :threat_alert_threshold)
      0.75
  """
  @spec get(atom(), atom(), term()) :: term()
  def get(category, key, default \\ nil) do
    case :ets.lookup(@ets_table, {category, key}) do
      [{{^category, ^key}, value}] ->
        value

      [] ->
        # Fall back to hardcoded default
        fallback = default || get_hardcoded_default(category, key)
        Logger.debug("[ThresholdConfig] Using fallback for #{category}.#{key}: #{inspect(fallback)}")
        fallback
    end
  end

  @doc """
  Get all thresholds for a category as a map.
  """
  @spec get_category(atom()) :: map()
  def get_category(category) do
    :ets.tab2list(@ets_table)
    |> Enum.filter(fn {{cat, _key}, _val} -> cat == category end)
    |> Enum.map(fn {{_cat, key}, val} -> {key, val} end)
    |> Map.new()
  rescue
    ArgumentError -> %{}
  end

  @doc """
  Reload thresholds from the config file.
  """
  @spec reload() :: :ok | {:error, term()}
  def reload do
    GenServer.call(__MODULE__, :reload)
  end

  @doc """
  Get the path to the config file.
  """
  @spec config_path() :: String.t()
  def config_path do
    # Try multiple paths for flexibility
    cond do
      File.exists?(resolved_config_path()) -> resolved_config_path()
      File.exists?("config/detection_thresholds.yml") -> "config/detection_thresholds.yml"
      File.exists?("../../config/detection_thresholds.yml") -> "../../config/detection_thresholds.yml"
      true -> resolved_config_path()
    end
  end

  defp resolved_config_path do
    # Resolve relative to the umbrella root
    case :code.priv_dir(:tamandua_server) do
      {:error, _} ->
        "config/detection_thresholds.yml"

      priv_dir ->
        priv_dir
        |> Path.join("../../..")
        |> Path.expand()
        |> Path.join("config/detection_thresholds.yml")
    end
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS table for fast threshold lookups
    :ets.new(@ets_table, [:named_table, :set, :public, {:read_concurrency, true}])

    # Load initial thresholds
    load_thresholds()

    # Schedule file watcher in dev mode
    if Application.get_env(:tamandua_server, :env) == :dev do
      schedule_file_watch()
    end

    {:ok, %{last_mtime: get_file_mtime()}}
  end

  @impl true
  def handle_call(:reload, _from, state) do
    case load_thresholds() do
      :ok ->
        Logger.info("[ThresholdConfig] Thresholds reloaded successfully")
        {:reply, :ok, %{state | last_mtime: get_file_mtime()}}

      {:error, reason} = error ->
        Logger.error("[ThresholdConfig] Failed to reload thresholds: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_info(:check_file, state) do
    current_mtime = get_file_mtime()

    new_state =
      if current_mtime != state.last_mtime do
        Logger.info("[ThresholdConfig] Config file changed, reloading...")
        load_thresholds()
        %{state | last_mtime: current_mtime}
      else
        state
      end

    schedule_file_watch()
    {:noreply, new_state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_thresholds do
    path = config_path()

    case File.read(path) do
      {:ok, content} ->
        case YamlElixir.read_from_string(content) do
          {:ok, config} ->
            parse_and_store_config(config)
            apply_preset_overlay(config)
            :ok

          {:error, reason} ->
            Logger.warning("[ThresholdConfig] Failed to parse YAML: #{inspect(reason)}, using defaults")
            load_hardcoded_defaults()
            log_active_preset("mid-market", :fallback)
            {:error, {:yaml_parse, reason}}
        end

      {:error, :enoent} ->
        Logger.warning("[ThresholdConfig] Config file not found at #{path}, using defaults")
        load_hardcoded_defaults()
        log_active_preset("mid-market", :fallback)
        :ok

      {:error, reason} ->
        Logger.warning("[ThresholdConfig] Failed to read config: #{inspect(reason)}, using defaults")
        load_hardcoded_defaults()
        log_active_preset("mid-market", :fallback)
        {:error, {:file_read, reason}}
    end
  end

  defp parse_and_store_config(config) when is_map(config) do
    Enum.each(config, fn {category_str, thresholds} ->
      category = String.to_atom(category_str)

      if is_map(thresholds) do
        Enum.each(thresholds, fn {key_str, value_def} ->
          key = String.to_atom(key_str)
          value = extract_threshold_value(value_def)
          :ets.insert(@ets_table, {{category, key}, value})
        end)
      end
    end)
  end

  defp parse_and_store_config(_), do: :ok

  defp extract_threshold_value(%{"default" => default}), do: default
  defp extract_threshold_value(value) when is_number(value), do: value
  defp extract_threshold_value(value) when is_binary(value), do: value
  defp extract_threshold_value(value) when is_list(value), do: value
  defp extract_threshold_value(_), do: nil

  # Overlay the resolved GLOBAL preset onto the score knobs already in ETS.
  # org_settings is nil here (global resolution only) — per-org override is a
  # documented setting resolved by PresetResolver elsewhere, not on this hot path.
  defp apply_preset_overlay(config) when is_map(config) do
    presets_block = Map.get(config, "presets", %{})

    case PresetResolver.resolve_preset(presets_block, nil) do
      {:ok, name, source, knobs} ->
        # Map preset knob keys -> existing ETS {category, key} slots.
        put_knob(:scores, :threat_alert_threshold, knobs["threat_alert_threshold"])
        put_knob(:scores, :threat_critical_threshold, knobs["threat_critical_threshold"])
        put_knob(:scores, :risk_alert_threshold, knobs["risk_alert_threshold"])
        # Suppression knob lives under a dedicated ETS category so Suppression
        # (Alerts.Suppression) can read the preset-resolved value via ThresholdConfig.get/3.
        put_knob(:fp_preset, :suppression_occurrence_threshold, knobs["suppression_occurrence_threshold"])
        put_knob(:fp_preset, :active_name, to_string(name))
        put_knob(:fp_preset, :active_source, to_string(source))
        log_active_preset(name, source)
        :ok

      {:error, reason} ->
        Logger.warning("[ThresholdConfig] FP preset overlay failed (#{inspect(reason)}); " <>
          "falling back to mid-market thresholds already loaded from YAML")
        log_active_preset("mid-market", :fallback)
        :ok
    end
  end

  defp apply_preset_overlay(_), do: :ok

  defp put_knob(_cat, _key, nil), do: :ok
  defp put_knob(cat, key, value), do: :ets.insert(@ets_table, {{cat, key}, value})

  # Non-silent boot announcement (FPB-02): names BOTH preset and source.
  defp log_active_preset(name, source) do
    Logger.info("[ThresholdConfig] Active FP-budget preset: #{name} (source: #{source})")
  end

  defp load_hardcoded_defaults do
    defaults = hardcoded_defaults()

    Enum.each(defaults, fn {category, thresholds} ->
      Enum.each(thresholds, fn {key, value} ->
        :ets.insert(@ets_table, {{category, key}, value})
      end)
    end)
  end

  defp get_hardcoded_default(category, key) do
    defaults = hardcoded_defaults()

    case Map.get(defaults, category) do
      nil -> nil
      category_defaults -> Map.get(category_defaults, key)
    end
  end

  defp hardcoded_defaults do
    %{
      # Entropy thresholds
      entropy: %{
        dga_domain: 4.0,
        dns_tunnel_subdomain: 3.5,
        c2_https_domain: 4.0
      },

      # Frequency thresholds
      frequency: %{
        dns_beaconing_queries: 100,
        dns_beaconing_window_minutes: 5,
        c2_high_frequency_connections: 30,
        c2_frequency_window_minutes: 5,
        dns_tunnel_volume: 50,
        dns_tunnel_volume_window_seconds: 60,
        rapid_file_ops_count: 50,
        rapid_file_ops_window_seconds: 10,
        exfil_unique_subdomains: 30,
        exfil_window_minutes: 5
      },

      # Time windows
      time_windows: %{
        event_ttl_hours: 1,
        lateral_movement_retention_hours: 168,
        c2_pattern_ttl_seconds: 3600,
        dns_data_ttl_minutes: 15,
        baseline_learning_hours: 48
      },

      # Score thresholds
      scores: %{
        threat_alert_threshold: 0.75,
        threat_critical_threshold: 0.9,
        risk_alert_threshold: 75,
        zscore_threshold: 3.0,
        c2_composite_threshold: 0.6,
        dns_tunnel_alert_threshold: 0.7,
        lateral_movement_threshold: 15
      },

      # Behavioral thresholds
      behavioral: %{
        ewma_alpha: 0.15,
        min_observations_zscore: 30,
        sustained_risk_ticks: 5,
        peer_group_recalc_minutes: 15,
        threshold_prior_strength: 10
      },

      # Graph limits
      graph_limits: %{
        max_lateral_edges: 500_000,
        max_lateral_anomalies: 50_000,
        max_bfs_depth: 12,
        correlation_cache_max_entries: 100_000,
        correlation_cache_ttl_hours: 1
      },

      # Label lengths
      label_lengths: %{
        dns_long_label_chars: 20,
        dns_exfil_label_chars: 30,
        dns_tunnel_long_label_chars: 24
      },

      # C2 beaconing
      c2_beaconing: %{
        min_samples: 5,
        min_span_seconds: 600,
        beacon_signal_weight: 0.4,
        dns_signal_weight: 0.3,
        ja3_signal_weight: 0.3
      }
    }
  end

  defp get_file_mtime do
    case File.stat(config_path()) do
      {:ok, %{mtime: mtime}} -> mtime
      _ -> nil
    end
  end

  defp schedule_file_watch do
    Process.send_after(self(), :check_file, 5_000)
  end
end
