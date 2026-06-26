defmodule TamanduaServer.Settings do
  @moduledoc """
  Context module for managing application settings.

  Settings are stored in ETS for fast runtime access and can optionally
  be persisted to the database for settings that need to survive restarts.

  ## Categories

  - **general**: Agent heartbeat interval, telemetry batch settings
  - **detection**: ML settings, auto-response configuration
  - **notifications**: Email, Slack, and webhook configurations
  - **integrations**: Third-party service integrations
  - **system**: Data retention, maintenance settings
  """

  use GenServer
  require Logger

  @table :tamandua_settings
  @persist_to_env true

  # Default settings
  @defaults %{
    general: %{
      agent_heartbeat_interval: 30,
      telemetry_batch_size: 100,
      telemetry_batch_timeout: 5
    },
    detection: %{
      ml_enabled: true,
      ml_threshold: 0.7,
      auto_response_enabled: false
    },
    notifications: %{
      email_enabled: false,
      email_recipients: [],
      slack_enabled: false,
      slack_webhook: nil,
      webhook_enabled: false,
      webhook_url: nil,
      push_tokens: [],
      critical_alerts: true,
      high_alerts: false,
      medium_alerts: false,
      daily_digest: false,
      weekly_report: false
    },
    integrations: %{
      virustotal: %{enabled: false},
      abuseipdb: %{enabled: false},
      misp: %{enabled: false},
      splunk: %{enabled: false},
      elasticsearch: %{enabled: false}
    },
    system: %{
      event_retention_days: 30,
      alert_retention_days: 90
    }
  }

  # Client API

  @doc """
  Starts the Settings GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Gets all settings for a category.

  ## Examples

      iex> TamanduaServer.Settings.get(:general)
      %{agent_heartbeat_interval: 30, telemetry_batch_size: 100, ...}
  """
  def get(category) when is_atom(category) do
    case :ets.lookup(@table, category) do
      [{^category, settings}] -> settings
      [] -> Map.get(@defaults, category, %{})
    end
  end

  @doc """
  Gets a specific setting value.

  ## Examples

      iex> TamanduaServer.Settings.get(:general, :agent_heartbeat_interval)
      30
  """
  def get(category, key) when is_atom(category) and is_atom(key) do
    settings = get(category)
    Map.get(settings, key)
  end

  @doc """
  Updates settings for a category.

  Returns `{:ok, updated_settings}` on success.

  ## Examples

      iex> TamanduaServer.Settings.update(:general, %{agent_heartbeat_interval: 60})
      {:ok, %{agent_heartbeat_interval: 60, telemetry_batch_size: 100, ...}}
  """
  def update(category, updates) when is_atom(category) and is_map(updates) do
    GenServer.call(__MODULE__, {:update, category, updates})
  end

  @doc """
  Resets a category to its default settings.
  """
  def reset(category) when is_atom(category) do
    GenServer.call(__MODULE__, {:reset, category})
  end

  @doc """
  Gets all settings across all categories.
  """
  def all do
    categories = [:general, :detection, :notifications, :integrations, :system]

    Enum.reduce(categories, %{}, fn category, acc ->
      Map.put(acc, category, get(category))
    end)
  end

  @doc """
  Checks if the settings table is initialized.
  """
  def initialized? do
    case :ets.info(@table) do
      :undefined -> false
      _ -> true
    end
  end

  # GenServer Implementation

  @impl true
  def init(_opts) do
    # Create ETS table for settings
    :ets.new(@table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Load defaults
    Enum.each(@defaults, fn {category, settings} ->
      :ets.insert(@table, {category, settings})
    end)

    # Load from application environment if configured
    if @persist_to_env do
      load_from_env()
    end

    Logger.info("Settings manager initialized")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:update, category, updates}, _from, state) do
    current = get(category)

    # Convert string keys to atoms for consistency
    normalized_updates = normalize_keys(updates)

    # Merge with current settings
    updated = Map.merge(current, normalized_updates)

    # Store in ETS
    :ets.insert(@table, {category, updated})

    # Optionally update application environment
    if @persist_to_env do
      update_env(category, updated)
    end

    Logger.info("Settings updated for category: #{category}")
    {:reply, {:ok, updated}, state}
  end

  @impl true
  def handle_call({:reset, category}, _from, state) do
    defaults = Map.get(@defaults, category, %{})
    :ets.insert(@table, {category, defaults})

    if @persist_to_env do
      update_env(category, defaults)
    end

    Logger.info("Settings reset to defaults for category: #{category}")
    {:reply, {:ok, defaults}, state}
  end

  # Private Functions

  defp normalize_keys(map) when is_map(map) do
    Enum.reduce(map, %{}, fn
      {key, value}, acc when is_binary(key) ->
        atom_key = String.to_existing_atom(key)
        Map.put(acc, atom_key, normalize_value(value))
      {key, value}, acc when is_atom(key) ->
        Map.put(acc, key, normalize_value(value))
    end)
  rescue
    ArgumentError ->
      # If string key doesn't have corresponding atom, try snake_case conversion
      Enum.reduce(map, %{}, fn
        {key, value}, acc when is_binary(key) ->
          atom_key = key |> Macro.underscore() |> String.to_atom()
          Map.put(acc, atom_key, normalize_value(value))
        {key, value}, acc when is_atom(key) ->
          Map.put(acc, key, normalize_value(value))
      end)
  end
  defp normalize_keys(other), do: other

  defp normalize_value(value) when is_map(value), do: normalize_keys(value)
  defp normalize_value(value) when is_list(value), do: Enum.map(value, &normalize_value/1)
  defp normalize_value(value), do: value

  defp load_from_env do
    config = Application.get_all_env(:tamandua_server)

    # Map application config to our settings structure
    general_settings = %{
      agent_heartbeat_interval: Keyword.get(config, :agent_heartbeat_interval, 30),
      telemetry_batch_size: Keyword.get(config, :telemetry_batch_size, 100),
      telemetry_batch_timeout: Keyword.get(config, :telemetry_batch_timeout, 5)
    }
    :ets.insert(@table, {:general, Map.merge(get(:general), general_settings)})

    detection_settings = %{
      ml_enabled: Keyword.get(config, :ml_enabled, true),
      ml_threshold: Keyword.get(config, :ml_confidence_threshold, 0.7),
      auto_response_enabled: Keyword.get(config, :auto_response_enabled, false)
    }
    :ets.insert(@table, {:detection, Map.merge(get(:detection), detection_settings)})

    # Load notifications from nested config
    notifications_config = Keyword.get(config, :notifications, [])
    notifications_settings = %{
      email_enabled: Keyword.get(notifications_config, :email_enabled, false),
      email_recipients: Keyword.get(notifications_config, :email_recipients, []),
      slack_enabled: Keyword.get(notifications_config, :slack_enabled, false),
      slack_webhook: Keyword.get(notifications_config, :slack_webhook),
      webhook_enabled: Keyword.get(notifications_config, :webhook_enabled, false),
      webhook_url: Keyword.get(notifications_config, :webhook_url),
      push_tokens: Keyword.get(notifications_config, :push_tokens, []),
      critical_alerts: Keyword.get(notifications_config, :critical_alerts, true),
      high_alerts: Keyword.get(notifications_config, :high_alerts, false),
      medium_alerts: Keyword.get(notifications_config, :medium_alerts, false)
    }
    :ets.insert(@table, {:notifications, Map.merge(get(:notifications), notifications_settings)})

    # Load system settings
    system_settings = %{
      event_retention_days: Keyword.get(config, :event_retention_days, 30),
      alert_retention_days: Keyword.get(config, :alert_retention_days, 90)
    }
    :ets.insert(@table, {:system, Map.merge(get(:system), system_settings)})
  end

  defp update_env(category, settings) do
    case category do
      :general ->
        Application.put_env(:tamandua_server, :agent_heartbeat_interval, settings[:agent_heartbeat_interval])
        Application.put_env(:tamandua_server, :telemetry_batch_size, settings[:telemetry_batch_size])
        Application.put_env(:tamandua_server, :telemetry_batch_timeout, settings[:telemetry_batch_timeout])

      :detection ->
        Application.put_env(:tamandua_server, :ml_enabled, settings[:ml_enabled])
        Application.put_env(:tamandua_server, :ml_confidence_threshold, settings[:ml_threshold])
        Application.put_env(:tamandua_server, :auto_response_enabled, settings[:auto_response_enabled])

      :notifications ->
        current = Application.get_env(:tamandua_server, :notifications, [])
        updated = Keyword.merge(current, [
          email_enabled: settings[:email_enabled],
          email_recipients: settings[:email_recipients],
          slack_enabled: settings[:slack_enabled],
          slack_webhook: settings[:slack_webhook],
          webhook_enabled: settings[:webhook_enabled],
          webhook_url: settings[:webhook_url],
          push_tokens: settings[:push_tokens],
          critical_alerts: settings[:critical_alerts],
          high_alerts: settings[:high_alerts],
          medium_alerts: settings[:medium_alerts]
        ])
        Application.put_env(:tamandua_server, :notifications, updated)

      :system ->
        Application.put_env(:tamandua_server, :event_retention_days, settings[:event_retention_days])
        Application.put_env(:tamandua_server, :alert_retention_days, settings[:alert_retention_days])

      _ ->
        :ok
    end
  end
end
