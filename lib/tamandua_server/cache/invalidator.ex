defmodule TamanduaServer.Cache.Invalidator do
  @moduledoc """
  Centralized cache invalidation with tag-based and event-driven strategies.

  Handles cache invalidation across Redis, ETS, and distributed nodes via PubSub.
  Supports write-through invalidation, tag-based bulk invalidation, and
  cross-resource dependency tracking.

  ## Features

  - Write-through invalidation (automatic on create/update/delete)
  - Tag-based invalidation (invalidate all related caches)
  - Distributed invalidation via PubSub
  - Dependency tracking (invalidate dependent resources)
  - Pattern-based invalidation (wildcards)
  - Batch invalidation for performance

  ## Usage

      # Single resource invalidation
      Invalidator.invalidate_alert(alert_id)

      # Tag-based invalidation
      Invalidator.invalidate_by_tag(:alert, tenant_id)

      # Pattern invalidation
      Invalidator.invalidate_pattern("alert:\#{tenant_id}:*")

      # Batch invalidation
      Invalidator.invalidate_batch([
        {:alert, 1},
        {:agent, 2},
        {:detection_rule, 3}
      ])
  """

  use GenServer
  require Logger

  alias Phoenix.PubSub
  alias TamanduaServer.Cache.{RedisCache, ETSCache}

  @pubsub_topic "cache:invalidation"

  # Resource dependency map (when X is invalidated, also invalidate Y)
  @dependencies %{
    alert: [:dashboard, :statistics, :timeline],
    agent: [:dashboard, :agent_list, :statistics],
    detection_rule: [:detection_engine, :rule_list],
    threat_intel: [:iocs, :detection_engine],
    user: [:session, :permissions],
    organization: [:users, :agents, :settings]
  }

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Invalidates all caches for an alert.
  """
  def invalidate_alert(alert_id) do
    invalidate(:alert, alert_id)
  end

  @doc """
  Invalidates all caches for an agent.
  """
  def invalidate_agent(agent_id) do
    invalidate(:agent, agent_id)
  end

  @doc """
  Invalidates all caches for a detection rule.
  """
  def invalidate_detection_rule(rule_id) do
    invalidate(:detection_rule, rule_id)
  end

  @doc """
  Invalidates all caches for a user.
  """
  def invalidate_user(user_id) do
    invalidate(:user, user_id)
  end

  @doc """
  Generic invalidation for a resource type and ID.
  """
  def invalidate(resource_type, resource_id) do
    GenServer.cast(__MODULE__, {:invalidate, resource_type, resource_id})
  end

  @doc """
  Invalidates all caches with a specific tag.

  ## Examples

      # Invalidate all alert caches for a tenant
      Invalidator.invalidate_by_tag(:alert, tenant_id)

      # Invalidate all detection rules
      Invalidator.invalidate_by_tag(:detection_rule)
  """
  def invalidate_by_tag(tag, context \\ nil) do
    GenServer.cast(__MODULE__, {:invalidate_by_tag, tag, context})
  end

  @doc """
  Invalidates caches matching a pattern.

  ## Examples

      # Invalidate all alert caches for tenant 1
      Invalidator.invalidate_pattern("alert:tenant_1:*")

      # Invalidate all agent status caches
      Invalidator.invalidate_pattern("agent:*:status")
  """
  def invalidate_pattern(pattern) do
    GenServer.cast(__MODULE__, {:invalidate_pattern, pattern})
  end

  @doc """
  Batch invalidation for multiple resources.

  ## Examples

      Invalidator.invalidate_batch([
        {:alert, 1},
        {:alert, 2},
        {:agent, 3}
      ])
  """
  def invalidate_batch(items) when is_list(items) do
    GenServer.cast(__MODULE__, {:invalidate_batch, items})
  end

  @doc """
  Clears all caches (use with caution).
  """
  def clear_all do
    GenServer.call(__MODULE__, :clear_all)
  end

  @doc """
  Returns invalidation statistics.
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # GenServer Callbacks

  @impl true
  def init(_opts) do
    # Subscribe to PubSub for distributed invalidation
    PubSub.subscribe(TamanduaServer.PubSub, @pubsub_topic)

    state = %{
      invalidations: 0,
      last_invalidation: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_cast({:invalidate, resource_type, resource_id}, state) do
    perform_invalidation(resource_type, resource_id)

    # Broadcast to other nodes
    broadcast_invalidation({:invalidate, resource_type, resource_id})

    # Invalidate dependent resources
    invalidate_dependencies(resource_type, resource_id)

    new_state = %{
      state
      | invalidations: state.invalidations + 1,
        last_invalidation: DateTime.utc_now()
    }

    {:noreply, new_state}
  end

  def handle_cast({:invalidate_by_tag, tag, context}, state) do
    perform_tag_invalidation(tag, context)
    broadcast_invalidation({:invalidate_by_tag, tag, context})

    new_state = %{
      state
      | invalidations: state.invalidations + 1,
        last_invalidation: DateTime.utc_now()
    }

    {:noreply, new_state}
  end

  def handle_cast({:invalidate_pattern, pattern}, state) do
    perform_pattern_invalidation(pattern)
    broadcast_invalidation({:invalidate_pattern, pattern})

    new_state = %{
      state
      | invalidations: state.invalidations + 1,
        last_invalidation: DateTime.utc_now()
    }

    {:noreply, new_state}
  end

  def handle_cast({:invalidate_batch, items}, state) do
    Enum.each(items, fn {resource_type, resource_id} ->
      perform_invalidation(resource_type, resource_id)
    end)

    broadcast_invalidation({:invalidate_batch, items})

    new_state = %{
      state
      | invalidations: state.invalidations + length(items),
        last_invalidation: DateTime.utc_now()
    }

    {:noreply, new_state}
  end

  @impl true
  def handle_call(:clear_all, _from, state) do
    # Clear all ETS caches
    Enum.each(ETSCache.cache_types(), fn cache_type ->
      ETSCache.clear(cache_type)
    end)

    # Clear Redis (use with caution!)
    RedisCache.clear_namespace("tamandua")

    Logger.warning("[Invalidator] Cleared all caches")

    broadcast_invalidation(:clear_all)

    {:reply, :ok, state}
  end

  def handle_call(:stats, _from, state) do
    stats = %{
      total_invalidations: state.invalidations,
      last_invalidation: state.last_invalidation,
      ets_stats: ETSCache.stats_all(),
      redis_stats: RedisCache.stats()
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info({:invalidate, resource_type, resource_id}, state) do
    # Remote invalidation received via PubSub
    Logger.debug("[Invalidator] Remote invalidation: #{resource_type}:#{resource_id}")
    perform_invalidation(resource_type, resource_id)
    {:noreply, state}
  end

  def handle_info({:invalidate_by_tag, tag, context}, state) do
    Logger.debug("[Invalidator] Remote tag invalidation: #{tag}")
    perform_tag_invalidation(tag, context)
    {:noreply, state}
  end

  def handle_info({:invalidate_pattern, pattern}, state) do
    Logger.debug("[Invalidator] Remote pattern invalidation: #{pattern}")
    perform_pattern_invalidation(pattern)
    {:noreply, state}
  end

  def handle_info({:invalidate_batch, items}, state) do
    Logger.debug("[Invalidator] Remote batch invalidation: #{length(items)} items")

    Enum.each(items, fn {resource_type, resource_id} ->
      perform_invalidation(resource_type, resource_id)
    end)

    {:noreply, state}
  end

  def handle_info(:clear_all, state) do
    Logger.warning("[Invalidator] Remote clear all received")

    Enum.each(ETSCache.cache_types(), fn cache_type ->
      ETSCache.clear(cache_type)
    end)

    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private Functions

  defp perform_invalidation(resource_type, resource_id) do
    # Build cache keys
    keys = build_cache_keys(resource_type, resource_id)

    # Invalidate in Redis
    Enum.each(keys, fn {namespace, key} ->
      RedisCache.delete(namespace, key)
    end)

    # Invalidate in ETS if applicable
    case resource_type do
      :detection_rule ->
        ETSCache.delete(:yara_rules, resource_id)
        ETSCache.delete(:sigma_rules, resource_id)
        ETSCache.delete(:detection_config, resource_id)

      :threat_intel ->
        ETSCache.delete(:iocs, resource_id)
        ETSCache.delete(:threat_intel, resource_id)

      :ml_prediction ->
        ETSCache.delete(:ml_predictions, resource_id)

      _ ->
        :ok
    end

    Logger.debug("[Invalidator] Invalidated #{resource_type}:#{resource_id}")
  end

  defp perform_tag_invalidation(tag, context) do
    # Pattern-based invalidation for tags
    pattern =
      if context do
        "#{tag}:#{context}:*"
      else
        "#{tag}:*"
      end

    RedisCache.delete_pattern(pattern)

    # Clear related ETS caches
    case tag do
      :alert -> ETSCache.clear(:agent_metadata)
      :agent -> ETSCache.clear(:agent_metadata)
      :detection_rule -> ETSCache.clear(:yara_rules) && ETSCache.clear(:sigma_rules)
      :threat_intel -> ETSCache.clear(:iocs) && ETSCache.clear(:threat_intel)
      _ -> :ok
    end

    Logger.debug("[Invalidator] Tag invalidation: #{tag} (context: #{inspect(context)})")
  end

  defp perform_pattern_invalidation(pattern) do
    RedisCache.delete_pattern(pattern)
    Logger.debug("[Invalidator] Pattern invalidation: #{pattern}")
  end

  defp invalidate_dependencies(resource_type, resource_id) do
    case Map.get(@dependencies, resource_type) do
      nil ->
        :ok

      dependent_types ->
        Enum.each(dependent_types, fn dep_type ->
          perform_tag_invalidation(dep_type, resource_id)
        end)
    end
  end

  defp build_cache_keys(resource_type, resource_id) do
    [
      {"tamandua", "#{resource_type}:#{resource_id}"},
      {"tamandua", "#{resource_type}:#{resource_id}:details"},
      {"tamandua", "#{resource_type}:#{resource_id}:metadata"}
    ]
  end

  defp broadcast_invalidation(message) do
    PubSub.broadcast(TamanduaServer.PubSub, @pubsub_topic, message)
  end
end
