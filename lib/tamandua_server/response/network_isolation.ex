defmodule TamanduaServer.Response.NetworkIsolation do
  @moduledoc """
  Network isolation management for compromised endpoints.

  Supports three isolation levels:
  - :full - Block all network traffic except management channel
  - :partial - Block internet access, allow LAN
  - :process - Block specific process from network access

  The isolation command is sent to the agent via the existing Executor/Worker
  pipeline, which then:
  1. Configures the kernel driver's WFP filters (Windows)
  2. Applies iptables/nftables rules (Linux)
  3. Applies PF rules (macOS)

  Isolation state is tracked both in-memory (ETS for fast reads) and persisted
  to the agent record via `TamanduaServer.Agents.update_isolation_status/2`.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.Response.Executor

  @type isolation_level :: :full | :partial | :process
  @type isolation_state :: %__MODULE__{
          agent_id: String.t(),
          level: isolation_level,
          started_at: DateTime.t(),
          started_by: String.t(),
          allowed_ips: [String.t()],
          blocked_pids: [integer()],
          reason: String.t()
        }

  defstruct [
    :agent_id,
    :level,
    :started_at,
    :started_by,
    :reason,
    allowed_ips: [],
    blocked_pids: []
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Isolate an agent from the network.

  Options:
    - :user       - The user/system requesting isolation (default: "system")
    - :reason     - Reason string for audit trail (default: "Manual isolation")
    - :allowed_ips - Additional IPs to allow through the isolation
    - :dns_ip     - DNS server IP to permit (default: "0.0.0.0")
    - :blocked_pids - Initial list of PIDs to block (only for :process level)
    - :duration   - Duration in seconds before auto de-isolation (default: 86400 = 24h)
    - :exceptions - List of isolation exceptions (e.g., [%{type: "ip", value: "10.0.0.5"}])
  """
  @spec isolate(String.t(), isolation_level, keyword()) ::
          {:ok, isolation_state()} | {:error, term()}
  def isolate(agent_id, level \\ :full, opts \\ []) do
    GenServer.call(__MODULE__, {:isolate, agent_id, level, opts})
  end

  @doc "Remove network isolation from an agent."
  @spec deisolate(String.t(), keyword()) :: :ok | {:error, term()}
  def deisolate(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:deisolate, agent_id, opts})
  end

  @doc "Block a specific process from network access."
  @spec block_process(String.t(), integer()) :: :ok | {:error, term()}
  def block_process(agent_id, pid) do
    GenServer.call(__MODULE__, {:block_process, agent_id, pid})
  end

  @doc "Unblock a specific process."
  @spec unblock_process(String.t(), integer()) :: :ok | {:error, term()}
  def unblock_process(agent_id, pid) do
    GenServer.call(__MODULE__, {:unblock_process, agent_id, pid})
  end

  @doc "Get current isolation state for an agent."
  @spec get_state(String.t()) :: {:ok, isolation_state()} | {:error, :not_isolated}
  def get_state(agent_id) do
    GenServer.call(__MODULE__, {:get_state, agent_id})
  end

  @doc "List all currently isolated agents."
  @spec list_isolated() :: [isolation_state()]
  def list_isolated do
    GenServer.call(__MODULE__, :list_isolated)
  end

  @doc """
  Check for expired isolations and automatically de-isolate them.
  Called periodically by the Oban job.
  """
  @spec check_and_expire_isolations() :: {:ok, [String.t()]}
  def check_and_expire_isolations do
    GenServer.call(__MODULE__, :check_expired_isolations)
  end

  @doc """
  Add or update isolation exceptions for an agent.

  Exceptions are whitelisted connections that bypass isolation rules.
  Example: %{type: "ip", value: "10.0.0.5"} or %{type: "port", value: 443}
  """
  @spec set_isolation_exceptions(String.t(), [map()]) :: :ok | {:error, term()}
  def set_isolation_exceptions(agent_id, exceptions) when is_list(exceptions) do
    GenServer.call(__MODULE__, {:set_exceptions, agent_id, exceptions})
  end

  @doc "Get current isolation exceptions for an agent."
  @spec get_isolation_exceptions(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_isolation_exceptions(agent_id) do
    GenServer.call(__MODULE__, {:get_exceptions, agent_id})
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    state = %{
      # agent_id -> %__MODULE__{} isolation state
      isolated_agents: %{}
    }

    Logger.info("[NetworkIsolation] Started")
    {:ok, state}
  end

  @impl true
  def handle_call({:isolate, agent_id, level, opts}, _from, state) do
    case Registry.get(agent_id) do
      {:ok, _agent} ->
        # Step 1: Capture previous network state and exceptions
        with {:ok, agent_record} <- TamanduaServer.Agents.get_agent(agent_id),
             {:ok, previous_state} <- capture_network_state(agent_record),
             {:ok, exceptions} <- get_or_build_exceptions(agent_record, opts) do

          # Step 2: Calculate expiry time
          duration_seconds = Keyword.get(opts, :duration, 86400) # Default 24 hours
          expires_at = DateTime.add(DateTime.utc_now(), duration_seconds, :second)

          # Build allowed IP list: management server + DNS + user-provided
          management_ip =
            Application.get_env(:tamandua_server, :management_ip, "0.0.0.0")

          dns_ip = Keyword.get(opts, :dns_ip, "0.0.0.0")
          allowed_ips = [management_ip, dns_ip] ++ Keyword.get(opts, :allowed_ips, [])
          allowed_ips = Enum.uniq(allowed_ips)

          # Build isolation params for the agent command (include exceptions)
          isolation_params = %{
            level: to_string(level),
            allowed_ips: allowed_ips,
            blocked_pids: Keyword.get(opts, :blocked_pids, []),
            exceptions: exceptions
          }

          # Step 3: Send isolation command to agent
          case Executor.execute_action(agent_id, "isolate_network", isolation_params) do
            {:ok, response} ->
              isolation = %__MODULE__{
                agent_id: agent_id,
                level: level,
                started_at: DateTime.utc_now(),
                started_by: Keyword.get(opts, :user, "system"),
                reason: Keyword.get(opts, :reason, "Manual isolation"),
                allowed_ips: allowed_ips,
                blocked_pids: Keyword.get(opts, :blocked_pids, [])
              }

              new_state = put_in(state, [:isolated_agents, agent_id], isolation)

              # Update agent registry status
              Registry.set_isolated(agent_id, true)

              # Step 4: Persist isolation state with expiry and rollback info
              TamanduaServer.Agents.update_agent(agent_record, %{
                isolation_status: %{
                  "state" => to_string(level),
                  "allowed_ips" => allowed_ips,
                  "started_at" => DateTime.to_iso8601(isolation.started_at),
                  "started_by" => isolation.started_by,
                  "reason" => isolation.reason,
                  "expires_at" => DateTime.to_iso8601(expires_at)
                },
                isolation_expires_at: expires_at,
                previous_network_state: previous_state,
                isolation_exceptions: exceptions
              })

              Logger.warning(
                "Network isolation ENABLED for agent #{agent_id} " <>
                  "(level=#{level}, by=#{isolation.started_by}, expires=#{DateTime.to_iso8601(expires_at)})"
              )

              # Create audit alert
              create_isolation_alert(
                agent_id,
                "high",
                "Network Isolation Enabled",
                "Agent #{agent_id} isolated at level '#{level}'. " <>
                  "Reason: #{isolation.reason}. Expires: #{DateTime.to_iso8601(expires_at)}. Response: #{inspect(response)}"
              )

              {:reply, {:ok, isolation}, new_state}

            {:error, reason} ->
              # Step 5: Rollback on failure - restore previous state
              Logger.error(
                "Failed to send isolation command to agent #{agent_id}: #{inspect(reason)}. Attempting rollback..."
              )

              # Send de-isolation command with previous state
              rollback_isolation(agent_id, previous_state)

              {:reply, {:error, {:send_failed, reason}}, state}
          end
        else
          {:error, reason} ->
            Logger.error("Failed to prepare isolation for agent #{agent_id}: #{inspect(reason)}")
            {:reply, {:error, reason}, state}
        end

      {:error, :not_found} ->
        {:reply, {:error, :agent_not_found}, state}
    end
  end

  @impl true
  def handle_call({:deisolate, agent_id, opts}, _from, state) do
    case Map.get(state.isolated_agents, agent_id) do
      nil ->
        {:reply, {:error, :not_isolated}, state}

      _isolation ->
        case Executor.execute_action(agent_id, "unisolate_network", %{}) do
          {:ok, _response} ->
            new_state =
              update_in(state, [:isolated_agents], &Map.delete(&1, agent_id))

            # Update agent registry status
            Registry.set_isolated(agent_id, false)

            # Clear persistent isolation status and expiry fields
            case TamanduaServer.Agents.get_agent(agent_id) do
              {:ok, agent} ->
                TamanduaServer.Agents.update_agent(agent, %{
                  isolation_status: nil,
                  status: "online",
                  isolation_expires_at: nil,
                  previous_network_state: nil
                })
              _ -> :ok
            end

            user = Keyword.get(opts, :user, "system")

            Logger.warning(
              "Network isolation DISABLED for agent #{agent_id} (by=#{user})"
            )

            create_isolation_alert(
              agent_id,
              "medium",
              "Network Isolation Removed",
              "Agent #{agent_id} network isolation removed by #{user}"
            )

            {:reply, :ok, new_state}

          {:error, reason} ->
            {:reply, {:error, {:send_failed, reason}}, state}
        end
    end
  end

  @impl true
  def handle_call({:block_process, agent_id, pid}, _from, state) do
    case Executor.execute_action(agent_id, "block_pid_network", %{pid: pid}) do
      {:ok, _response} ->
        new_state =
          update_in(
            state,
            [:isolated_agents, agent_id],
            fn
              nil ->
                %__MODULE__{
                  agent_id: agent_id,
                  level: :process,
                  started_at: DateTime.utc_now(),
                  started_by: "system",
                  reason: "Process-level block",
                  blocked_pids: [pid]
                }

              iso ->
                %{iso | blocked_pids: Enum.uniq([pid | iso.blocked_pids])}
            end
          )

        Logger.info("Blocked process #{pid} network access on agent #{agent_id}")
        {:reply, :ok, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:unblock_process, agent_id, pid}, _from, state) do
    case Executor.execute_action(agent_id, "unblock_pid_network", %{pid: pid}) do
      {:ok, _response} ->
        new_state =
          update_in(
            state,
            [:isolated_agents, agent_id],
            fn
              nil ->
                nil

              iso ->
                updated = %{iso | blocked_pids: List.delete(iso.blocked_pids, pid)}

                # If no more blocked PIDs and level is :process, clean up
                if updated.level == :process and updated.blocked_pids == [] do
                  nil
                else
                  updated
                end
            end
          )

        # Remove nil entries from the map
        new_state =
          update_in(new_state, [:isolated_agents], fn agents ->
            agents
            |> Enum.reject(fn {_k, v} -> is_nil(v) end)
            |> Map.new()
          end)

        Logger.info("Unblocked process #{pid} network access on agent #{agent_id}")
        {:reply, :ok, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_state, agent_id}, _from, state) do
    case Map.get(state.isolated_agents, agent_id) do
      nil -> {:reply, {:error, :not_isolated}, state}
      iso -> {:reply, {:ok, iso}, state}
    end
  end

  @impl true
  def handle_call(:list_isolated, _from, state) do
    {:reply, Map.values(state.isolated_agents), state}
  end

  @impl true
  def handle_call(:check_expired_isolations, _from, state) do
    now = DateTime.utc_now()

    # Query database for expired isolations
    expired_agents =
      try do
        import Ecto.Query

        TamanduaServer.Repo.all(
          from a in TamanduaServer.Agents.Agent,
          where: not is_nil(a.isolation_expires_at),
          where: a.isolation_expires_at <= ^now,
          select: %{id: a.id, hostname: a.hostname, expires_at: a.isolation_expires_at}
        )
      rescue
        e ->
          Logger.error("Failed to query expired isolations: #{Exception.message(e)}")
          []
      end

    # De-isolate each expired agent
    de_isolated =
      Enum.reduce(expired_agents, [], fn agent, acc ->
        Logger.info("Auto de-isolating agent #{agent.id} (expired at #{DateTime.to_iso8601(agent.expires_at)})")

        case deisolate_internal(agent.id, state, user: "system (auto-expiry)") do
          {:ok, _new_state} ->
            # Create alert for auto de-isolation
            create_isolation_alert(
              agent.id,
              "medium",
              "Network Isolation Auto-Expired",
              "Agent #{agent.hostname} (#{agent.id}) automatically de-isolated after expiry time (#{DateTime.to_iso8601(agent.expires_at)})"
            )
            [agent.id | acc]
          {:error, reason} ->
            Logger.error("Failed to auto de-isolate agent #{agent.id}: #{inspect(reason)}")
            acc
        end
      end)

    {:reply, {:ok, de_isolated}, state}
  end

  @impl true
  def handle_call({:set_exceptions, agent_id, exceptions}, _from, state) do
    case TamanduaServer.Agents.get_agent(agent_id) do
      {:ok, agent} ->
        case TamanduaServer.Agents.update_agent(agent, %{isolation_exceptions: exceptions}) do
          {:ok, _updated} ->
            Logger.info("Updated isolation exceptions for agent #{agent_id}: #{inspect(exceptions)}")

            # If agent is currently isolated, re-apply isolation with new exceptions
            if Map.has_key?(state.isolated_agents, agent_id) do
              iso = state.isolated_agents[agent_id]

              # Send update command to agent
              isolation_params = %{
                level: to_string(iso.level),
                allowed_ips: iso.allowed_ips,
                blocked_pids: iso.blocked_pids,
                exceptions: exceptions
              }

              case Executor.execute_action(agent_id, "isolate_network", isolation_params) do
                {:ok, _} ->
                  Logger.info("Re-applied isolation with updated exceptions for agent #{agent_id}")
                  {:reply, :ok, state}
                {:error, reason} ->
                  Logger.error("Failed to re-apply isolation with exceptions: #{inspect(reason)}")
                  {:reply, {:error, reason}, state}
              end
            else
              {:reply, :ok, state}
            end

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_exceptions, agent_id}, _from, state) do
    case TamanduaServer.Agents.get_agent(agent_id) do
      {:ok, agent} ->
        exceptions = agent.isolation_exceptions || []
        {:reply, {:ok, exceptions}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  # Private helpers

  defp create_isolation_alert(agent_id, severity, title, description) do
    try do
      TamanduaServer.Alerts.create_alert(%{
        agent_id: agent_id,
        severity: severity,
        title: title,
        description: description,
        category: "response_action",
        detection_type: "network_isolation"
      })
    rescue
      e ->
        Logger.error("Failed to create isolation alert: #{Exception.message(e)}")
    end
  end

  # Capture the current network state before applying isolation
  # This allows rollback on failure
  defp capture_network_state(agent) do
    # Store the current isolation status if any
    previous_state = %{
      isolation_status: agent.isolation_status,
      status: agent.status,
      captured_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:ok, previous_state}
  end

  # Get or build isolation exceptions list
  defp get_or_build_exceptions(agent, opts) do
    # Use exceptions from opts if provided, otherwise use stored exceptions
    exceptions = case Keyword.get(opts, :exceptions) do
      nil -> agent.isolation_exceptions || []
      provided -> provided
    end

    {:ok, exceptions}
  end

  # Rollback isolation on failure - restore previous network state
  defp rollback_isolation(agent_id, previous_state) do
    Logger.warning("Rolling back isolation for agent #{agent_id}")

    # Send de-isolation command
    case Executor.execute_action(agent_id, "unisolate_network", %{}) do
      {:ok, _} ->
        Logger.info("Rollback successful for agent #{agent_id}")

        # Restore previous state in database
        case TamanduaServer.Agents.get_agent(agent_id) do
          {:ok, agent} ->
            TamanduaServer.Agents.update_agent(agent, %{
              isolation_status: previous_state.isolation_status,
              status: previous_state.status,
              isolation_expires_at: nil,
              previous_network_state: nil
            })
          _ -> :ok
        end

      {:error, reason} ->
        Logger.error("Rollback failed for agent #{agent_id}: #{inspect(reason)}")
    end
  end

  # Internal de-isolation that doesn't use GenServer call (used by expiry check)
  defp deisolate_internal(agent_id, state, opts) do
    case Executor.execute_action(agent_id, "unisolate_network", %{}) do
      {:ok, _response} ->
        # Update agent registry status
        Registry.set_isolated(agent_id, false)

        # Clear persistent isolation status and expiry fields
        case TamanduaServer.Agents.get_agent(agent_id) do
          {:ok, agent} ->
            TamanduaServer.Agents.update_agent(agent, %{
              isolation_status: nil,
              status: "online",
              isolation_expires_at: nil,
              previous_network_state: nil
            })
          _ -> :ok
        end

        user = Keyword.get(opts, :user, "system")

        Logger.warning(
          "Network isolation DISABLED for agent #{agent_id} (by=#{user})"
        )

        {:ok, state}

      {:error, reason} ->
        {:error, {:send_failed, reason}}
    end
  end
end
