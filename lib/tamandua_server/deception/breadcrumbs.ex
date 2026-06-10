defmodule TamanduaServer.Deception.Breadcrumbs do
  @moduledoc """
  Breadcrumb Distribution System - Automated Decoy Deployment

  Manages the distribution of deception artifacts (breadcrumbs) across endpoints:
  - Automatic deployment of decoys based on endpoint profile
  - Tracking of decoy placement across the environment
  - Periodic rotation of decoys to prevent attacker adaptation
  - Smart placement based on attack patterns

  Comparable to Attivo/SentinelOne Singularity Hologram or Illusive Networks.
  """

  use GenServer
  require Logger
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.CommandManager
  alias TamanduaServer.Deception.{BreadcrumbGenerator, BreadcrumbDeployment, BreadcrumbAccessLog}
  alias TamanduaServer.Repo

  import Ecto.Query

  # ============================================================================
  # Types
  # ============================================================================

  @type decoy_type ::
          :credential
          | :document
          | :ssh_key
          | :api_token
          | :cloud_credential
          | :browser_password
          | :kube_config
          | :env_file
          | :database
          | :network_share

  @type breadcrumb :: %{
          id: String.t(),
          type: decoy_type(),
          agent_id: String.t(),
          path: String.t(),
          content_hash: String.t(),
          canary_token: String.t(),
          deployed_at: DateTime.t(),
          last_rotated_at: DateTime.t() | nil,
          status: :active | :accessed | :rotated | :removed,
          access_count: non_neg_integer(),
          metadata: map()
        }

  @type deployment_profile :: %{
          id: String.t(),
          name: String.t(),
          description: String.t(),
          decoy_types: [decoy_type()],
          target_paths: [String.t()],
          os_types: [:windows | :linux | :macos],
          density: :low | :medium | :high,
          rotation_interval_hours: non_neg_integer(),
          enabled: boolean()
        }

  # ============================================================================
  # State
  # ============================================================================

  defstruct breadcrumbs: %{},
            profiles: %{},
            deployment_queue: [],
            rotation_schedule: %{},
            stats: %{
              total_deployed: 0,
              total_accessed: 0,
              total_rotated: 0,
              deployments_by_type: %{},
              access_by_agent: %{}
            }

  # ============================================================================
  # GenServer API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get all deployed breadcrumbs.
  """
  def list_breadcrumbs(opts \\ []) do
    GenServer.call(__MODULE__, {:list_breadcrumbs, opts})
  end

  @doc """
  Get breadcrumbs for a specific agent.
  """
  def get_agent_breadcrumbs(agent_id) do
    GenServer.call(__MODULE__, {:get_agent_breadcrumbs, agent_id})
  end

  @doc """
  Deploy breadcrumbs to an agent.
  """
  def deploy_to_agent(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:deploy_to_agent, agent_id, opts})
  end

  @doc """
  Deploy breadcrumbs to all agents matching a profile.
  """
  def deploy_by_profile(profile_id) do
    GenServer.call(__MODULE__, {:deploy_by_profile, profile_id})
  end

  @doc """
  Record a breadcrumb access event.
  """
  def record_access(agent_id, canary_token, access_info) do
    GenServer.cast(__MODULE__, {:record_access, agent_id, canary_token, access_info})
  end

  @doc """
  Rotate breadcrumbs for an agent.
  """
  def rotate_agent_breadcrumbs(agent_id) do
    GenServer.call(__MODULE__, {:rotate_breadcrumbs, agent_id})
  end

  @doc """
  Create or update a deployment profile.
  """
  def upsert_profile(profile) do
    GenServer.call(__MODULE__, {:upsert_profile, profile})
  end

  @doc """
  List deployment profiles.
  """
  def list_profiles do
    GenServer.call(__MODULE__, :list_profiles)
  end

  @doc """
  Get deployment statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get deployment recommendations for an agent.
  """
  def get_recommendations(agent_id) do
    GenServer.call(__MODULE__, {:get_recommendations, agent_id})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Breadcrumb Distribution System")

    # Schedule periodic rotation check
    schedule_rotation_check()

    # Initialize with default profiles
    state = %__MODULE__{
      profiles: default_profiles()
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:list_breadcrumbs, opts}, _from, state) do
    breadcrumbs =
      state.breadcrumbs
      |> Map.values()
      |> filter_breadcrumbs(opts)
      |> Enum.sort_by(& &1.deployed_at, {:desc, DateTime})

    {:reply, {:ok, breadcrumbs}, state}
  end

  @impl true
  def handle_call({:get_agent_breadcrumbs, agent_id}, _from, state) do
    breadcrumbs =
      state.breadcrumbs
      |> Map.values()
      |> Enum.filter(&(&1.agent_id == agent_id))
      |> Enum.sort_by(& &1.deployed_at, {:desc, DateTime})

    {:reply, {:ok, breadcrumbs}, state}
  end

  @impl true
  def handle_call({:deploy_to_agent, agent_id, opts}, _from, state) do
    case Agents.get_agent(agent_id) do
      {:ok, agent} ->
        {breadcrumbs, new_state} = generate_breadcrumbs_for_agent(agent, opts, state)

        # Send deployment command to agent
        case deploy_breadcrumbs_to_agent(agent_id, breadcrumbs) do
          :ok ->
            {:reply, {:ok, length(breadcrumbs)}, new_state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      {:error, :not_found} ->
        {:reply, {:error, :agent_not_found}, state}
    end
  end

  @impl true
  def handle_call({:deploy_by_profile, profile_id}, _from, state) do
    case Map.get(state.profiles, profile_id) do
      nil ->
        {:reply, {:error, :profile_not_found}, state}

      profile ->
        agents =
          Agents.list_all()
          |> Enum.filter(fn agent ->
            os_type = String.to_existing_atom(agent.os_type)
            os_type in profile.os_types
          end)

        {total_deployed, new_state} =
          Enum.reduce(agents, {0, state}, fn agent, {count, acc_state} ->
            {breadcrumbs, updated_state} =
              generate_breadcrumbs_for_agent(
                agent,
                [types: profile.decoy_types, density: profile.density],
                acc_state
              )

            case deploy_breadcrumbs_to_agent(agent.id, breadcrumbs) do
              :ok -> {count + length(breadcrumbs), updated_state}
              _ -> {count, acc_state}
            end
          end)

        {:reply, {:ok, %{agents: length(agents), breadcrumbs: total_deployed}}, new_state}
    end
  end

  @impl true
  def handle_call({:rotate_breadcrumbs, agent_id}, _from, state) do
    agent_breadcrumbs =
      state.breadcrumbs
      |> Map.values()
      |> Enum.filter(&(&1.agent_id == agent_id && &1.status == :active))

    {rotated_count, new_state} =
      Enum.reduce(agent_breadcrumbs, {0, state}, fn bc, {count, acc_state} ->
        new_bc = generate_replacement_breadcrumb(bc)

        updated_breadcrumbs =
          acc_state.breadcrumbs
          |> Map.put(bc.id, %{bc | status: :rotated, last_rotated_at: DateTime.utc_now()})
          |> Map.put(new_bc.id, new_bc)

        {count + 1, %{acc_state | breadcrumbs: updated_breadcrumbs}}
      end)

    # Send rotation command to agent
    case Agents.get_agent(agent_id) do
      {:ok, _agent} ->
        deploy_rotation_to_agent(agent_id, agent_breadcrumbs)
        {:reply, {:ok, rotated_count}, update_stats(new_state, :rotated, rotated_count)}

      _ ->
        {:reply, {:ok, rotated_count}, new_state}
    end
  end

  @impl true
  def handle_call({:upsert_profile, profile}, _from, state) do
    profile_id = profile[:id] || generate_id()
    profile = Map.put(profile, :id, profile_id)

    new_profiles = Map.put(state.profiles, profile_id, profile)
    {:reply, {:ok, profile}, %{state | profiles: new_profiles}}
  end

  @impl true
  def handle_call(:list_profiles, _from, state) do
    profiles = Map.values(state.profiles)
    {:reply, {:ok, profiles}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats =
      state.stats
      |> Map.put(:active_breadcrumbs, count_by_status(state.breadcrumbs, :active))
      |> Map.put(:accessed_breadcrumbs, count_by_status(state.breadcrumbs, :accessed))
      |> Map.put(:total_breadcrumbs, map_size(state.breadcrumbs))
      |> Map.put(:agents_with_breadcrumbs, count_unique_agents(state.breadcrumbs))

    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call({:get_recommendations, agent_id}, _from, state) do
    recommendations = generate_recommendations(agent_id, state)
    {:reply, {:ok, recommendations}, state}
  end

  @impl true
  def handle_cast({:record_access, agent_id, canary_token, access_info}, state) do
    new_state =
      case find_breadcrumb_by_token(state.breadcrumbs, canary_token) do
        nil ->
          Logger.warning("Unknown canary token accessed: #{canary_token}")
          state

        breadcrumb ->
          Logger.warning(
            "DECEPTION TRIGGERED: Breadcrumb #{breadcrumb.id} accessed on agent #{agent_id}"
          )

          # Forward to BreadcrumbMonitor for alerting and response
          spawn(fn ->
            TamanduaServer.Deception.BreadcrumbMonitor.handle_breadcrumb_access(%{
              canary_token: canary_token,
              agent_id: agent_id,
              process_name: access_info[:process_name],
              pid: access_info[:pid],
              user: access_info[:user],
              access_type: access_info[:access_type] || "read",
              timestamp: DateTime.utc_now(),
              file_hash: access_info[:file_hash]
            })
          end)

          updated_bc = %{
            breadcrumb
            | status: :accessed,
              access_count: breadcrumb.access_count + 1,
              metadata: Map.merge(breadcrumb.metadata, %{last_access: access_info})
          }

          updated_breadcrumbs = Map.put(state.breadcrumbs, breadcrumb.id, updated_bc)

          %{state | breadcrumbs: updated_breadcrumbs}
          |> update_stats(:accessed, 1)
          |> update_access_by_agent(agent_id)
      end

    {:noreply, new_state}
  end

  @impl true
  def handle_info(:rotation_check, state) do
    Logger.debug("Running breadcrumb rotation check")

    # Find breadcrumbs due for rotation
    now = DateTime.utc_now()

    breadcrumbs_to_rotate =
      state.breadcrumbs
      |> Map.values()
      |> Enum.filter(fn bc ->
        bc.status == :active && should_rotate?(bc, now, state.profiles)
      end)
      |> Enum.group_by(& &1.agent_id)

    # Rotate breadcrumbs for each agent
    new_state =
      Enum.reduce(breadcrumbs_to_rotate, state, fn {agent_id, bcs}, acc_state ->
        Enum.reduce(bcs, acc_state, fn bc, inner_state ->
          new_bc = generate_replacement_breadcrumb(bc)

          updated_breadcrumbs =
            inner_state.breadcrumbs
            |> Map.put(bc.id, %{bc | status: :rotated, last_rotated_at: now})
            |> Map.put(new_bc.id, new_bc)

          %{inner_state | breadcrumbs: updated_breadcrumbs}
        end)
      end)

    # Schedule next check
    schedule_rotation_check()

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp default_profiles do
    %{
      "default-windows" => %{
        id: "default-windows",
        name: "Windows Default",
        description: "Default breadcrumb profile for Windows endpoints",
        decoy_types: [
          :credential,
          :document,
          :browser_password,
          :cloud_credential,
          :kube_config
        ],
        target_paths: [
          "Documents",
          "Desktop",
          ".aws",
          ".ssh",
          "AppData\\Roaming"
        ],
        os_types: [:windows],
        density: :medium,
        rotation_interval_hours: 168,
        enabled: true
      },
      "default-linux" => %{
        id: "default-linux",
        name: "Linux Default",
        description: "Default breadcrumb profile for Linux endpoints",
        decoy_types: [
          :ssh_key,
          :env_file,
          :api_token,
          :cloud_credential,
          :kube_config
        ],
        target_paths: [
          ".ssh",
          ".aws",
          ".kube",
          ".config",
          "Documents"
        ],
        os_types: [:linux],
        density: :medium,
        rotation_interval_hours: 168,
        enabled: true
      },
      "high-value-servers" => %{
        id: "high-value-servers",
        name: "High-Value Servers",
        description: "Dense breadcrumb deployment for critical servers",
        decoy_types: [
          :ssh_key,
          :api_token,
          :cloud_credential,
          :database,
          :kube_config,
          :env_file
        ],
        target_paths: [
          "/root",
          "/home",
          "/etc",
          "/var/www",
          "/opt"
        ],
        os_types: [:linux],
        density: :high,
        rotation_interval_hours: 72,
        enabled: true
      },
      "developer-workstations" => %{
        id: "developer-workstations",
        name: "Developer Workstations",
        description: "Breadcrumbs targeting developer credentials and code",
        decoy_types: [
          :ssh_key,
          :api_token,
          :env_file,
          :cloud_credential,
          :browser_password
        ],
        target_paths: [
          ".ssh",
          ".aws",
          ".npm",
          ".docker",
          "projects",
          "code",
          "repositories"
        ],
        os_types: [:windows, :linux, :macos],
        density: :medium,
        rotation_interval_hours: 168,
        enabled: true
      }
    }
  end

  defp generate_breadcrumbs_for_agent(agent, opts, state) do
    types = Keyword.get(opts, :types, default_types_for_os(agent.os_type))
    density = Keyword.get(opts, :density, :medium)

    count = density_to_count(density)

    # Generate breadcrumbs with actual content
    breadcrumbs =
      types
      |> Enum.take(count)
      |> Enum.map(fn type ->
        create_breadcrumb_with_content(agent.id, agent.os_type, type)
      end)

    # Persist to database
    persist_breadcrumbs_to_db(breadcrumbs)

    new_breadcrumbs =
      Enum.reduce(breadcrumbs, state.breadcrumbs, fn bc, acc ->
        Map.put(acc, bc.id, bc)
      end)

    new_state =
      %{state | breadcrumbs: new_breadcrumbs}
      |> update_stats(:deployed, length(breadcrumbs))
      |> update_deployments_by_type(breadcrumbs)

    {breadcrumbs, new_state}
  end

  defp create_breadcrumb(agent_id, type) do
    id = generate_id()
    canary_token = "TAMANDUA-#{generate_id()}"

    %{
      id: id,
      type: type,
      agent_id: agent_id,
      path: generate_path_for_type(type),
      content_hash: generate_content_hash(),
      canary_token: canary_token,
      deployed_at: DateTime.utc_now(),
      last_rotated_at: nil,
      status: :active,
      access_count: 0,
      metadata: %{
        version: 1,
        generator: "tamandua-breadcrumbs"
      }
    }
  end

  defp generate_replacement_breadcrumb(old_bc) do
    %{
      create_breadcrumb(old_bc.agent_id, old_bc.type)
      | metadata: Map.put(old_bc.metadata, :replaces, old_bc.id)
    }
  end

  defp generate_path_for_type(type) do
    base_paths = %{
      credential: [".config/credentials", "Documents/passwords"],
      document: ["Documents", "Desktop"],
      ssh_key: [".ssh"],
      api_token: [".config", ".local/share"],
      cloud_credential: [".aws", ".azure", ".config/gcloud"],
      browser_password: ["AppData/Local/Google/Chrome/User Data"],
      kube_config: [".kube"],
      env_file: ["projects", "code"],
      database: ["backups", "data"],
      network_share: ["Network"]
    }

    paths = Map.get(base_paths, type, ["Documents"])
    Enum.random(paths)
  end

  defp generate_content_hash do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp default_types_for_os(os_type) do
    case os_type do
      "windows" ->
        [:credential, :document, :browser_password, :cloud_credential]

      "linux" ->
        [:ssh_key, :env_file, :api_token, :cloud_credential, :kube_config]

      "macos" ->
        [:ssh_key, :document, :cloud_credential, :browser_password]

      _ ->
        [:credential, :document]
    end
  end

  defp density_to_count(:low), do: 3
  defp density_to_count(:medium), do: 6
  defp density_to_count(:high), do: 12

  defp deploy_breadcrumbs_to_agent(agent_id, breadcrumbs) do
    # Convert to deployment command format
    deployment_cmd = %{
      action: "deploy_breadcrumbs",
      breadcrumbs:
        Enum.map(breadcrumbs, fn bc ->
          %{
            type: bc.type,
            path: bc.path,
            canary_token: bc.canary_token
          }
        end)
    }

    # Send to agent via WebSocket channel
    case Agents.Registry.get(agent_id) do
      {:ok, %{pid: pid}} ->
        send(pid, {:command, deployment_cmd})
        :ok

      _ ->
        # Queue for later deployment when agent connects
        Logger.debug("Agent #{agent_id} not connected, queueing breadcrumb deployment")
        :ok
    end
  end

  defp deploy_rotation_to_agent(agent_id, old_breadcrumbs) do
    rotation_cmd = %{
      action: "rotate_breadcrumbs",
      remove_tokens: Enum.map(old_breadcrumbs, & &1.canary_token)
    }

    case Agents.Registry.get(agent_id) do
      {:ok, %{pid: pid}} ->
        send(pid, {:command, rotation_cmd})

      _ ->
        Logger.debug("Agent #{agent_id} not connected, rotation queued")
    end
  end

  defp filter_breadcrumbs(breadcrumbs, opts) do
    breadcrumbs
    |> filter_by_status(Keyword.get(opts, :status))
    |> filter_by_type(Keyword.get(opts, :type))
    |> filter_by_agent(Keyword.get(opts, :agent_id))
  end

  defp filter_by_status(bcs, nil), do: bcs
  defp filter_by_status(bcs, status), do: Enum.filter(bcs, &(&1.status == status))

  defp filter_by_type(bcs, nil), do: bcs
  defp filter_by_type(bcs, type), do: Enum.filter(bcs, &(&1.type == type))

  defp filter_by_agent(bcs, nil), do: bcs
  defp filter_by_agent(bcs, agent_id), do: Enum.filter(bcs, &(&1.agent_id == agent_id))

  defp find_breadcrumb_by_token(breadcrumbs, token) do
    breadcrumbs
    |> Map.values()
    |> Enum.find(&(&1.canary_token == token))
  end

  defp should_rotate?(breadcrumb, now, profiles) do
    # Get rotation interval from profile or use default (7 days)
    rotation_hours = get_rotation_interval(breadcrumb, profiles)
    rotation_threshold = DateTime.add(breadcrumb.deployed_at, rotation_hours * 3600, :second)

    DateTime.compare(now, rotation_threshold) == :gt
  end

  defp get_rotation_interval(_breadcrumb, _profiles) do
    # Default: 7 days
    168
  end

  defp generate_recommendations(agent_id, state) do
    current_breadcrumbs =
      state.breadcrumbs
      |> Map.values()
      |> Enum.filter(&(&1.agent_id == agent_id && &1.status == :active))

    current_types = Enum.map(current_breadcrumbs, & &1.type) |> MapSet.new()

    # Get agent info
    recommendations =
      case Agents.get_agent(agent_id) do
        {:ok, agent} ->
          all_types = default_types_for_os(agent.os_type) |> MapSet.new()
          missing_types = MapSet.difference(all_types, current_types)

          missing_recs =
            missing_types
            |> Enum.map(fn type ->
              %{
                type: :add_decoy,
                decoy_type: type,
                priority: priority_for_type(type),
                reason: "Missing #{type} decoy on this #{agent.os_type} endpoint"
              }
            end)

          # Check for stale breadcrumbs
          stale_recs =
            current_breadcrumbs
            |> Enum.filter(fn bc ->
              age_days = DateTime.diff(DateTime.utc_now(), bc.deployed_at, :day)
              age_days > 30
            end)
            |> Enum.map(fn bc ->
              %{
                type: :rotate,
                breadcrumb_id: bc.id,
                priority: :medium,
                reason: "Breadcrumb deployed over 30 days ago"
              }
            end)

          missing_recs ++ stale_recs

        _ ->
          []
      end

    recommendations
    |> Enum.sort_by(& &1.priority, :desc)
  end

  defp priority_for_type(type) do
    case type do
      :ssh_key -> :critical
      :cloud_credential -> :critical
      :api_token -> :high
      :kube_config -> :high
      :credential -> :high
      :env_file -> :medium
      :browser_password -> :medium
      _ -> :low
    end
  end

  defp count_by_status(breadcrumbs, status) do
    breadcrumbs
    |> Map.values()
    |> Enum.count(&(&1.status == status))
  end

  defp count_unique_agents(breadcrumbs) do
    breadcrumbs
    |> Map.values()
    |> Enum.map(& &1.agent_id)
    |> Enum.uniq()
    |> length()
  end

  defp update_stats(state, :deployed, count) do
    %{state | stats: Map.update!(state.stats, :total_deployed, &(&1 + count))}
  end

  defp update_stats(state, :accessed, count) do
    %{state | stats: Map.update!(state.stats, :total_accessed, &(&1 + count))}
  end

  defp update_stats(state, :rotated, count) do
    %{state | stats: Map.update!(state.stats, :total_rotated, &(&1 + count))}
  end

  defp update_deployments_by_type(state, breadcrumbs) do
    new_counts =
      Enum.reduce(breadcrumbs, state.stats.deployments_by_type, fn bc, acc ->
        Map.update(acc, bc.type, 1, &(&1 + 1))
      end)

    %{state | stats: Map.put(state.stats, :deployments_by_type, new_counts)}
  end

  defp update_access_by_agent(state, agent_id) do
    new_counts = Map.update(state.stats.access_by_agent, agent_id, 1, &(&1 + 1))
    %{state | stats: Map.put(state.stats, :access_by_agent, new_counts)}
  end

  defp generate_id do
    Ecto.UUID.generate()
  end

  defp schedule_rotation_check do
    # Check every hour
    Process.send_after(self(), :rotation_check, :timer.hours(1))
  end

  # ============================================================================
  # New Deployment Implementation
  # ============================================================================

  defp create_breadcrumb_with_content(agent_id, os_type, type) do
    # Generate content using BreadcrumbGenerator
    generated = BreadcrumbGenerator.generate(type, os_type)

    id = generate_id()
    canary_token = "TAMANDUA-#{generate_id()}"

    # Select deployment path from suggestions
    base_path = Enum.random(generated.path_suggestions)
    filename = if generated.extension != "" do
      "#{generated.filename}.#{generated.extension}"
    else
      generated.filename
    end

    full_path = Path.join(base_path, filename)

    # Calculate content hash
    content_hash = :crypto.hash(:sha256, generated.content) |> Base.encode16(case: :lower)

    %{
      id: id,
      type: type,
      agent_id: agent_id,
      path: full_path,
      content: generated.content,
      content_hash: content_hash,
      canary_token: canary_token,
      deployed_at: DateTime.utc_now(),
      last_rotated_at: nil,
      status: :active,
      access_count: 0,
      metadata: %{
        version: 1,
        generator: "tamandua-breadcrumbs",
        filename: filename,
        base_path: base_path
      }
    }
  end

  defp persist_breadcrumbs_to_db(breadcrumbs) do
    # Persist breadcrumbs to database in background
    Task.start(fn ->
      Enum.each(breadcrumbs, fn bc ->
        attrs = %{
          id: bc.id,
          agent_id: bc.agent_id,
          type: to_string(bc.type),
          path: bc.path,
          content_hash: bc.content_hash,
          canary_token: bc.canary_token,
          deployed_at: bc.deployed_at,
          status: to_string(bc.status),
          access_count: bc.access_count,
          metadata: bc.metadata
        }

        case Repo.insert(BreadcrumbDeployment.changeset(%BreadcrumbDeployment{}, attrs)) do
          {:ok, _deployment} ->
            Logger.debug("Persisted breadcrumb #{bc.id} to database")

          {:error, changeset} ->
            Logger.error("Failed to persist breadcrumb #{bc.id}: #{inspect(changeset.errors)}")
        end
      end)
    end)
  end

  defp deploy_breadcrumbs_to_agent(agent_id, breadcrumbs) do
    # Get agent info to determine OS-specific details
    case Agents.get_agent(agent_id) do
      {:ok, agent} ->
        # Build deployment commands with full file content
        deploy_commands = build_deploy_commands(breadcrumbs, agent.os_type)

        # Queue command via CommandManager
        case CommandManager.queue_command(
          agent_id,
          :deploy_breadcrumbs,
          %{deployments: deploy_commands},
          priority: 3
        ) do
          {:ok, _command} ->
            Logger.info("Queued breadcrumb deployment for agent #{agent_id}: #{length(breadcrumbs)} files")
            :ok

          {:error, reason} ->
            Logger.error("Failed to queue breadcrumb deployment: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, :not_found} ->
        Logger.warning("Agent #{agent_id} not found, cannot deploy breadcrumbs")
        {:error, :agent_not_found}
    end
  end

  defp build_deploy_commands(breadcrumbs, os_type) do
    Enum.map(breadcrumbs, fn bc ->
      %{
        type: to_string(bc.type),
        path: resolve_path_for_os(bc.path, os_type),
        content: Base.encode64(bc.content),
        canary_token: bc.canary_token,
        content_hash: bc.content_hash,
        metadata: %{
          deployed_at: DateTime.to_iso8601(bc.deployed_at),
          breadcrumb_id: bc.id
        }
      }
    end)
  end

  defp resolve_path_for_os(path, os_type) do
    # Expand path based on OS conventions
    case os_type do
      "windows" ->
        # Convert to Windows path format
        path
        |> String.replace("/", "\\")
        |> expand_windows_path()

      "linux" ->
        # Expand ~ to home directory (agent will handle actual expansion)
        if String.starts_with?(path, ".") do
          "~/" <> path
        else
          path
        end

      "macos" ->
        # Similar to Linux
        if String.starts_with?(path, ".") or String.starts_with?(path, "Library") do
          "~/" <> path
        else
          path
        end

      _ ->
        path
    end
  end

  defp expand_windows_path(path) do
    cond do
      String.starts_with?(path, "AppData") ->
        "%USERPROFILE%\\" <> path

      String.starts_with?(path, "Documents") or String.starts_with?(path, "Desktop") or
      String.starts_with?(path, "Downloads") ->
        "%USERPROFILE%\\" <> path

      String.starts_with?(path, ".") ->
        # Hidden/config files go to user profile
        "%USERPROFILE%\\" <> path

      true ->
        path
    end
  end

  defp deploy_rotation_to_agent(agent_id, old_breadcrumbs) do
    # Generate new breadcrumbs to replace old ones
    case Agents.get_agent(agent_id) do
      {:ok, agent} ->
        new_breadcrumbs =
          Enum.map(old_breadcrumbs, fn old_bc ->
            create_breadcrumb_with_content(agent_id, agent.os_type, old_bc.type)
          end)

        # Persist new breadcrumbs
        persist_breadcrumbs_to_db(new_breadcrumbs)

        # Build rotation command
        rotation_command = %{
          remove: Enum.map(old_breadcrumbs, &Map.take(&1, [:path, :canary_token])),
          deploy: build_deploy_commands(new_breadcrumbs, agent.os_type)
        }

        case CommandManager.queue_command(
          agent_id,
          :rotate_breadcrumbs,
          rotation_command,
          priority: 2
        ) do
          {:ok, _command} ->
            Logger.info("Queued breadcrumb rotation for agent #{agent_id}")
            :ok

          {:error, reason} ->
            Logger.error("Failed to queue breadcrumb rotation: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, :not_found} ->
        Logger.debug("Agent #{agent_id} not connected, rotation queued")
        :ok
    end
  end
end
