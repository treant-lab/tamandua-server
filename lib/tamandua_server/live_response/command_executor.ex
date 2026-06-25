defmodule TamanduaServer.LiveResponse.CommandExecutor do
  @moduledoc """
  Executes live response commands against remote agents.

  Provides a comprehensive set of forensic and incident response operations
  organized into categories:

  ## File Operations
  - `list_directory` - List directory contents
  - `read_file` - Read file contents (text or hex)
  - `download_file` - Download a file from the agent
  - `upload_file` - Upload a file to the agent
  - `delete_file` - Delete a file from the agent
  - `hash_file` - Calculate hashes (MD5, SHA1, SHA256)
  - `get_file_metadata` - Get file attributes, timestamps, ACLs

  ## Process Operations
  - `list_processes` - List running processes
  - `kill_process` - Terminate a process
  - `suspend_process` - Suspend a process
  - `get_process_details` - Get detailed process info (modules, handles, memory)

  ## Registry Operations (Windows)
  - `list_keys` - List registry subkeys
  - `get_value` - Get a registry value
  - `search_registry` - Search for patterns in registry

  ## Network Operations
  - `list_connections` - List active network connections
  - `list_listening_ports` - List listening sockets
  - `dns_cache` - Dump DNS resolver cache
  - `arp_table` - Dump ARP/neighbor table

  ## System Info
  - `os_info` - Get OS version, hostname, uptime
  - `installed_software` - List installed software/packages
  - `services` - List system services
  - `scheduled_tasks` - List scheduled tasks/cron jobs
  - `autoruns` - List autostart entries

  ## Memory Operations
  - `dump_process_memory` - Dump process memory to file
  - `list_loaded_modules` - List DLLs/shared libraries in a process

  ## Evidence Collection
  - `collect_artifacts` - Collect a set of forensic artifacts
  - `hash_file` - Hash a file on disk

  ## Safety

  Each command goes through:
  1. Validation (required parameters, types)
  2. Authorization check (user role + command allowlist/denylist)
  3. Execution via agent channel
  4. Response parsing and sanitization

  Commands are subject to an allowlist/denylist to prevent accidental or
  malicious damage to target endpoints.
  """

  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Agents.Registry, as: AgentRegistry
  alias TamanduaServer.Agents.Worker
  alias TamanduaServer.LiveResponse.SessionManager
  alias TamanduaServer.LiveResponse.AuditLogger

  # Command timeout (30 seconds default)
  @default_timeout 30_000

  # Maximum output size (1MB)
  @max_output_size 1_048_576

  # Commands that are always blocked (destructive, no forensic value)
  @blocked_commands [
    "format_disk",
    "wipe_disk",
    "flash_bios"
  ]

  # Commands that require elevated authorization (admin or supervisor)
  @elevated_commands [
    "delete_file",
    "upload_file",
    "kill_process",
    "suspend_process",
    "dump_process_memory",
    "shell_execute"
  ]

  # All supported command types
  @supported_commands [
    # File operations
    "list_directory",
    "read_file",
    "download_file",
    "upload_file",
    "delete_file",
    "hash_file",
    "get_file_metadata",
    # Process operations
    "list_processes",
    "kill_process",
    "suspend_process",
    "get_process_details",
    # Registry operations
    "list_keys",
    "get_value",
    "search_registry",
    # Network operations
    "list_connections",
    "list_listening_ports",
    "dns_cache",
    "arp_table",
    # System info
    "os_info",
    "installed_software",
    "services",
    "scheduled_tasks",
    "autoruns",
    # Memory
    "dump_process_memory",
    "list_loaded_modules",
    "shell_execute",
    # Evidence collection
    "collect_artifacts"
  ]

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Execute a live response command.

  ## Parameters
  - `session_id` - Active session ID
  - `command` - Command type (one of the supported commands)
  - `args` - Command arguments (depends on command type)
  - `opts` - Options:
    - `:timeout` - Command timeout in ms (default 30s)
    - `:user_id` - Executing user's ID (for authorization)
    - `:user_role` - Executing user's role (for authorization)

  ## Returns
  - `{:ok, result}` - Command executed successfully
  - `{:error, reason}` - Command failed
  """
  @spec execute(String.t(), String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def execute(session_id, command, args \\ %{}, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    user_role = Keyword.get(opts, :user_role, :analyst)

    with :ok <- validate_command(command),
         :ok <- check_blocked(command),
         :ok <- check_authorization(command, user_role),
         :ok <- validate_args(command, args),
         {:ok, session} <- SessionManager.get_session(session_id),
         :ok <- validate_session_active(session),
         {:ok, agent_id} <- {:ok, session.agent_id} do
      # Execute the command
      start_time = System.monotonic_time(:millisecond)

      result =
        case dispatch_to_agent(agent_id, command, args, timeout) do
          {:ok, output} ->
            end_time = System.monotonic_time(:millisecond)

            result = %{
              status: "success",
              command: command,
              output: sanitize_output(output),
              exit_code: 0,
              executed_at: command_timestamp(),
              duration_ms: end_time - start_time
            }

            # Record in session history
            SessionManager.record_command(session_id, command, args, result)

            # Write audit log
            AuditLogger.log_command(session_id, session.user_id, session.agent_id, command, args, result)

            {:ok, result}

          {:error, :timeout} ->
            end_time = System.monotonic_time(:millisecond)

            result = %{
              status: "timeout",
              command: command,
              output: nil,
              exit_code: -1,
              executed_at: command_timestamp(),
              duration_ms: end_time - start_time
            }

            SessionManager.record_command(session_id, command, args, result)
            AuditLogger.log_command(session_id, session.user_id, session.agent_id, command, args, result)

            {:error, :timeout}

          {:error, reason} ->
            end_time = System.monotonic_time(:millisecond)

            result = %{
              status: "error",
              command: command,
              output: reason_to_output(reason),
              exit_code: 1,
              executed_at: command_timestamp(),
              duration_ms: end_time - start_time
            }

            SessionManager.record_command(session_id, command, args, result)
            AuditLogger.log_command(session_id, session.user_id, session.agent_id, command, args, result)

            {:ok, result}
        end

      # Touch session to prevent timeout
      SessionManager.touch_session(session_id)

      result
    end
  end

  @doc """
  Execute a command directly against an agent with tenant validation.
  Used for one-shot operations from the REST controller.

  This is the recommended function for API endpoints as it enforces
  multi-tenant isolation.

  ## Parameters
  - `agent_id` - Target agent ID
  - `org_id` - Organization ID for tenant validation
  - `command` - Command type
  - `args` - Command arguments
  - `opts` - Options (same as `execute/4`)

  ## Returns
  - `{:ok, result}` on success
  - `{:error, :unauthorized}` if agent does not belong to organization
  - `{:error, reason}` on other failures
  """
  @spec execute_direct(String.t(), String.t() | integer(), String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def execute_direct(agent_id, org_id, command, args, opts)
      when (is_binary(org_id) or is_integer(org_id)) and is_binary(command) do
    # Validate agent belongs to organization before executing. Live response
    # file/process APIs may target a freshly connected endpoint whose durable
    # inventory row has not caught up yet, so accept the live registry record
    # when its organization_id matches the requester.
    case validate_agent_for_org(agent_id, org_id) do
      :ok ->
        execute_direct_unsafe(agent_id, command, args, opts)

      {:error, :not_found} ->
        {:error, :unauthorized}
    end
  end

  @doc """
  Execute a command directly against a pre-authorized agent struct.
  Use this when the agent has already been authorized by the caller.

  ## Parameters
  - `agent` - Pre-authorized Agent struct
  - `command` - Command type
  - `args` - Command arguments
  - `opts` - Options (same as `execute/4`)
  """
  @spec execute_direct_for_agent(Agent.t() | map(), String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def execute_direct_for_agent(%{id: agent_id}, command, args \\ %{}, opts \\ [])
      when is_binary(agent_id) do
    execute_direct_unsafe(agent_id, command, args, opts)
  end

  def execute_direct_for_agent(%{agent_id: agent_id}, command, args, opts)
      when is_binary(agent_id) do
    execute_direct_unsafe(agent_id, command, args, opts)
  end

  @doc """
  Legacy execute_direct without tenant validation.

  DEPRECATED: This function bypasses tenant validation.
  Only use for system-level operations or internal calls where
  the agent has already been validated.

  For API endpoints, use `execute_direct/5` with org_id parameter.
  """
  @spec execute_direct_unsafe(String.t(), String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def execute_direct_unsafe(agent_id, command, args \\ %{}, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    user_role = Keyword.get(opts, :user_role, :analyst)

    with :ok <- validate_command(command),
         :ok <- check_blocked(command),
         :ok <- check_authorization(command, user_role),
         :ok <- validate_args(command, args),
         :ok <- verify_agent_online(agent_id) do
      start_time = System.monotonic_time(:millisecond)

      case dispatch_to_agent(agent_id, command, args, timeout) do
        {:ok, output} ->
          end_time = System.monotonic_time(:millisecond)

          {:ok,
           %{
             status: "success",
              command: command,
              output: sanitize_output(output),
              exit_code: 0,
              executed_at: command_timestamp(),
              duration_ms: end_time - start_time
            }}

        {:error, :timeout} ->
          {:error, :timeout}

        {:error, reason} ->
          end_time = System.monotonic_time(:millisecond)

          {:ok,
           %{
              status: "error",
              command: command,
              output: reason_to_output(reason),
              exit_code: 1,
              executed_at: command_timestamp(),
              duration_ms: end_time - start_time
            }}
      end
    end
  end

  @doc """
  Returns the list of all supported command types.
  """
  @spec supported_commands() :: [String.t()]
  def supported_commands, do: @supported_commands

  @doc """
  Returns the list of commands that require elevated authorization.
  """
  @spec elevated_commands() :: [String.t()]
  def elevated_commands, do: @elevated_commands

  @doc """
  Returns the list of permanently blocked commands.
  """
  @spec blocked_commands() :: [String.t()]
  def blocked_commands, do: @blocked_commands

  @doc """
  Check if a specific command is allowed for a given user role.
  """
  @spec command_allowed?(String.t(), atom() | String.t()) :: boolean()
  def command_allowed?(command, role) do
    role = normalize_role(role)

    cond do
      command in @blocked_commands -> false
      command not in @supported_commands -> false
      command in @elevated_commands -> role in [:admin, :supervisor, :responder]
      true -> true
    end
  end

  defp normalize_role(role) when is_atom(role), do: role

  defp normalize_role(role) when is_binary(role) do
    role
    |> String.downcase()
    |> String.replace("-", "_")
    |> case do
      "admin" -> :admin
      "supervisor" -> :supervisor
      "responder" -> :responder
      "analyst" -> :analyst
      "viewer" -> :viewer
      _ -> :unknown
    end
  end

  defp normalize_role(_), do: :unknown

  defp command_timestamp do
    DateTime.utc_now()
    |> DateTime.truncate(:second)
  end

  defp reason_to_output(reason) when is_binary(reason), do: reason
  defp reason_to_output(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp reason_to_output(reason), do: inspect(reason)

  # ============================================================================
  # File Operations
  # ============================================================================

  @doc """
  List directory contents on the remote agent.
  """
  @spec list_directory(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_directory(session_id, path, opts \\ []) do
    args = %{
      path: path,
      recursive: Keyword.get(opts, :recursive, false),
      include_hidden: Keyword.get(opts, :include_hidden, true),
      max_depth: Keyword.get(opts, :max_depth, 1)
    }

    execute(session_id, "list_directory", args, opts)
  end

  @doc """
  Read file contents from the remote agent.
  """
  @spec read_file(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def read_file(session_id, path, opts \\ []) do
    args = %{
      path: path,
      mode: Keyword.get(opts, :mode, "text"),
      max_size: Keyword.get(opts, :max_size, 65536),
      offset: Keyword.get(opts, :offset, 0)
    }

    execute(session_id, "read_file", args, opts)
  end

  @doc """
  Download a file from the remote agent.
  """
  @spec download_file(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def download_file(session_id, path, opts \\ []) do
    args = %{path: path}
    execute(session_id, "download_file", args, opts)
  end

  @doc """
  Upload a file to the remote agent.
  """
  @spec upload_file(String.t(), String.t(), binary(), keyword()) :: {:ok, map()} | {:error, term()}
  def upload_file(session_id, path, content, opts \\ []) do
    args = %{
      path: path,
      content: Base.encode64(content),
      overwrite: Keyword.get(opts, :overwrite, false),
      create_dirs: Keyword.get(opts, :create_dirs, false)
    }

    execute(session_id, "upload_file", args, opts)
  end

  @doc """
  Delete a file from the remote agent.
  """
  @spec delete_file(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def delete_file(session_id, path, opts \\ []) do
    args = %{path: path}
    execute(session_id, "delete_file", args, opts)
  end

  # ============================================================================
  # Process Operations
  # ============================================================================

  @doc """
  List running processes on the remote agent.
  """
  @spec list_processes(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_processes(session_id, opts \\ []) do
    args = %{
      filter: Keyword.get(opts, :filter),
      sort_by: Keyword.get(opts, :sort_by, "pid"),
      include_threads: Keyword.get(opts, :include_threads, false)
    }

    execute(session_id, "list_processes", args, opts)
  end

  @doc """
  Terminate a process on the remote agent.
  """
  @spec kill_process(String.t(), integer() | String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def kill_process(session_id, pid, opts \\ []) do
    args = %{
      pid: pid,
      force: Keyword.get(opts, :force, false)
    }

    execute(session_id, "kill_process", args, opts)
  end

  @doc """
  Suspend a process on the remote agent.
  """
  @spec suspend_process(String.t(), integer() | String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def suspend_process(session_id, pid, opts \\ []) do
    args = %{pid: pid}
    execute(session_id, "suspend_process", args, opts)
  end

  @doc """
  Get detailed information about a process.
  """
  @spec get_process_details(String.t(), integer() | String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_process_details(session_id, pid, opts \\ []) do
    args = %{
      pid: pid,
      include_modules: Keyword.get(opts, :include_modules, true),
      include_handles: Keyword.get(opts, :include_handles, false),
      include_memory_map: Keyword.get(opts, :include_memory_map, false)
    }

    execute(session_id, "get_process_details", args, opts)
  end

  # ============================================================================
  # Registry Operations
  # ============================================================================

  @doc """
  List registry subkeys (Windows only).
  """
  @spec list_keys(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_keys(session_id, key_path, opts \\ []) do
    args = %{
      key: key_path,
      recursive: Keyword.get(opts, :recursive, false)
    }

    execute(session_id, "list_keys", args, opts)
  end

  @doc """
  Get a registry value (Windows only).
  """
  @spec get_value(String.t(), String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_value(session_id, key_path, value_name, opts \\ []) do
    args = %{
      key: key_path,
      value_name: value_name
    }

    execute(session_id, "get_value", args, opts)
  end

  @doc """
  Search for patterns in the registry (Windows only).
  """
  @spec search_registry(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_registry(session_id, pattern, opts \\ []) do
    args = %{
      pattern: pattern,
      root_key: Keyword.get(opts, :root_key, "HKLM"),
      search_keys: Keyword.get(opts, :search_keys, true),
      search_values: Keyword.get(opts, :search_values, true),
      search_data: Keyword.get(opts, :search_data, false),
      max_results: Keyword.get(opts, :max_results, 100)
    }

    execute(session_id, "search_registry", args, opts)
  end

  # ============================================================================
  # Network Operations
  # ============================================================================

  @doc """
  List active network connections on the remote agent.
  """
  @spec list_connections(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_connections(session_id, opts \\ []) do
    args = %{
      state: Keyword.get(opts, :state, "all"),
      protocol: Keyword.get(opts, :protocol, "all"),
      pid: Keyword.get(opts, :pid)
    }

    execute(session_id, "list_connections", args, opts)
  end

  @doc """
  List listening ports on the remote agent.
  """
  @spec list_listening_ports(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_listening_ports(session_id, opts \\ []) do
    args = %{
      protocol: Keyword.get(opts, :protocol, "all")
    }

    execute(session_id, "list_listening_ports", args, opts)
  end

  @doc """
  Get DNS resolver cache from the remote agent.
  """
  @spec dns_cache(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def dns_cache(session_id, opts \\ []) do
    execute(session_id, "dns_cache", %{}, opts)
  end

  @doc """
  Get ARP/neighbor table from the remote agent.
  """
  @spec arp_table(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def arp_table(session_id, opts \\ []) do
    execute(session_id, "arp_table", %{}, opts)
  end

  # ============================================================================
  # System Info Operations
  # ============================================================================

  @doc """
  Get OS information from the remote agent.
  """
  @spec os_info(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def os_info(session_id, opts \\ []) do
    execute(session_id, "os_info", %{}, opts)
  end

  @doc """
  List installed software on the remote agent.
  """
  @spec installed_software(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def installed_software(session_id, opts \\ []) do
    args = %{
      filter: Keyword.get(opts, :filter)
    }

    execute(session_id, "installed_software", args, opts)
  end

  @doc """
  List system services on the remote agent.
  """
  @spec services(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def services(session_id, opts \\ []) do
    args = %{
      filter: Keyword.get(opts, :filter),
      state: Keyword.get(opts, :state, "all")
    }

    execute(session_id, "services", args, opts)
  end

  @doc """
  List scheduled tasks on the remote agent.
  """
  @spec scheduled_tasks(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def scheduled_tasks(session_id, opts \\ []) do
    execute(session_id, "scheduled_tasks", %{}, opts)
  end

  @doc """
  List autostart/autorun entries on the remote agent.
  """
  @spec autoruns(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def autoruns(session_id, opts \\ []) do
    execute(session_id, "autoruns", %{}, opts)
  end

  # ============================================================================
  # Memory Operations
  # ============================================================================

  @doc """
  Dump process memory on the remote agent.
  """
  @spec dump_process_memory(String.t(), integer() | String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def dump_process_memory(session_id, pid, opts \\ []) do
    args = %{
      pid: pid,
      full_dump: Keyword.get(opts, :full_dump, false),
      include_strings: Keyword.get(opts, :include_strings, false)
    }

    execute(session_id, "dump_process_memory", args, opts)
  end

  @doc """
  List loaded modules (DLLs/SOs) for a process.
  """
  @spec list_loaded_modules(String.t(), integer() | String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_loaded_modules(session_id, pid, opts \\ []) do
    args = %{pid: pid}
    execute(session_id, "list_loaded_modules", args, opts)
  end

  # ============================================================================
  # Evidence Collection
  # ============================================================================

  @doc """
  Collect a set of forensic artifacts from the remote agent.
  """
  @spec collect_artifacts(String.t(), [String.t()], keyword()) :: {:ok, map()} | {:error, term()}
  def collect_artifacts(session_id, artifact_types, opts \\ []) do
    args = %{
      artifacts: artifact_types,
      compress: Keyword.get(opts, :compress, true),
      include_hashes: Keyword.get(opts, :include_hashes, true)
    }

    execute(session_id, "collect_artifacts", args, opts)
  end

  @doc """
  Calculate file hashes (MD5, SHA1, SHA256) on the remote agent.
  """
  @spec hash_file(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def hash_file(session_id, path, opts \\ []) do
    args = %{path: path}
    execute(session_id, "hash_file", args, opts)
  end

  @doc """
  Get detailed file metadata including timestamps, ownership, and permissions.
  """
  @spec get_file_metadata(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_file_metadata(session_id, path, opts \\ []) do
    args = %{path: path}
    execute(session_id, "get_file_metadata", args, opts)
  end

  # ============================================================================
  # Private - Validation
  # ============================================================================

  defp validate_command(command) do
    if command in @supported_commands do
      :ok
    else
      {:error, :unknown_command}
    end
  end

  defp check_blocked(command) do
    if command in @blocked_commands do
      {:error, :command_blocked}
    else
      :ok
    end
  end

  defp check_authorization(command, role) do
    if command_allowed?(command, role) do
      :ok
    else
      {:error, :insufficient_permissions}
    end
  end

  defp validate_args(command, args) do
    case command do
      cmd when cmd in ["list_directory", "read_file", "download_file", "delete_file", "hash_file", "get_file_metadata"] ->
        if Map.has_key?(args, :path) or Map.has_key?(args, "path") do
          :ok
        else
          {:error, :missing_required_arg_path}
        end

      cmd when cmd in ["kill_process", "suspend_process", "get_process_details", "dump_process_memory", "list_loaded_modules"] ->
        if Map.has_key?(args, :pid) or Map.has_key?(args, "pid") do
          :ok
        else
          {:error, :missing_required_arg_pid}
        end

      "upload_file" ->
        has_path = Map.has_key?(args, :path) or Map.has_key?(args, "path")
        has_content = Map.has_key?(args, :content) or Map.has_key?(args, "content")

        if has_path and has_content do
          :ok
        else
          {:error, :missing_required_args}
        end

      cmd when cmd in ["list_keys", "get_value"] ->
        if Map.has_key?(args, :key) or Map.has_key?(args, "key") do
          :ok
        else
          {:error, :missing_required_arg_key}
        end

      "search_registry" ->
        if Map.has_key?(args, :pattern) or Map.has_key?(args, "pattern") do
          :ok
        else
          {:error, :missing_required_arg_pattern}
        end

      "collect_artifacts" ->
        if Map.has_key?(args, :artifacts) or Map.has_key?(args, "artifacts") do
          :ok
        else
          {:error, :missing_required_arg_artifacts}
        end

      "shell_execute" ->
        if Map.has_key?(args, :command) or Map.has_key?(args, "command") do
          :ok
        else
          {:error, :missing_required_arg_command}
        end

      _ ->
        # Commands without required args
        :ok
    end
  end

  defp validate_session_active(%{status: status}) when status in [:active, :idle], do: :ok
  defp validate_session_active(%{status: :expired}), do: {:error, :session_expired}
  defp validate_session_active(%{status: :closed}), do: {:error, :session_closed}
  defp validate_session_active(_), do: {:error, :session_not_active}

  defp verify_agent_online(agent_id) do
    case AgentRegistry.get(agent_id) do
      {:ok, %{status: status}} when status in [:online, :isolated] -> :ok
      {:ok, _} -> {:error, :agent_offline}
      {:error, _} -> {:error, :agent_not_found}
    end
  end

  defp validate_agent_for_org(agent_id, org_id) do
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, _agent} ->
        :ok

      {:error, :not_found} ->
        case AgentRegistry.get(agent_id) do
          {:ok, %{organization_id: agent_org_id}} when not is_nil(agent_org_id) ->
            if same_org?(agent_org_id, org_id), do: :ok, else: {:error, :not_found}

          _ ->
            {:error, :not_found}
        end
    end
  end

  defp same_org?(left, right), do: to_string(left) == to_string(right)

  # ============================================================================
  # Private - Dispatch
  # ============================================================================

  defp dispatch_to_agent(agent_id, command, args, timeout) do
    case AgentRegistry.get_worker_pid(agent_id) do
      {:ok, pid} ->
        payload = %{
          command_type: agent_command_type(command),
          payload: args
        }

        try do
          Worker.send_command(pid, payload, timeout: timeout)
        catch
          :exit, {:timeout, _} -> {:error, :timeout}
          :exit, reason -> {:error, {:agent_error, reason}}
        end

      {:error, :not_found} ->
        {:error, :agent_not_connected}
    end
  end

  defp agent_command_type("list_directory"), do: "file_list"
  defp agent_command_type("read_file"), do: "file_download"
  defp agent_command_type("download_file"), do: "file_download"
  defp agent_command_type("upload_file"), do: "file_upload"
  defp agent_command_type("hash_file"), do: "file_hash"
  defp agent_command_type("list_processes"), do: "process_list"
  defp agent_command_type("kill_process"), do: "process_kill"
  defp agent_command_type("dump_process_memory"), do: "process_dump"
  defp agent_command_type("memory_yara_scan"), do: "memory_scan"
  defp agent_command_type("memory_strings"), do: "memory_strings"
  defp agent_command_type("list_connections"), do: "network_connections"
  defp agent_command_type("dns_cache"), do: "dns_cache"
  defp agent_command_type("list_keys"), do: "registry_query"
  defp agent_command_type("services"), do: "service_list"
  defp agent_command_type("scheduled_tasks"), do: "scheduled_tasks"
  defp agent_command_type("autoruns"), do: "startup_items"
  defp agent_command_type("shell_execute"), do: "shell_execute"
  defp agent_command_type(command), do: command

  # ============================================================================
  # Private - Output Processing
  # ============================================================================

  defp sanitize_output(output) when is_binary(output) do
    if byte_size(output) > @max_output_size do
      String.slice(output, 0, @max_output_size) <> "\n... [output truncated at #{@max_output_size} bytes]"
    else
      output
    end
  end

  defp sanitize_output(output) when is_map(output), do: output
  defp sanitize_output(output) when is_list(output), do: output
  defp sanitize_output(output), do: to_string(output)
end
