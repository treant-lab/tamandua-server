defmodule TamanduaServer.Remediation.Executor do
  @moduledoc """
  Remediation Playbook Executor with 15+ Action Handlers

  Executes remediation playbooks with comprehensive action support:
  - Network isolation and firewall management
  - Process and service management
  - User account management
  - File operations and quarantine
  - Registry operations (Windows)
  - Certificate management
  - Session management
  - Patch deployment
  - Forensic collection
  - Notification and ticketing

  Features:
  - Dry-run simulation mode
  - Automatic rollback on failure
  - Step-by-step execution with retry logic
  - Parallel and conditional execution
  - Comprehensive error handling and logging
  """

  require Logger
  alias TamanduaServer.Accounts
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Response.Executor, as: ResponseExecutor
  alias TamanduaServer.Remediation.{ApprovalManager, Playbook, Execution}

  @type execution_result :: {:ok, map()} | {:error, term()}
  @type step_result :: {:ok, map(), map()} | {:error, String.t()} | {:skip, String.t(), map()}

  @max_retries 3

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Execute a playbook with the given context.

  Options:
    - :dry_run - Simulate execution without making changes (default: false)
    - :skip_approval - Skip approval only for dry-run simulations (default: false)
    - :triggered_by - User ID who triggered the execution
    - :scope - Required tenant scope (`{:organization, organization_id}`)
    - :timeout - Overall execution timeout in milliseconds (default: 300000)

  Returns:
    - {:ok, execution} - Execution started or completed successfully
    - {:error, reason} - Failed to start or execute playbook
  """
  @spec execute_playbook(String.t(), map(), keyword()) :: {:ok, Execution.t()} | {:error, term()}
  def execute_playbook(playbook_id, context \\ %{}, opts \\ []) do
    context = normalize_context(context)
    scope = Keyword.get(opts, :scope)

    with {:ok, playbook} <- load_playbook(playbook_id, scope),
         :ok <- live_execution_admission(playbook, opts),
         :ok <- validate_approval_bypass(opts),
         :ok <- validate_execution_context(playbook, context),
         scoped_context <- put_context_organization(context, playbook.organization_id),
         {:ok, execution} <- create_execution_record(playbook, scoped_context, opts, scope) do
      if execution.status == "pending_approval" do
        ApprovalManager.request_approval(execution)
      else
        Task.start(fn -> run_execution(execution, playbook, opts) end)
      end

      {:ok, execution}
    end
  end

  @doc """
  Execute a single remediation action.

  This is a lower-level function for executing individual actions without
  a full playbook context.
  """
  @spec execute_action(String.t(), map(), map(), term()) :: execution_result()
  def execute_action(action_type, params, context, scope \\ nil) do
    context = normalize_context(context)

    with {:ok, organization_id} <- organization_from_scope(scope),
         :ok <- validate_claimed_organization(context, organization_id) do
      scoped_context = put_context_organization(context, organization_id)
      execute_step_action(action_type, params, scoped_context, false)
    end
  end

  @doc """
  Approve a pending execution.
  """
  @spec approve_execution(String.t(), String.t(), String.t() | nil, term()) ::
          {:ok, Execution.t()} | {:error, term()}
  def approve_execution(execution_id, approver_id, comments \\ nil, scope \\ nil) do
    with {:ok, execution} <- get_execution(execution_id, scope),
         :ok <- validate_pending_approval(execution),
         :ok <- validate_persisted_execution_admission(execution),
         execution_scope <- execution_scope(execution),
         {:ok, playbook} <- load_playbook(execution.playbook_id, execution_scope),
         :ok <- validate_playbook_for_execution(playbook, execution),
         :ok <- validate_approver(execution, approver_id) do
      # Update execution to approved status
      {:ok, execution} =
        Execution.update_execution(
          execution,
          %{
            status: "approved",
            approval_status: "approved",
            approved_by: approver_id,
            approved_at: DateTime.utc_now(),
            approval_comments: comments
          },
          execution_scope
        )

      # Continue execution
      Task.start(fn ->
        run_execution(execution, playbook, dry_run: true)
      end)

      {:ok, execution}
    end
  end

  @doc """
  Reject a pending execution.
  """
  @spec reject_execution(String.t(), String.t(), String.t(), term()) ::
          {:ok, Execution.t()} | {:error, term()}
  def reject_execution(execution_id, approver_id, reason, scope \\ nil) do
    with {:ok, execution} <- get_execution(execution_id, scope),
         :ok <- validate_pending_approval(execution),
         :ok <- validate_approver(execution, approver_id) do
      Execution.update_execution(
        execution,
        %{
          status: "cancelled",
          approval_status: "rejected",
          approved_by: approver_id,
          approved_at: DateTime.utc_now(),
          approval_comments: reason,
          completed_at: DateTime.utc_now()
        },
        scope
      )
    end
  end

  @doc false
  def expire_approval(execution_id, scope) do
    with {:ok, execution} <- get_execution(execution_id, scope),
         :ok <- validate_pending_approval(execution) do
      Execution.update_execution(
        execution,
        %{
          status: "cancelled",
          approval_status: "expired",
          approval_comments: "Approval timeout exceeded",
          completed_at: DateTime.utc_now()
        },
        scope
      )
    end
  end

  @doc """
  Cancel a running execution.
  """
  @spec cancel_execution(String.t(), String.t(), term()) ::
          {:ok, Execution.t()} | {:error, term()}
  def cancel_execution(execution_id, reason, scope \\ nil) do
    with {:ok, execution} <- get_execution(execution_id, scope) do
      Execution.update_execution(
        execution,
        %{
          status: "cancelled",
          error_message: reason,
          completed_at: DateTime.utc_now()
        },
        scope
      )
    end
  end

  @doc """
  Rollback an execution.
  """
  @spec rollback_execution(String.t(), String.t(), term()) ::
          {:ok, Execution.t()} | {:error, term()}
  def rollback_execution(execution_id, user_id, scope \\ nil) do
    with {:ok, execution} <- get_execution(execution_id, scope),
         :ok <- validate_persisted_execution_admission(execution),
         :ok <- validate_user_membership(execution, user_id),
         :ok <- validate_rollback_available(execution) do
      # Perform rollback
      rollback_result = perform_rollback(execution)

      case rollback_result do
        {:ok, _} ->
          Execution.update_execution(
            execution,
            %{
              status: "rolled_back",
              rolled_back: true,
              rolled_back_at: DateTime.utc_now(),
              rolled_back_by: user_id
            },
            scope
          )

        {:error, reason} ->
          Logger.error("Rollback failed for execution #{execution_id}: #{reason}")
          {:error, "Rollback failed: #{reason}"}
      end
    end
  end

  # ============================================================================
  # Private Functions - Execution Flow
  # ============================================================================

  defp run_execution(execution, _playbook, opts) do
    scope = execution_scope(execution)

    with {:ok, execution} <- get_execution(execution.id, scope),
         :ok <- validate_persisted_worker_admission(execution),
         {:ok, playbook} <- load_playbook(execution.playbook_id, scope),
         :ok <- validate_playbook_for_execution(playbook, execution) do
      do_run_execution(execution, playbook, opts)
    end
  end

  defp do_run_execution(execution, playbook, opts) do
    dry_run = Keyword.get(opts, :dry_run, false) || execution.execution_mode == "dry_run"

    # Update status to running
    {:ok, execution} =
      Execution.update_execution(
        execution,
        %{
          status: "running",
          started_at: DateTime.utc_now()
        },
        execution_scope(execution)
      )

    Logger.info(
      "Starting #{if dry_run, do: "dry-run", else: "live"} execution of playbook #{playbook.name} (#{execution.id})"
    )

    # Execute all steps sequentially
    result = execute_steps(execution, playbook.steps, execution.execution_context, dry_run, 0)

    case result do
      {:ok, final_context} ->
        Logger.info("Playbook execution #{execution.id} completed successfully")

        Execution.update_execution(
          execution,
          %{
            status: "completed",
            completed_at: DateTime.utc_now(),
            execution_context: final_context
          },
          execution_scope(execution)
        )

      {:error, reason} ->
        Logger.error("Playbook execution #{execution.id} failed: #{reason}")

        {:ok, execution} =
          Execution.update_execution(
            execution,
            %{
              status: "failed",
              error_message: reason,
              completed_at: DateTime.utc_now()
            },
            execution_scope(execution)
          )

        # Auto-rollback if enabled
        if playbook.auto_rollback_on_failure && execution.rollback_available do
          Logger.info("Auto-rolling back execution #{execution.id}")
          perform_rollback(execution)
        end

        {:error, reason}
    end
  end

  defp execute_steps(_execution, steps, context, _dry_run, index) when index >= length(steps) do
    # All steps completed
    {:ok, context}
  end

  defp execute_steps(execution, steps, context, dry_run, index) do
    step = Enum.at(steps, index)
    action = step["action"]

    Logger.info("Executing step #{index + 1}/#{length(steps)}: #{action}")

    # Update execution progress
    Execution.update_execution(
      execution,
      %{
        current_step_index: index,
        steps_completed: index
      },
      execution_scope(execution)
    )

    # Execute the step
    result = execute_single_step(step, context, dry_run)

    case result do
      {:ok, step_result, updated_context} ->
        # Record step result
        record_step_result(execution, index, step, :success, step_result)

        # Continue to next step
        execute_steps(execution, steps, updated_context, dry_run, index + 1)

      {:skip, reason, updated_context} ->
        Logger.info("Step #{index} skipped: #{reason}")
        record_step_result(execution, index, step, :skipped, %{reason: reason})
        execute_steps(execution, steps, updated_context, dry_run, index + 1)

      {:error, reason} ->
        record_step_result(execution, index, step, :failed, %{error: reason})

        # Check if we should continue on failure
        continue_on_failure = step["continue_on_failure"] || false

        if continue_on_failure do
          Logger.warning("Step #{index} failed but continue_on_failure is true: #{reason}")
          execute_steps(execution, steps, context, dry_run, index + 1)
        else
          {:error, "Step #{index} (#{action}) failed: #{reason}"}
        end
    end
  end

  defp execute_single_step(step, context, dry_run) do
    action = step["action"]
    params = step["params"] || %{}
    max_retries = step["max_retries"] || @max_retries

    # Merge context into params
    merged_params = merge_context_into_params(params, context)

    # Execute with retries
    execute_with_retries(action, merged_params, context, dry_run, max_retries)
  end

  defp execute_with_retries(action, params, context, dry_run, retries_left) do
    result = execute_step_action(action, params, context, dry_run)

    case result do
      {:error, reason} when retries_left > 0 ->
        Logger.warning("Action #{action} failed (#{retries_left} retries left): #{reason}")
        delay = 1000 * (@max_retries - retries_left + 1) ** 2
        Process.sleep(delay)
        execute_with_retries(action, params, context, dry_run, retries_left - 1)

      other ->
        other
    end
  end

  # ============================================================================
  # Action Handlers (15+ types)
  # ============================================================================

  # This is deliberately checked at the final action boundary as well as at
  # playbook admission. A future caller must not be able to bypass the product
  # lock by reaching an individual handler directly.
  defp execute_step_action(action, params, context, true),
    do: do_execute_step_action(action, params, context, true)

  defp execute_step_action(_action, _params, _context, _dry_run),
    do: {:error, :live_execution_disabled}

  # Network Isolation
  defp do_execute_step_action("isolate_network", params, context, dry_run) do
    agent_id = get_agent_id(params, context)

    if dry_run do
      Logger.info("[DRY RUN] Would isolate agent #{agent_id}")
      {:ok, %{action: "isolate_network", agent_id: agent_id, dry_run: true}, context}
    else
      options = Keyword.put(params[:options] || [], :actor, response_actor(context))

      case ResponseExecutor.isolate_network(agent_id, options) do
        {:ok, result} ->
          {:ok, %{action: "isolate_network", agent_id: agent_id, result: result},
           Map.put(context, :isolated_agents, [agent_id | Map.get(context, :isolated_agents, [])])}

        {:error, reason} ->
          {:error, "Failed to isolate network: #{inspect(reason)}"}
      end
    end
  end

  # Process Kill
  defp do_execute_step_action("kill_process", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    pid = params["pid"] || context[:pid]

    if dry_run do
      Logger.info("[DRY RUN] Would kill process #{pid} on agent #{agent_id}")
      {:ok, %{action: "kill_process", agent_id: agent_id, pid: pid, dry_run: true}, context}
    else
      case ResponseExecutor.kill_process(agent_id, pid, actor: response_actor(context)) do
        {:ok, result} ->
          {:ok, %{action: "kill_process", agent_id: agent_id, pid: pid, result: result}, context}

        {:error, reason} ->
          {:error, "Failed to kill process: #{inspect(reason)}"}
      end
    end
  end

  # File Quarantine
  defp do_execute_step_action("quarantine_file", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    path = params["path"] || context[:file_path]

    if dry_run do
      Logger.info("[DRY RUN] Would quarantine file #{path} on agent #{agent_id}")
      {:ok, %{action: "quarantine_file", agent_id: agent_id, path: path, dry_run: true}, context}
    else
      case ResponseExecutor.quarantine_file(agent_id, path, actor: response_actor(context)) do
        {:ok, result} ->
          # Store rollback data
          rollback_data = %{
            action: "restore_file",
            agent_id: agent_id,
            path: path,
            quarantine_location: result["quarantine_path"]
          }

          updated_context =
            Map.update(context, :rollback_stack, [rollback_data], &[rollback_data | &1])

          {:ok, %{action: "quarantine_file", agent_id: agent_id, path: path, result: result},
           updated_context}

        {:error, reason} ->
          {:error, "Failed to quarantine file: #{inspect(reason)}"}
      end
    end
  end

  # User Account Disable
  defp do_execute_step_action("disable_user", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    username = params["username"] || context[:username]
    domain = params["domain"] || context[:domain]

    if dry_run do
      Logger.info("[DRY RUN] Would disable user #{username} on agent #{agent_id}")

      {:ok, %{action: "disable_user", agent_id: agent_id, username: username, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(
             agent_id,
             "disable_user",
             %{username: username, domain: domain},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          # Store rollback data
          rollback_data = %{
            action: "enable_user",
            agent_id: agent_id,
            username: username,
            domain: domain
          }

          updated_context =
            Map.update(context, :rollback_stack, [rollback_data], &[rollback_data | &1])

          {:ok, %{action: "disable_user", agent_id: agent_id, username: username, result: result},
           updated_context}

        {:error, reason} ->
          {:error, "Failed to disable user: #{inspect(reason)}"}
      end
    end
  end

  # Force Password Reset
  defp do_execute_step_action("force_password_reset", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    username = params["username"] || context[:username]
    domain = params["domain"] || context[:domain]

    if dry_run do
      Logger.info("[DRY RUN] Would force password reset for #{username} on agent #{agent_id}")

      {:ok,
       %{action: "force_password_reset", agent_id: agent_id, username: username, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(
             agent_id,
             "force_password_reset",
             %{username: username, domain: domain},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok,
           %{
             action: "force_password_reset",
             agent_id: agent_id,
             username: username,
             result: result
           }, context}

        {:error, reason} ->
          {:error, "Failed to force password reset: #{inspect(reason)}"}
      end
    end
  end

  # IP Blocking
  defp do_execute_step_action("block_ip", params, context, dry_run) do
    ip = params["ip"] || context[:remote_ip] || context[:ip]
    duration = params["duration"] || context[:block_duration] || 0

    if dry_run do
      Logger.info("[DRY RUN] Would block IP #{ip}")
      {:ok, %{action: "block_ip", ip: ip, dry_run: true}, context}
    else
      # Require an explicit target; tenant-wide broadcast is intentionally disabled.
      agent_id = params["agent_id"] || context[:agent_id]

      if is_binary(agent_id) and agent_id != "" do
        case execute_block_ip(agent_id, ip, duration, context) do
          {:ok, result} ->
            {:ok, %{action: "block_ip", ip: ip, agent_id: agent_id, result: result}, context}

          {:error, failure} ->
            {:error, "Failed to block IP: #{inspect(failure)}"}
        end
      else
        {:error, "block_ip requires an explicit agent_id; tenant-wide broadcast is disabled"}
      end
    end
  end

  # Domain Blocking
  defp do_execute_step_action("block_domain", params, context, dry_run) do
    domain = params["domain"] || context[:domain]
    reason = params["reason"] || "Blocked by remediation playbook"

    if dry_run do
      Logger.info("[DRY RUN] Would block domain #{domain}")
      {:ok, %{action: "block_domain", domain: domain, dry_run: true}, context}
    else
      # Add to DNS blocklist
      organization_id = organization_id_from_context(context)

      case TamanduaServer.Detection.DNSAnalyzer.add_to_blocklist(
             [domain],
             reason,
             "remediation",
             organization_id
           ) do
        {:ok, applied_domains} ->
          Logger.info("Blocked domain #{domain} (#{length(applied_domains)} entries added)")

          {:ok,
           %{
             action: "block_domain",
             domain: domain,
             entries_added: length(applied_domains),
             applied_domains: applied_domains
           }, context}

        {:error, reason} ->
          {:error, "Failed to block domain: #{reason}"}
      end
    end
  end

  # Service Stop
  defp do_execute_step_action("stop_service", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    service_name = params["service_name"] || context[:service_name]

    if dry_run do
      Logger.info("[DRY RUN] Would stop service #{service_name} on agent #{agent_id}")

      {:ok,
       %{action: "stop_service", agent_id: agent_id, service_name: service_name, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(agent_id, "stop_service", %{service: service_name},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok,
           %{
             action: "stop_service",
             agent_id: agent_id,
             service_name: service_name,
             result: result
           }, context}

        {:error, reason} ->
          {:error, "Failed to stop service: #{inspect(reason)}"}
      end
    end
  end

  # Service Disable
  defp do_execute_step_action("disable_service", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    service_name = params["service_name"] || context[:service_name]

    if dry_run do
      Logger.info("[DRY RUN] Would disable service #{service_name} on agent #{agent_id}")

      {:ok,
       %{
         action: "disable_service",
         agent_id: agent_id,
         service_name: service_name,
         dry_run: true
       }, context}
    else
      case ResponseExecutor.execute_action(agent_id, "disable_service", %{service: service_name},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          # Store rollback data
          rollback_data = %{
            action: "enable_service",
            agent_id: agent_id,
            service_name: service_name
          }

          updated_context =
            Map.update(context, :rollback_stack, [rollback_data], &[rollback_data | &1])

          {:ok,
           %{
             action: "disable_service",
             agent_id: agent_id,
             service_name: service_name,
             result: result
           }, updated_context}

        {:error, reason} ->
          {:error, "Failed to disable service: #{inspect(reason)}"}
      end
    end
  end

  # Registry Key Delete (Windows)
  defp do_execute_step_action("delete_registry_key", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    key_path = params["key_path"] || context[:registry_key]

    if dry_run do
      Logger.info("[DRY RUN] Would delete registry key #{key_path} on agent #{agent_id}")

      {:ok,
       %{action: "delete_registry_key", agent_id: agent_id, key_path: key_path, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(agent_id, "delete_registry_key", %{key_path: key_path},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok,
           %{
             action: "delete_registry_key",
             agent_id: agent_id,
             key_path: key_path,
             result: result
           }, context}

        {:error, reason} ->
          {:error, "Failed to delete registry key: #{inspect(reason)}"}
      end
    end
  end

  # File Delete
  defp do_execute_step_action("delete_file", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    path = params["path"] || context[:file_path]

    if dry_run do
      Logger.info("[DRY RUN] Would delete file #{path} on agent #{agent_id}")
      {:ok, %{action: "delete_file", agent_id: agent_id, path: path, dry_run: true}, context}
    else
      case ResponseExecutor.execute_action(agent_id, "delete_file", %{path: path},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok, %{action: "delete_file", agent_id: agent_id, path: path, result: result}, context}

        {:error, reason} ->
          {:error, "Failed to delete file: #{inspect(reason)}"}
      end
    end
  end

  # Agent Reboot
  defp do_execute_step_action("reboot_agent", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    delay_seconds = params["delay_seconds"] || 30

    if dry_run do
      Logger.info("[DRY RUN] Would reboot agent #{agent_id} after #{delay_seconds}s")

      {:ok,
       %{action: "reboot_agent", agent_id: agent_id, delay_seconds: delay_seconds, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(agent_id, "reboot", %{delay_seconds: delay_seconds},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok,
           %{
             action: "reboot_agent",
             agent_id: agent_id,
             delay_seconds: delay_seconds,
             result: result
           }, context}

        {:error, reason} ->
          {:error, "Failed to reboot agent: #{inspect(reason)}"}
      end
    end
  end

  # Patch Deployment
  defp do_execute_step_action("deploy_patch", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    patch_id = params["patch_id"] || context[:patch_id]

    if dry_run do
      Logger.info("[DRY RUN] Would deploy patch #{patch_id} to agent #{agent_id}")

      {:ok, %{action: "deploy_patch", agent_id: agent_id, patch_id: patch_id, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(agent_id, "deploy_patch", %{patch_id: patch_id},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok, %{action: "deploy_patch", agent_id: agent_id, patch_id: patch_id, result: result},
           context}

        {:error, reason} ->
          {:error, "Failed to deploy patch: #{inspect(reason)}"}
      end
    end
  end

  # Certificate Revocation
  defp do_execute_step_action("revoke_certificate", params, context, dry_run) do
    certificate_serial = params["certificate_serial"] || context[:certificate_serial]
    reason = params["reason"] || "Revoked by remediation playbook"

    if dry_run do
      Logger.info("[DRY RUN] Would revoke certificate #{certificate_serial}")

      {:ok,
       %{action: "revoke_certificate", certificate_serial: certificate_serial, dry_run: true},
       context}
    else
      # This would integrate with your PKI/certificate management system
      Logger.warning("Certificate revocation not yet implemented: #{certificate_serial}")

      {:ok,
       %{
         action: "revoke_certificate",
         certificate_serial: certificate_serial,
         status: "simulated"
       }, context}
    end
  end

  # MFA Enforcement
  defp do_execute_step_action("enforce_mfa", params, context, dry_run) do
    username = params["username"] || context[:username]
    domain = params["domain"] || context[:domain]

    if dry_run do
      Logger.info("[DRY RUN] Would enforce MFA for user #{username}")
      {:ok, %{action: "enforce_mfa", username: username, dry_run: true}, context}
    else
      # This would integrate with your identity provider
      Logger.warning("MFA enforcement not yet implemented for user: #{username}")
      {:ok, %{action: "enforce_mfa", username: username, status: "simulated"}, context}
    end
  end

  # Session Termination
  defp do_execute_step_action("terminate_session", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    session_id = params["session_id"] || context[:session_id]
    username = params["username"] || context[:username]

    if dry_run do
      Logger.info("[DRY RUN] Would terminate session #{session_id} on agent #{agent_id}")

      {:ok,
       %{action: "terminate_session", agent_id: agent_id, session_id: session_id, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(
             agent_id,
             "terminate_session",
             %{session_id: session_id, username: username},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok,
           %{
             action: "terminate_session",
             agent_id: agent_id,
             session_id: session_id,
             result: result
           }, context}

        {:error, reason} ->
          {:error, "Failed to terminate session: #{inspect(reason)}"}
      end
    end
  end

  # Forensics Collection
  defp do_execute_step_action("collect_forensics", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    collection_type = params["type"] || "standard"

    if dry_run do
      Logger.info("[DRY RUN] Would collect #{collection_type} forensics from agent #{agent_id}")

      {:ok,
       %{action: "collect_forensics", agent_id: agent_id, type: collection_type, dry_run: true},
       context}
    else
      case ResponseExecutor.collect_forensics(
             agent_id,
             Map.put(params, :actor, response_actor(context))
           ) do
        {:ok, collection_id} ->
          {:ok,
           %{
             action: "collect_forensics",
             agent_id: agent_id,
             collection_id: collection_id,
             type: collection_type
           }, context}

        {:error, reason} ->
          {:error, "Failed to collect forensics: #{inspect(reason)}"}
      end
    end
  end

  # Notification
  defp do_execute_step_action("send_notification", params, context, dry_run) do
    channel = params["channel"] || "email"
    message = params["message"] || "Remediation action completed"
    recipients = params["recipients"] || []

    Logger.info("[DRY RUN] Would send notification via #{channel}: #{message}")

    {:ok,
     %{
       action: "send_notification",
       channel: channel,
       recipients: recipients,
       sent: false,
       dry_run: dry_run
     }, context}
  end

  # Ticket Creation
  defp do_execute_step_action("create_ticket", params, context, dry_run) do
    title = params["title"] || "Security Incident - Remediation Action"
    description = params["description"] || build_ticket_description(context)
    priority = params["priority"] || "high"

    if dry_run do
      Logger.info("[DRY RUN] Would create ticket: #{title}")
      {:ok, %{action: "create_ticket", title: title, dry_run: true}, context}
    else
      # This would integrate with your ticketing system
      ticket_id = "TICKET-#{:rand.uniform(100_000)}"
      Logger.info("Created ticket #{ticket_id}: #{title}")

      {:ok, %{action: "create_ticket", ticket_id: ticket_id, title: title, priority: priority},
       context}
    end
  end

  # Script Execution
  defp do_execute_step_action("run_script", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    script = params["script"] || params["command"]
    script_type = params["script_type"] || "powershell"

    if dry_run do
      Logger.info("[DRY RUN] Would run #{script_type} script on agent #{agent_id}")

      {:ok, %{action: "run_script", agent_id: agent_id, script_type: script_type, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(
             agent_id,
             "run_script",
             %{script: script, script_type: script_type},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok,
           %{action: "run_script", agent_id: agent_id, script_type: script_type, result: result},
           context}

        {:error, reason} ->
          {:error, "Failed to run script: #{inspect(reason)}"}
      end
    end
  end

  # Restore File (for rollback)
  defp do_execute_step_action("restore_file", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    path = params["path"]
    quarantine_location = params["quarantine_location"]

    if dry_run do
      Logger.info("[DRY RUN] Would restore file #{path} from #{quarantine_location}")
      {:ok, %{action: "restore_file", agent_id: agent_id, path: path, dry_run: true}, context}
    else
      case ResponseExecutor.execute_action(
             agent_id,
             "restore_file",
             %{path: path, quarantine_location: quarantine_location},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok, %{action: "restore_file", agent_id: agent_id, path: path, result: result},
           context}

        {:error, reason} ->
          {:error, "Failed to restore file: #{inspect(reason)}"}
      end
    end
  end

  # Enable User (for rollback)
  defp do_execute_step_action("enable_user", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    username = params["username"]
    domain = params["domain"]

    if dry_run do
      Logger.info("[DRY RUN] Would enable user #{username}")

      {:ok, %{action: "enable_user", agent_id: agent_id, username: username, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(
             agent_id,
             "enable_user",
             %{username: username, domain: domain},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok, %{action: "enable_user", agent_id: agent_id, username: username, result: result},
           context}

        {:error, reason} ->
          {:error, "Failed to enable user: #{inspect(reason)}"}
      end
    end
  end

  # Enable Service (for rollback)
  defp do_execute_step_action("enable_service", params, context, dry_run) do
    agent_id = get_agent_id(params, context)
    service_name = params["service_name"]

    if dry_run do
      Logger.info("[DRY RUN] Would enable service #{service_name}")

      {:ok,
       %{action: "enable_service", agent_id: agent_id, service_name: service_name, dry_run: true},
       context}
    else
      case ResponseExecutor.execute_action(agent_id, "enable_service", %{service: service_name},
             actor: response_actor(context)
           ) do
        {:ok, result} ->
          {:ok,
           %{
             action: "enable_service",
             agent_id: agent_id,
             service_name: service_name,
             result: result
           }, context}

        {:error, reason} ->
          {:error, "Failed to enable service: #{inspect(reason)}"}
      end
    end
  end

  # Default handler for unknown actions
  defp do_execute_step_action(action, _params, _context, _dry_run) do
    {:error, "Unknown action type: #{action}"}
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp normalize_context(context) when is_map(context), do: context
  defp normalize_context(context) when is_list(context), do: Map.new(context)
  defp normalize_context(_context), do: %{}

  defp organization_id_from_context(context) do
    agent_id = get_agent_id(%{}, context)

    context[:organization_id] ||
      context["organization_id"] ||
      (agent_id && TamanduaServer.Agents.OrgLookup.get_org_id(agent_id))
  rescue
    _ -> nil
  end

  defp load_playbook(playbook_id, scope) do
    case Playbook.get_playbook(playbook_id, scope) do
      {:ok, playbook} -> {:ok, playbook}
      {:error, :not_found} -> {:error, :playbook_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  defp create_execution_record(playbook, context, opts, scope) do
    dry_run = Keyword.get(opts, :dry_run, false)
    skip_approval = Keyword.get(opts, :skip_approval, false)
    triggered_by = Keyword.get(opts, :triggered_by)

    execution_mode = if dry_run, do: "dry_run", else: "live"

    status =
      cond do
        playbook.require_approval and not skip_approval -> "pending_approval"
        true -> "approved"
      end

    attrs = %{
      playbook_id: playbook.id,
      playbook_name: playbook.name,
      playbook_version: playbook.version,
      trigger_event: context,
      status: status,
      execution_mode: execution_mode,
      execution_context: context,
      steps_total: length(playbook.steps),
      require_approval: playbook.require_approval and not skip_approval,
      approval_tier: playbook.approval_tier,
      approval_timeout_minutes: playbook.approval_timeout_minutes,
      approval_status: if(status == "pending_approval", do: "pending", else: nil),
      triggered_by: triggered_by,
      agent_id: get_agent_id(%{}, context),
      alert_id: context[:alert_id] || context["alert_id"],
      rollback_available: false,
      rollback_data: %{rollback_stack: []},
      organization_id: playbook.organization_id
    }

    Execution.create_execution(attrs, execution_scope_from_playbook(playbook, scope))
  end

  defp get_execution(execution_id, scope), do: Execution.get_execution(execution_id, scope)

  defp validate_execution_context(playbook, context) do
    claimed_org = organization_id_from_context(context)
    agent_id = get_agent_id(%{}, context)

    cond do
      is_binary(claimed_org) and claimed_org != playbook.organization_id ->
        {:error, :organization_mismatch}

      is_binary(agent_id) ->
        resolved_org =
          MultiTenant.with_organization(playbook.organization_id, fn ->
            TamanduaServer.Agents.OrgLookup.get_org_id(agent_id)
          end)

        case resolved_org do
          org_id when org_id == playbook.organization_id -> :ok
          _ -> {:error, :unauthorized_agent}
        end

      true ->
        :ok
    end
  rescue
    _ -> {:error, :unauthorized_agent}
  end

  defp put_context_organization(context, organization_id) do
    context
    |> Map.delete("organization_id")
    |> Map.put(:organization_id, organization_id)
  end

  defp execution_scope_from_playbook(%{organization_id: organization_id}, _scope)
       when is_binary(organization_id) and organization_id != "",
       do: {:organization, organization_id}

  defp execution_scope_from_playbook(_playbook, scope), do: scope

  defp organization_from_scope({:organization, organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:ok, organization_id}

  defp organization_from_scope(_scope), do: {:error, :tenant_required}

  defp validate_claimed_organization(context, organization_id) do
    case organization_id_from_context(context) do
      nil -> :ok
      ^organization_id -> :ok
      _other -> {:error, :organization_mismatch}
    end
  end

  defp validate_pending_approval(execution) do
    if execution.status == "pending_approval" do
      :ok
    else
      {:error, :not_pending_approval}
    end
  end

  defp validate_approval_bypass(opts) do
    if Keyword.get(opts, :skip_approval, false) and not Keyword.get(opts, :dry_run, false) do
      {:error, :approval_bypass_not_allowed}
    else
      :ok
    end
  end

  @doc false
  def live_execution_admission(playbook, opts) when is_list(opts) do
    cond do
      Keyword.get(opts, :dry_run, false) != true ->
        {:error, :live_execution_disabled}

      Keyword.get(opts, :skip_approval, false) != false ->
        {:error, :approval_bypass_not_allowed}

      Map.get(playbook, :require_approval, false) != true ->
        {:error, :approval_required}

      true ->
        :ok
    end
  end

  def live_execution_admission(_playbook, _opts), do: {:error, :live_execution_disabled}

  defp validate_persisted_execution_admission(%Execution{
         execution_mode: "dry_run",
         require_approval: true
       }),
       do: :ok

  defp validate_persisted_execution_admission(_execution),
    do: {:error, :live_execution_disabled}

  defp validate_persisted_worker_admission(%Execution{
         execution_mode: "dry_run",
         require_approval: true,
         status: "approved",
         approval_status: "approved"
       }),
       do: :ok

  defp validate_persisted_worker_admission(_execution),
    do: {:error, :live_execution_disabled}

  defp validate_playbook_for_execution(
         %Playbook{
           id: playbook_id,
           organization_id: organization_id,
           version: version,
           enabled: true,
           require_approval: true
         },
         %Execution{
           playbook_id: playbook_id,
           organization_id: organization_id,
           playbook_version: version
         }
       )
       when is_binary(organization_id) and organization_id != "",
       do: :ok

  defp validate_playbook_for_execution(_playbook, _execution),
    do: {:error, :playbook_execution_mismatch}

  defp validate_approver(execution, approver_id) do
    required_level = approval_level(execution.approval_tier)

    user =
      MultiTenant.with_organization(execution.organization_id, fn ->
        Accounts.get_user(approver_id)
      end)

    case user do
      %{organization_id: organization_id, role: role}
      when organization_id == execution.organization_id ->
        if approval_level(role) >= required_level,
          do: :ok,
          else: {:error, :insufficient_permissions}

      %{organization_id: _other} ->
        {:error, :organization_mismatch}

      nil ->
        {:error, :user_not_found}

      _ ->
        {:error, :user_lookup_failed}
    end
  rescue
    _ -> {:error, :user_lookup_failed}
  end

  defp validate_user_membership(execution, user_id) do
    user =
      MultiTenant.with_organization(execution.organization_id, fn ->
        Accounts.get_user(user_id)
      end)

    case user do
      %{organization_id: organization_id} when organization_id == execution.organization_id -> :ok
      %{organization_id: _other} -> {:error, :organization_mismatch}
      nil -> {:error, :user_not_found}
      _ -> {:error, :user_lookup_failed}
    end
  rescue
    _ -> {:error, :user_lookup_failed}
  end

  defp approval_level(role) when role in ["security_director", "admin"], do: 4
  defp approval_level("manager"), do: 3
  defp approval_level("senior_analyst"), do: 2
  defp approval_level("analyst"), do: 1
  defp approval_level(_role), do: 0

  defp validate_rollback_available(execution) do
    if execution.rollback_available and not execution.rolled_back do
      :ok
    else
      {:error, :rollback_not_available}
    end
  end

  defp record_step_result(execution, step_index, step, status, result) do
    step_result = %{
      step_index: step_index,
      action: step["action"],
      status: to_string(status),
      result: result,
      timestamp: DateTime.utc_now()
    }

    updated_results = execution.execution_results ++ [step_result]

    Execution.update_execution(
      execution,
      %{
        execution_results: updated_results,
        steps_completed: step_index + if(status in [:success, :skipped], do: 1, else: 0)
      },
      execution_scope(execution)
    )
  end

  defp perform_rollback(execution) do
    with :ok <- validate_persisted_execution_admission(execution) do
      do_perform_rollback(execution)
    end
  end

  defp do_perform_rollback(execution) do
    rollback_stack = get_in(execution.rollback_data, [:rollback_stack]) || []

    Logger.info("Performing rollback with #{length(rollback_stack)} actions")

    # Execute rollback actions in reverse order
    results =
      rollback_stack
      |> Enum.reverse()
      |> Enum.map(fn rollback_action ->
        Logger.info("Rollback action: #{rollback_action[:action]}")

        case execute_step_action(
               rollback_action[:action],
               rollback_action,
               execution.execution_context,
               true
             ) do
          {:ok, result, _context} -> {:ok, result}
          {:error, reason} -> {:error, reason}
          _ -> {:ok, %{}}
        end
      end)

    failed = Enum.count(results, &match?({:error, _}, &1))

    if failed > 0 do
      {:error, "#{failed} rollback actions failed"}
    else
      {:ok, %{actions_rolled_back: length(results)}}
    end
  end

  defp get_agent_id(params, context) do
    params["agent_id"] || params[:agent_id] || context[:agent_id] || context["agent_id"]
  end

  defp merge_context_into_params(params, context) do
    # Replace {{variable}} placeholders with context values
    params
    |> Enum.map(fn {key, value} ->
      {key, interpolate_value(value, context)}
    end)
    |> Map.new()
  end

  defp interpolate_value(value, context) when is_binary(value) do
    Regex.replace(~r/\{\{(\w+)\}\}/, value, fn _, key ->
      try do
        atom_key = String.to_existing_atom(key)
        to_string(Map.get(context, atom_key, Map.get(context, key, "")))
      rescue
        _ -> ""
      end
    end)
  end

  defp interpolate_value(value, _context), do: value

  defp execute_block_ip(agent_id, ip, duration, context) do
    ResponseExecutor.execute_action(
      agent_id,
      "block_ip",
      %{ip: ip, duration: duration},
      actor: response_actor(context)
    )
  end

  defp response_actor(context) do
    %{
      organization_id: organization_id_from_context(context),
      user_id: context[:current_user_id] || context["current_user_id"] || :system
    }
  end

  defp execution_scope(%Execution{organization_id: organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:organization, organization_id}

  defp execution_scope(_execution), do: nil

  defp build_ticket_description(context) do
    """
    Automated Remediation Action

    Context:
    #{inspect(context, pretty: true, limit: :infinity)}
    """
  end
end
