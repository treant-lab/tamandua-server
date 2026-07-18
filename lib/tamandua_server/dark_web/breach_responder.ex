defmodule TamanduaServer.DarkWeb.BreachResponder do
  @moduledoc """
  Automated breach response workflows for compromised credentials.

  Provides configurable response actions when credentials are discovered
  on the dark web:

  - Password reset enforcement
  - Account disablement
  - MFA enforcement
  - User notification
  - Security team notification
  - Incident creation

  ## Configuration

  Configure default responses based on severity:

      config :tamandua_server, TamanduaServer.DarkWeb.BreachResponder,
        auto_response: true,
        critical_actions: [:account_disable, :security_team_notify, :create_incident],
        high_actions: [:password_reset, :mfa_enforce, :user_notify],
        medium_actions: [:user_notify],
        low_actions: []
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.DarkWeb.{Credential, ResponseWorkflow}
  alias TamanduaServer.Accounts
  alias TamanduaServer.Notifications

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Handle a compromised credential by triggering appropriate response workflows.

  ## Parameters

    - `credential` - The credential record
    - `opts` - Options:
      - `:manual` - If true, requires manual approval (default: false)
      - `:actions` - Override default actions (list of atoms)

  ## Examples

      iex> handle_compromise(credential)
      {:ok, [%ResponseWorkflow{}, ...]}

      iex> handle_compromise(credential, manual: true)
      {:ok, :pending_approval}
  """
  @spec handle_compromise(Credential.t(), keyword()) :: {:ok, term()} | {:error, term()}
  def handle_compromise(%Credential{} = credential, opts \\ []) do
    credential = Repo.preload(credential, [:user, :breach])

    manual = Keyword.get(opts, :manual, false)
    actions = Keyword.get(opts, :actions, get_default_actions(credential.severity))

    if manual do
      # Create pending workflows for manual approval
      create_pending_workflows(credential, actions)
      {:ok, :pending_approval}
    else
      # Execute workflows automatically
      execute_workflows(credential, actions)
    end
  end

  @doc """
  Execute a specific response action.

  ## Parameters

    - `credential` - The credential record
    - `action` - Action to execute: :password_reset, :account_disable, :mfa_enforce,
                :user_notify, :security_team_notify, :create_incident

  ## Examples

      iex> execute_action(credential, :password_reset)
      {:ok, %ResponseWorkflow{}}
  """
  @spec execute_action(Credential.t(), atom()) :: {:ok, ResponseWorkflow.t()} | {:error, term()}
  def execute_action(%Credential{} = credential, action) do
    credential = Repo.preload(credential, [:user, :breach])

    workflow_attrs = %{
      credential_id: credential.id,
      workflow_type: Atom.to_string(action),
      status: "in_progress",
      triggered_at: DateTime.utc_now()
    }

    {:ok, workflow} = create_workflow(workflow_attrs)

    result =
      case action do
        :password_reset -> force_password_reset(credential)
        :account_disable -> disable_account(credential)
        :mfa_enforce -> enforce_mfa(credential)
        :user_notify -> notify_user(credential)
        :security_team_notify -> notify_security_team(credential)
        :create_incident -> create_incident(credential)
        _ -> {:error, :unknown_action}
      end

    case result do
      {:ok, metadata} ->
        update_workflow(workflow, :completed, metadata)

      {:error, reason} ->
        update_workflow(workflow, :failed, %{error: inspect(reason)})
    end
  end

  @doc """
  Approve and execute a pending workflow.
  """
  @spec approve_workflow(String.t(), String.t()) :: {:ok, ResponseWorkflow.t()} | {:error, term()}
  def approve_workflow(workflow_id, executed_by_id) do
    workflow = Repo.get!(ResponseWorkflow, workflow_id)
    workflow = Repo.preload(workflow, credential: [:user, :breach])

    if workflow.status == "pending" do
      workflow
      |> ResponseWorkflow.changeset(%{
        status: "in_progress",
        executed_by_id: executed_by_id
      })
      |> Repo.update()

      action = String.to_atom(workflow.workflow_type)
      execute_action(workflow.credential, action)
    else
      {:error, :workflow_not_pending}
    end
  end

  # ============================================================================
  # Private Functions - Workflow Execution
  # ============================================================================

  defp execute_workflows(credential, actions) do
    results =
      Enum.map(actions, fn action ->
        Logger.info("[BreachResponder] Executing #{action} for credential #{credential.id}")
        execute_action(credential, action)
      end)

    # Update credential status
    update_credential_response(credential, actions)

    {:ok, results}
  end

  defp create_pending_workflows(credential, actions) do
    Enum.each(actions, fn action ->
      create_workflow(%{
        credential_id: credential.id,
        workflow_type: Atom.to_string(action),
        status: "pending",
        triggered_at: DateTime.utc_now()
      })
    end)
  end

  defp create_workflow(attrs) do
    %ResponseWorkflow{}
    |> ResponseWorkflow.changeset(attrs)
    |> Repo.insert()
  end

  defp update_workflow(workflow, status, metadata) do
    updates = %{
      status: Atom.to_string(status),
      completed_at: DateTime.utc_now(),
      metadata: metadata
    }

    updates =
      if status == :failed and metadata[:error] do
        Map.put(updates, :error_message, metadata[:error])
      else
        updates
      end

    workflow
    |> ResponseWorkflow.changeset(updates)
    |> Repo.update()
  end

  # ============================================================================
  # Private Functions - Response Actions
  # ============================================================================

  defp force_password_reset(credential) do
    if credential.user do
      # Mark user as requiring password reset
      case Accounts.require_password_reset(credential.user) do
        {:ok, _user} ->
          Logger.info("[BreachResponder] Forced password reset for user #{credential.user.email}")

          # Send notification email
          send_password_reset_email(credential.user, credential.breach)

          {:ok, %{action: "password_reset", user_id: credential.user.id}}

        {:error, reason} ->
          Logger.error("[BreachResponder] Failed to force password reset: #{inspect(reason)}")
          {:error, reason}
      end
    else
      {:error, :no_user_associated}
    end
  end

  defp disable_account(credential) do
    if credential.user do
      case Accounts.disable_user(credential.user) do
        {:ok, _user} ->
          Logger.info("[BreachResponder] Disabled account for user #{credential.user.email}")

          # Send notification
          send_account_disabled_email(credential.user, credential.breach)

          {:ok, %{action: "account_disabled", user_id: credential.user.id}}

        {:error, reason} ->
          Logger.error("[BreachResponder] Failed to disable account: #{inspect(reason)}")
          {:error, reason}
      end
    else
      {:error, :no_user_associated}
    end
  end

  defp enforce_mfa(credential) do
    if credential.user do
      # If user doesn't have MFA, require it on next login
      if !credential.user.mfa_enabled do
        case Accounts.require_mfa(credential.user) do
          {:ok, _user} ->
            Logger.info("[BreachResponder] Enforced MFA for user #{credential.user.email}")

            send_mfa_enforcement_email(credential.user, credential.breach)

            {:ok, %{action: "mfa_enforced", user_id: credential.user.id}}

          {:error, reason} ->
            {:error, reason}
        end
      else
        {:ok, %{action: "mfa_already_enabled", user_id: credential.user.id}}
      end
    else
      {:error, :no_user_associated}
    end
  end

  defp notify_user(credential) do
    if credential.user do
      send_breach_notification_email(credential.user, credential.breach)

      Logger.info("[BreachResponder] Sent breach notification to user #{credential.user.email}")

      {:ok, %{action: "user_notified", user_id: credential.user.id}}
    else
      {:error, :no_user_associated}
    end
  end

  defp notify_security_team(credential) do
    # Get all admin/security team users
    security_team = Accounts.list_security_team_users()

    Enum.each(security_team, fn user ->
      send_security_team_alert(user, credential)
    end)

    # Also create a notification in the notification center
    Notifications.create_notification(%{
      title: "Dark Web Credential Compromise",
      message: "Compromised credentials detected for #{credential.email}",
      type: "security_alert",
      severity: credential.severity,
      metadata: %{
        credential_id: credential.id,
        breach_id: credential.breach_id
      }
    })

    Logger.info("[BreachResponder] Notified security team about credential #{credential.id}")

    {:ok, %{action: "security_team_notified", notification_count: length(security_team)}}
  end

  defp create_incident(credential) do
    # Create an incident in the incident management system
    incident_attrs = %{
      title: "Dark Web Credential Compromise - #{credential.email}",
      description: """
      Compromised credentials detected on dark web.

      Email: #{credential.email}
      Breach: #{credential.breach && credential.breach.breach_name}
      Breach Date: #{credential.breach && credential.breach.breach_date}
      Data Exposed: #{credential.breach && Enum.join(credential.breach.data_classes || [], ", ")}
      Severity: #{credential.severity}
      Source: #{credential.source}
      """,
      severity: credential.severity,
      status: "open",
      incident_type: "credential_compromise",
      metadata: %{
        credential_id: credential.id,
        breach_id: credential.breach_id,
        user_id: credential.user_id
      }
    }

    # Assuming you have an Incidents context
    case TamanduaServer.Investigations.create_case_investigation(incident_attrs) do
      {:ok, incident} ->
        Logger.info("[BreachResponder] Created incident #{incident.id} for credential #{credential.id}")
        {:ok, %{action: "incident_created", incident_id: incident.id}}

      {:error, reason} ->
        Logger.error("[BreachResponder] Failed to create incident: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ============================================================================
  # Private Functions - Email Notifications
  # ============================================================================

  defp send_password_reset_email(user, _breach) do
    # Implementation would use your Mailer
    Logger.info("[BreachResponder] Sending password reset email to #{user.email}")
    # Mailer.send_password_reset_required(user, breach)
    :ok
  end

  defp send_account_disabled_email(user, _breach) do
    Logger.info("[BreachResponder] Sending account disabled email to #{user.email}")
    # Mailer.send_account_disabled(user, breach)
    :ok
  end

  defp send_mfa_enforcement_email(user, _breach) do
    Logger.info("[BreachResponder] Sending MFA enforcement email to #{user.email}")
    # Mailer.send_mfa_required(user, breach)
    :ok
  end

  defp send_breach_notification_email(user, _breach) do
    Logger.info("[BreachResponder] Sending breach notification email to #{user.email}")
    # Mailer.send_breach_notification(user, breach)
    :ok
  end

  defp send_security_team_alert(user, _credential) do
    Logger.info("[BreachResponder] Sending security alert to #{user.email}")
    # Mailer.send_security_alert(user, credential)
    :ok
  end

  # ============================================================================
  # Private Functions - Utilities
  # ============================================================================

  defp get_default_actions(severity) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    auto_response = Keyword.get(config, :auto_response, true)

    if auto_response do
      case severity do
        "critical" ->
          Keyword.get(config, :critical_actions, [
            :account_disable,
            :security_team_notify,
            :create_incident
          ])

        "high" ->
          Keyword.get(config, :high_actions, [
            :password_reset,
            :mfa_enforce,
            :user_notify,
            :security_team_notify
          ])

        "medium" ->
          Keyword.get(config, :medium_actions, [:user_notify])

        "low" ->
          Keyword.get(config, :low_actions, [])

        _ ->
          []
      end
    else
      []
    end
  end

  defp update_credential_response(credential, actions) do
    actions_str = Enum.map(actions, &Atom.to_string/1)

    credential
    |> Credential.changeset(%{
      response_taken: Enum.join(actions_str, ", "),
      response_at: DateTime.utc_now(),
      status: "investigating"
    })
    |> Repo.update()
  end
end
