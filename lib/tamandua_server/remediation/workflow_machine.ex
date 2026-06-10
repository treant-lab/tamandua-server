defmodule TamanduaServer.Remediation.WorkflowMachine do
  @moduledoc """
  State machine logic for remediation workflows.

  Defines valid state transitions and provides validation functions.

  ## State Diagram

  ```
  pending ─────┬──► in_progress ───┬──► completed
               │                    │
               │                    └──► failed
               │
               └──► cancelled

  in_progress ──► cancelled (manual abort)
  failed ────────► in_progress (retry)
  ```
  """

  @valid_transitions %{
    "pending" => ~w(in_progress cancelled),
    "in_progress" => ~w(completed failed cancelled),
    "completed" => [],  # Terminal state
    "failed" => ~w(in_progress),  # Can retry
    "cancelled" => []  # Terminal state
  }

  @terminal_states ~w(completed cancelled)

  @doc "Get all valid transitions"
  def valid_transitions, do: @valid_transitions

  @doc "Check if a transition is valid"
  def can_transition?(from_state, to_state) do
    valid_next = Map.get(@valid_transitions, from_state, [])

    if to_state in valid_next do
      :ok
    else
      {:error, {:invalid_transition, from_state, to_state}}
    end
  end

  @doc "Get valid next states from current state"
  def next_states(current_state) do
    Map.get(@valid_transitions, current_state, [])
  end

  @doc "Check if state is terminal"
  def terminal?(state), do: state in @terminal_states

  @doc "Check if workflow can be retried"
  def can_retry?(workflow) do
    workflow.state == "failed" and workflow.retry_count < max_retries(workflow)
  end

  @doc "Get max retries for a workflow based on action type"
  def max_retries(%{action_type: "quarantine"}), do: 3
  def max_retries(%{action_type: "block"}), do: 3
  def max_retries(%{action_type: "notify"}), do: 5  # Notifications can retry more
  def max_retries(%{action_type: "escalate"}), do: 3
  def max_retries(_), do: 3

  @doc """
  Transition a workflow to a new state.

  Returns {:ok, workflow} or {:error, reason}.
  """
  def transition(workflow, new_state, attrs \\ %{}) do
    TamanduaServer.Remediation.Workflow.transition_state(workflow, new_state, attrs)
  end

  @doc "Start workflow execution"
  def start(workflow) do
    transition(workflow, "in_progress")
  end

  @doc "Mark workflow as completed"
  def complete(workflow, result \\ %{}) do
    transition(workflow, "completed", %{result: result})
  end

  @doc "Mark workflow as failed"
  def fail(workflow, error_message) do
    transition(workflow, "failed", %{error_message: error_message})
  end

  @doc "Cancel workflow"
  def cancel(workflow, reason \\ nil) do
    transition(workflow, "cancelled", %{error_message: reason})
  end
end
