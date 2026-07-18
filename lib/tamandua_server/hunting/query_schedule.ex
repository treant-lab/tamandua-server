defmodule TamanduaServer.Hunting.QuerySchedule do
  @moduledoc """
  Schema for scheduling saved queries to run automatically.
  Supports various schedule types and notification channels.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @schedule_types ~w(hourly daily weekly monthly cron)
  @alert_channels ~w(email slack webhook)

  schema "query_schedules" do
    belongs_to :saved_query, TamanduaServer.Hunting.SavedQuery
    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization

    # Schedule configuration
    field :schedule_type, :string
    field :cron_expression, :string
    field :enabled, :boolean, default: true

    # Alert configuration
    field :alert_on_results, :boolean, default: false
    field :result_threshold, :integer
    field :alert_channels, {:array, :string}, default: []

    # Notification recipients
    field :notification_emails, {:array, :string}, default: []
    field :notification_slack_channels, {:array, :string}, default: []
    field :notification_webhook_urls, {:array, :string}, default: []

    # Execution tracking
    field :last_executed_at, :utc_datetime
    field :next_execution_at, :utc_datetime
    field :execution_count, :integer, default: 0
    field :last_result_count, :integer
    field :last_execution_status, :string
    field :last_error_message, :string

    has_many :parameter_values, TamanduaServer.Hunting.QueryParameterValue
    has_many :result_history, TamanduaServer.Hunting.QueryResultHistory

    timestamps()
  end

  @doc false
  def changeset(schedule, attrs) do
    schedule
    |> cast(attrs, [
      :saved_query_id, :user_id, :organization_id,
      :schedule_type, :cron_expression, :enabled,
      :alert_on_results, :result_threshold, :alert_channels,
      :notification_emails, :notification_slack_channels, :notification_webhook_urls,
      :last_executed_at, :next_execution_at, :execution_count,
      :last_result_count, :last_execution_status, :last_error_message
    ])
    |> validate_required([:saved_query_id, :user_id, :schedule_type])
    |> validate_inclusion(:schedule_type, @schedule_types)
    |> validate_alert_channels()
    |> validate_cron_expression()
    |> calculate_next_execution()
  end

  def mark_executed_changeset(schedule, result_count, status, error_message \\ nil) do
    schedule
    |> change(%{
      last_executed_at: DateTime.utc_now() |> DateTime.truncate(:second),
      execution_count: (schedule.execution_count || 0) + 1,
      last_result_count: result_count,
      last_execution_status: status,
      last_error_message: error_message
    })
    |> calculate_next_execution()
  end

  defp validate_alert_channels(changeset) do
    case get_field(changeset, :alert_channels) do
      channels when is_list(channels) ->
        if Enum.all?(channels, &(&1 in @alert_channels)) do
          changeset
        else
          add_error(changeset, :alert_channels, "contains invalid channel types")
        end

      _ ->
        changeset
    end
  end

  defp validate_cron_expression(changeset) do
    schedule_type = get_field(changeset, :schedule_type)
    cron_expression = get_field(changeset, :cron_expression)

    if schedule_type == "cron" and is_nil(cron_expression) do
      add_error(changeset, :cron_expression, "required for cron schedule type")
    else
      changeset
    end
  end

  defp calculate_next_execution(changeset) do
    schedule_type = get_field(changeset, :schedule_type)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    next_execution =
      case schedule_type do
        "hourly" -> DateTime.add(now, 3600, :second)
        "daily" -> DateTime.add(now, 86400, :second)
        "weekly" -> DateTime.add(now, 604_800, :second)
        "monthly" -> DateTime.add(now, 2_592_000, :second)
        "cron" -> calculate_cron_next_execution(changeset, now)
        _ -> now
      end

    put_change(changeset, :next_execution_at, next_execution)
  end

  defp calculate_cron_next_execution(_changeset, now) do
    # Simplified cron calculation - in production, use a library like Quantum
    # For now, default to 1 hour
    DateTime.add(now, 3600, :second)
  end
end
