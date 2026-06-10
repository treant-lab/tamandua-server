defmodule TamanduaServer.Repo.Migrations.EnhanceSavedQueriesForLibrary do
  use Ecto.Migration

  def change do
    # Add new fields to saved_queries
    alter table(:saved_queries) do
      # Favoriting/starring
      add_if_not_exists :is_favorite, :boolean, default: false

      # Visibility control
      add_if_not_exists :visibility, :string, default: "private"  # private, organization, public

      # Query parameters/variables
      add_if_not_exists :parameters, :map, default: %{}  # {param_name: {type: "string", default: "..."}}

      # Performance tracking
      add_if_not_exists :avg_execution_time_ms, :integer
      add_if_not_exists :last_execution_time_ms, :integer

      # Community features
      add_if_not_exists :upvotes, :integer, default: 0
      add_if_not_exists :downvotes, :integer, default: 0
      add_if_not_exists :rating, :float, default: 0.0
      add_if_not_exists :download_count, :integer, default: 0

      # MITRE ATT&CK mapping
      add_if_not_exists :mitre_tactics, {:array, :string}, default: []
      add_if_not_exists :mitre_techniques, {:array, :string}, default: []

      # Author tracking
      add_if_not_exists :author_name, :string
      add_if_not_exists :author_organization, :string

      # Version control
      add_if_not_exists :version, :string, default: "1.0.0"
      add_if_not_exists :parent_id, references(:saved_queries, type: :binary_id, on_delete: :nilify_all)
    end

    # Create query schedules table
    create_if_not_exists table(:query_schedules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :saved_query_id, references(:saved_queries, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # Schedule configuration
      add :schedule_type, :string, null: false  # hourly, daily, weekly, monthly, cron
      add :cron_expression, :string
      add :enabled, :boolean, default: true

      # Alert configuration
      add :alert_on_results, :boolean, default: false
      add :result_threshold, :integer  # Alert if result count > threshold
      add :alert_channels, {:array, :string}, default: []  # ["email", "slack", "webhook"]

      # Notification recipients
      add :notification_emails, {:array, :string}, default: []
      add :notification_slack_channels, {:array, :string}, default: []
      add :notification_webhook_urls, {:array, :string}, default: []

      # Execution tracking
      add :last_executed_at, :utc_datetime
      add :next_execution_at, :utc_datetime
      add :execution_count, :integer, default: 0
      add :last_result_count, :integer
      add :last_execution_status, :string  # success, error, timeout
      add :last_error_message, :text

      timestamps()
    end

    # Create query results history table
    create_if_not_exists table(:query_result_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :query_schedule_id, references(:query_schedules, type: :binary_id, on_delete: :delete_all)
      add :saved_query_id, references(:saved_queries, type: :binary_id, on_delete: :delete_all)
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all)

      add :query_text, :text
      add :result_count, :integer
      add :execution_time_ms, :integer
      add :status, :string  # success, error, timeout
      add :error_message, :text
      add :results_summary, :map  # Aggregated stats, not full results

      timestamps(updated_at: false)
    end

    # Create query ratings/votes table
    create_if_not_exists table(:query_ratings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :saved_query_id, references(:saved_queries, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :vote, :integer  # 1 for upvote, -1 for downvote
      add :rating, :integer  # 1-5 stars
      add :comment, :text

      timestamps()
    end

    # Create query comments table
    create_if_not_exists table(:query_comments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :saved_query_id, references(:saved_queries, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :comment, :text, null: false
      add :parent_id, references(:query_comments, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    # Create query parameter values table (for scheduled queries with parameters)
    create_if_not_exists table(:query_parameter_values, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :query_schedule_id, references(:query_schedules, type: :binary_id, on_delete: :delete_all), null: false

      add :parameter_name, :string, null: false
      add :parameter_value, :string, null: false

      timestamps()
    end

    # Add indexes
    create_if_not_exists index(:saved_queries, [:is_favorite])
    create_if_not_exists index(:saved_queries, [:visibility])
    create_if_not_exists index(:saved_queries, [:rating])
    create_if_not_exists index(:saved_queries, [:upvotes])
    create_if_not_exists index(:saved_queries, [:download_count])
    create_if_not_exists index(:saved_queries, [:mitre_tactics], using: "gin")
    create_if_not_exists index(:saved_queries, [:mitre_techniques], using: "gin")
    create_if_not_exists index(:saved_queries, [:parent_id])

    create_if_not_exists index(:query_schedules, [:saved_query_id])
    create_if_not_exists index(:query_schedules, [:user_id])
    create_if_not_exists index(:query_schedules, [:organization_id])
    create_if_not_exists index(:query_schedules, [:enabled])
    create_if_not_exists index(:query_schedules, [:next_execution_at])

    create_if_not_exists index(:query_result_history, [:query_schedule_id])
    create_if_not_exists index(:query_result_history, [:saved_query_id])
    create_if_not_exists index(:query_result_history, [:user_id])
    create_if_not_exists index(:query_result_history, [:inserted_at])

    create_if_not_exists index(:query_ratings, [:saved_query_id])
    create_if_not_exists index(:query_ratings, [:user_id])
    create_if_not_exists unique_index(:query_ratings, [:saved_query_id, :user_id], name: :query_ratings_unique_user_query)

    create_if_not_exists index(:query_comments, [:saved_query_id])
    create_if_not_exists index(:query_comments, [:user_id])
    create_if_not_exists index(:query_comments, [:parent_id])

    create_if_not_exists index(:query_parameter_values, [:query_schedule_id])
  end
end
