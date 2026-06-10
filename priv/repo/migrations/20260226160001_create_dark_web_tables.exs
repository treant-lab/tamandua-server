defmodule TamanduaServer.Repo.Migrations.CreateDarkWebTables do
  use Ecto.Migration

  def change do
    # Dark web breaches discovered
    create table(:dark_web_breaches, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :breach_name, :string, null: false
      add :domain, :string
      add :breach_date, :utc_datetime
      add :added_date, :utc_datetime
      add :modified_date, :utc_datetime
      add :pwn_count, :integer
      add :description, :text
      add :data_classes, {:array, :string}, default: []
      add :is_verified, :boolean, default: false
      add :is_fabricated, :boolean, default: false
      add :is_sensitive, :boolean, default: false
      add :is_retired, :boolean, default: false
      add :is_spam_list, :boolean, default: false
      add :is_malware, :boolean, default: false
      add :logo_path, :string
      add :source, :string, null: false # hibp, intel471, flashpoint, custom
      add :source_id, :string
      add :raw_data, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dark_web_breaches, [:breach_name])
    create index(:dark_web_breaches, [:source])
    create index(:dark_web_breaches, [:breach_date])
    create unique_index(:dark_web_breaches, [:source, :source_id])

    # Compromised credentials found on dark web
    create table(:dark_web_credentials, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :breach_id, references(:dark_web_breaches, type: :binary_id, on_delete: :delete_all)
      add :email, :string, null: false
      add :username, :string
      add :password, :string # Encrypted/hashed
      add :password_hash, :string
      add :domain, :string
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all) # Matched organizational user
      add :severity, :string, null: false # critical, high, medium, low
      add :status, :string, null: false # new, investigating, resolved, false_positive
      add :matched_at, :utc_datetime
      add :first_seen, :utc_datetime
      add :last_seen, :utc_datetime
      add :source, :string, null: false
      add :response_taken, :string # action taken: password_reset, account_disabled, mfa_enforced, etc.
      add :response_at, :utc_datetime
      add :notes, :text
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dark_web_credentials, [:email])
    create index(:dark_web_credentials, [:user_id])
    create index(:dark_web_credentials, [:breach_id])
    create index(:dark_web_credentials, [:status])
    create index(:dark_web_credentials, [:severity])
    create index(:dark_web_credentials, [:first_seen])

    # Dark web intelligence findings (threat actor mentions, ransomware negotiations, etc.)
    create table(:dark_web_intelligence, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :intelligence_type, :string, null: false # threat_actor_chatter, ransomware_negotiation, data_leak, vulnerability_exploit, credential_marketplace
      add :title, :string, null: false
      add :description, :text
      add :content, :text
      add :url, :string
      add :source, :string, null: false # intel471, flashpoint, custom_scraper
      add :source_id, :string
      add :severity, :string, null: false
      add :keywords_matched, {:array, :string}, default: []
      add :threat_actors, {:array, :string}, default: []
      add :organizations_mentioned, {:array, :string}, default: []
      add :iocs, {:array, :string}, default: [] # IPs, domains, hashes mentioned
      add :cvees, {:array, :string}, default: []
      add :first_seen, :utc_datetime
      add :last_seen, :utc_datetime
      add :status, :string, null: false # new, investigating, resolved, false_positive
      add :assigned_to, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :incident_id, :binary_id # Link to incident if created
      add :raw_data, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dark_web_intelligence, [:intelligence_type])
    create index(:dark_web_intelligence, [:source])
    create index(:dark_web_intelligence, [:severity])
    create index(:dark_web_intelligence, [:status])
    create index(:dark_web_intelligence, [:first_seen])
    create unique_index(:dark_web_intelligence, [:source, :source_id])

    # Threat actor profiles from dark web
    create table(:dark_web_threat_actors, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :aliases, {:array, :string}, default: []
      add :actor_type, :string # ransomware_group, apt_group, cybercrime_group, hacktivist, etc.
      add :description, :text
      add :ttps, {:array, :string}, default: [] # MITRE ATT&CK techniques
      add :target_industries, {:array, :string}, default: []
      add :target_countries, {:array, :string}, default: []
      add :first_seen, :utc_datetime
      add :last_seen, :utc_datetime
      add :activity_level, :string # active, dormant, retired
      add :sophistication, :string # low, medium, high, advanced
      add :source, :string, null: false
      add :source_urls, {:array, :string}, default: []
      add :associated_malware, {:array, :string}, default: []
      add :ransom_amounts, :map, default: %{} # {min: X, max: Y, avg: Z}
      add :known_victims, {:array, :string}, default: []
      add :raw_data, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dark_web_threat_actors, [:name])
    create index(:dark_web_threat_actors, [:actor_type])
    create index(:dark_web_threat_actors, [:activity_level])
    create unique_index(:dark_web_threat_actors, [:name, :source])

    # Monitoring configurations (keywords, domains to monitor)
    create table(:dark_web_monitors, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :monitor_type, :string, null: false # credentials, keywords, domains, threat_actors
      add :keywords, {:array, :string}, default: []
      add :domains, {:array, :string}, default: []
      add :email_patterns, {:array, :string}, default: [] # @company.com patterns
      add :is_active, :boolean, default: true
      add :severity, :string, default: "high"
      add :alert_on_match, :boolean, default: true
      add :notification_channels, {:array, :string}, default: [] # email, slack, pagerduty
      add :last_check, :utc_datetime
      add :match_count, :integer, default: 0
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dark_web_monitors, [:monitor_type])
    create index(:dark_web_monitors, [:is_active])

    # Breach response workflows
    create table(:dark_web_response_workflows, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :credential_id, references(:dark_web_credentials, type: :binary_id, on_delete: :delete_all)
      add :intelligence_id, references(:dark_web_intelligence, type: :binary_id, on_delete: :delete_all)
      add :workflow_type, :string, null: false # password_reset, account_disable, mfa_enforce, user_notify, create_incident
      add :status, :string, null: false # pending, in_progress, completed, failed
      add :triggered_at, :utc_datetime, null: false
      add :completed_at, :utc_datetime
      add :error_message, :text
      add :actions_taken, {:array, :string}, default: []
      add :executed_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dark_web_response_workflows, [:credential_id])
    create index(:dark_web_response_workflows, [:intelligence_id])
    create index(:dark_web_response_workflows, [:status])
    create index(:dark_web_response_workflows, [:triggered_at])

    # Feed sync status
    create table(:dark_web_feed_status, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :feed_name, :string, null: false # hibp, intel471, flashpoint, custom
      add :last_sync, :utc_datetime
      add :last_error, :text
      add :status, :string, null: false # ok, error, syncing
      add :items_synced, :integer, default: 0
      add :next_sync, :utc_datetime

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:dark_web_feed_status, [:feed_name])
  end
end
