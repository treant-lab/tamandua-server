defmodule TamanduaServer.Notifications.Integration do
  @moduledoc """
  Schema for notification integrations (Slack, Teams, Email, PagerDuty, etc.).

  Stores provider-specific configuration, templates, routing rules, and health metrics.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @providers ~w(slack teams email pagerduty opsgenie discord telegram)
  @default_title_template "Alert: {{ alert.title }}"
  @default_body_template """
  Severity: {{ alert.severity }}
  Agent: {{ agent.hostname }}
  Time: {{ alert.inserted_at }}

  {{ alert.description }}
  """

  schema "notification_integrations" do
    field :name, :string
    field :provider, :string
    field :enabled, :boolean, default: true

    # Provider-specific config (will be encrypted at rest)
    field :config, :map

    # Template configuration (Liquid/Mustache syntax)
    field :template_title, :string, default: @default_title_template
    field :template_body, :string, default: @default_body_template

    # Routing rules (filter which alerts trigger this integration)
    field :routing_rules, :map, default: %{}

    # Throttling
    field :throttle_enabled, :boolean, default: false
    field :throttle_max_per_hour, :integer, default: 60

    # Health tracking
    field :last_success_at, :utc_datetime_usec
    field :last_failure_at, :utc_datetime_usec
    field :failure_count, :integer, default: 0
    field :total_sent, :integer, default: 0
    field :total_failed, :integer, default: 0

    belongs_to :organization, TamanduaServer.Accounts.Organization
    has_many :delivery_logs, TamanduaServer.Notifications.DeliveryLog

    timestamps()
  end

  @doc """
  Changeset for creating/updating integrations.
  """
  def changeset(integration, attrs) do
    integration
    |> cast(attrs, [
      :name,
      :provider,
      :enabled,
      :config,
      :template_title,
      :template_body,
      :routing_rules,
      :throttle_enabled,
      :throttle_max_per_hour,
      :organization_id
    ])
    |> validate_required([:name, :provider, :config, :organization_id])
    |> validate_inclusion(:provider, @providers)
    |> validate_number(:throttle_max_per_hour, greater_than: 0, less_than: 1000)
    |> validate_config()
    |> validate_templates()
    |> unique_constraint([:organization_id, :name])
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for updating health metrics.
  """
  def health_changeset(integration, attrs) do
    integration
    |> cast(attrs, [
      :last_success_at,
      :last_failure_at,
      :failure_count,
      :total_sent,
      :total_failed
    ])
  end

  @doc """
  Validate provider-specific configuration.
  """
  defp validate_config(changeset) do
    provider = get_field(changeset, :provider)
    config = get_field(changeset, :config)

    case {provider, config} do
      {nil, _} -> changeset
      {_, nil} -> add_error(changeset, :config, "can't be blank")
      {"slack", config} -> validate_slack_config(changeset, config)
      {"teams", config} -> validate_teams_config(changeset, config)
      {"email", config} -> validate_email_config(changeset, config)
      {"pagerduty", config} -> validate_pagerduty_config(changeset, config)
      {"opsgenie", config} -> validate_opsgenie_config(changeset, config)
      {"discord", config} -> validate_discord_config(changeset, config)
      {"telegram", config} -> validate_telegram_config(changeset, config)
      _ -> changeset
    end
  end

  defp validate_slack_config(changeset, config) do
    cond do
      Map.has_key?(config, "webhook_url") or Map.has_key?(config, :webhook_url) ->
        changeset

      Map.has_key?(config, "oauth_token") or Map.has_key?(config, :oauth_token) ->
        changeset

      true ->
        add_error(changeset, :config, "must include webhook_url or oauth_token")
    end
  end

  defp validate_teams_config(changeset, config) do
    if Map.has_key?(config, "webhook_url") or Map.has_key?(config, :webhook_url) do
      changeset
    else
      add_error(changeset, :config, "must include webhook_url")
    end
  end

  defp validate_email_config(changeset, config) do
    required_keys = ["smtp_host", "smtp_port", "username", "password", "from"]
    atom_keys = [:smtp_host, :smtp_port, :username, :password, :from]

    has_all = Enum.all?(required_keys, &Map.has_key?(config, &1)) or
              Enum.all?(atom_keys, &Map.has_key?(config, &1))

    if has_all do
      changeset
    else
      add_error(changeset, :config, "must include smtp_host, smtp_port, username, password, from")
    end
  end

  defp validate_pagerduty_config(changeset, config) do
    if Map.has_key?(config, "integration_key") or Map.has_key?(config, :integration_key) do
      changeset
    else
      add_error(changeset, :config, "must include integration_key")
    end
  end

  defp validate_opsgenie_config(changeset, config) do
    if Map.has_key?(config, "api_key") or Map.has_key?(config, :api_key) do
      changeset
    else
      add_error(changeset, :config, "must include api_key")
    end
  end

  defp validate_discord_config(changeset, config) do
    if Map.has_key?(config, "webhook_url") or Map.has_key?(config, :webhook_url) do
      changeset
    else
      add_error(changeset, :config, "must include webhook_url")
    end
  end

  defp validate_telegram_config(changeset, config) do
    required = ["bot_token", "chat_id"]
    atom_required = [:bot_token, :chat_id]

    has_all = Enum.all?(required, &Map.has_key?(config, &1)) or
              Enum.all?(atom_required, &Map.has_key?(config, &1))

    if has_all do
      changeset
    else
      add_error(changeset, :config, "must include bot_token and chat_id")
    end
  end

  defp validate_templates(changeset) do
    # Basic template syntax validation
    # In a production system, you'd use Solid (Liquid parser) or BBMustache
    changeset
  end

  @doc """
  Get list of supported providers.
  """
  def providers, do: @providers

  @doc """
  Get default templates for a provider.
  """
  def default_templates(provider) do
    case provider do
      "slack" -> slack_templates()
      "teams" -> teams_templates()
      "email" -> email_templates()
      "pagerduty" -> pagerduty_templates()
      "opsgenie" -> opsgenie_templates()
      "discord" -> discord_templates()
      "telegram" -> telegram_templates()
      _ -> %{title: @default_title_template, body: @default_body_template}
    end
  end

  defp slack_templates do
    %{
      title: "*{{ alert.severity | upcase }}*: {{ alert.title }}",
      body: """
      :warning: *Alert from Tamandua EDR*

      *Severity:* {{ alert.severity | upcase }}
      *Agent:* {{ agent.hostname }} ({{ agent.os_type }})
      *MITRE Technique:* {{ alert.mitre_technique }}
      *Time:* {{ alert.inserted_at | date: "%Y-%m-%d %H:%M:%S UTC" }}

      {{ alert.description }}

      <{{ dashboard_url }}/alerts/{{ alert.id }}|View Alert>
      """
    }
  end

  defp teams_templates do
    %{
      title: "{{ alert.severity | upcase }}: {{ alert.title }}",
      body: """
      **Alert from Tamandua EDR**

      **Severity:** {{ alert.severity | upcase }}
      **Agent:** {{ agent.hostname }} ({{ agent.os_type }})
      **MITRE Technique:** {{ alert.mitre_technique }}
      **Time:** {{ alert.inserted_at | date: "%Y-%m-%d %H:%M:%S UTC" }}

      {{ alert.description }}

      [View Alert]({{ dashboard_url }}/alerts/{{ alert.id }})
      """
    }
  end

  defp email_templates do
    %{
      title: "[Tamandua EDR] {{ alert.severity | upcase }}: {{ alert.title }}",
      body: """
      Alert from Tamandua EDR

      Severity: {{ alert.severity | upcase }}
      Agent: {{ agent.hostname }} ({{ agent.os_type }})
      MITRE Technique: {{ alert.mitre_technique }}
      Time: {{ alert.inserted_at | date: "%Y-%m-%d %H:%M:%S UTC" }}

      Description:
      {{ alert.description }}

      View Alert: {{ dashboard_url }}/alerts/{{ alert.id }}
      """
    }
  end

  defp pagerduty_templates do
    %{
      title: "{{ alert.severity | upcase }}: {{ alert.title }}",
      body: """
      Agent: {{ agent.hostname }}
      MITRE: {{ alert.mitre_technique }}
      {{ alert.description }}
      """
    }
  end

  defp opsgenie_templates do
    %{
      title: "{{ alert.severity | upcase }}: {{ alert.title }}",
      body: """
      Agent: {{ agent.hostname }} ({{ agent.os_type }})
      MITRE Technique: {{ alert.mitre_technique }}
      Time: {{ alert.inserted_at | date: "%Y-%m-%d %H:%M:%S UTC" }}

      {{ alert.description }}
      """
    }
  end

  defp discord_templates do
    %{
      title: "**{{ alert.severity | upcase }}**: {{ alert.title }}",
      body: """
      **Alert from Tamandua EDR**

      **Severity:** {{ alert.severity | upcase }}
      **Agent:** {{ agent.hostname }} ({{ agent.os_type }})
      **MITRE Technique:** {{ alert.mitre_technique }}
      **Time:** {{ alert.inserted_at | date: "%Y-%m-%d %H:%M:%S UTC" }}

      {{ alert.description }}

      [View Alert]({{ dashboard_url }}/alerts/{{ alert.id }})
      """
    }
  end

  defp telegram_templates do
    %{
      title: "🚨 {{ alert.severity | upcase }}: {{ alert.title }}",
      body: """
      <b>Alert from Tamandua EDR</b>

      <b>Severity:</b> {{ alert.severity | upcase }}
      <b>Agent:</b> {{ agent.hostname }} ({{ agent.os_type }})
      <b>MITRE Technique:</b> {{ alert.mitre_technique }}
      <b>Time:</b> {{ alert.inserted_at | date: "%Y-%m-%d %H:%M:%S UTC" }}

      {{ alert.description }}

      <a href="{{ dashboard_url }}/alerts/{{ alert.id }}">View Alert</a>
      """
    }
  end
end
