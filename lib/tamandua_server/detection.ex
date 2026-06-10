defmodule TamanduaServer.Detection do
  @moduledoc """
  Context module for detection rules management.

  Provides functions to query and manage:
  - YARA rules
  - Sigma rules
  - IOCs (Indicators of Compromise)
  - Rule distribution to agents
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.{YaraRule, SigmaRule, IOC, IOCs}
  alias TamanduaServer.Alerts.Alert

  @doc """
  Get top detected MITRE techniques from alerts.
  """
  def get_top_techniques(opts \\ []) do
    limit = Keyword.get(opts, :limit, 5)

    alerts = Repo.all(
      from a in Alert,
        where: not is_nil(a.mitre_techniques),
        select: a.mitre_techniques
    )

    alerts
    |> List.flatten()
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_tech, count} -> -count end)
    |> Enum.take(limit)
    |> Enum.map(fn {technique_id, count} ->
      name = get_technique_name(technique_id)
      {technique_id, name, count}
    end)
  end

  defp get_technique_name(technique_id) do
    case TamanduaServer.Detection.Mitre.get_technique(technique_id) do
      nil -> technique_id
      technique -> technique.name
    end
  end

  # -------------------------------------------------------------------
  # YARA Rules
  # -------------------------------------------------------------------

  @doc """
  List all enabled YARA rules for an organization.
  """
  def list_enabled_yara_rules(organization_id \\ nil) do
    YaraRule
    |> where([r], r.enabled == true)
    |> filter_by_org(organization_id)
    |> Repo.all()
  end

  @doc """
  List all enabled YARA rules formatted for agent distribution.
  Returns a list of maps with only the fields needed by agents.
  """
  def list_yara_rules_for_agent(organization_id \\ nil) do
    organization_id
    |> list_enabled_yara_rules()
    |> Enum.map(&YaraRule.to_agent_format/1)
  end

  @doc """
  Get a YARA rule by ID.
  """
  def get_yara_rule(id) do
    Repo.get(YaraRule, id)
  end

  @doc """
  Create a new YARA rule.
  """
  def create_yara_rule(attrs) do
    %YaraRule{}
    |> YaraRule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a YARA rule.
  """
  def update_yara_rule(%YaraRule{} = rule, attrs) do
    rule
    |> YaraRule.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a YARA rule.
  """
  def delete_yara_rule(%YaraRule{} = rule) do
    Repo.delete(rule)
  end

  # -------------------------------------------------------------------
  # Sigma Rules
  # -------------------------------------------------------------------

  @doc """
  List all Sigma rules.
  """
  def list_sigma_rules do
    Repo.all(SigmaRule)
  end

  @doc """
  List all enabled Sigma rules for an organization.
  """
  def list_enabled_sigma_rules(organization_id \\ nil) do
    SigmaRule
    |> where([r], r.enabled == true)
    |> filter_by_org(organization_id)
    |> Repo.all()
  end

  @doc """
  List all enabled Sigma rules formatted for agent distribution.
  Returns a list of maps with the compiled detection logic.
  """
  def list_sigma_rules_for_agent(organization_id \\ nil) do
    organization_id
    |> list_enabled_sigma_rules()
    |> Enum.map(&sigma_rule_to_agent_format/1)
  end

  @doc """
  Get a Sigma rule by ID.
  """
  def get_sigma_rule(id) do
    Repo.get(SigmaRule, id)
  end

  @doc """
  Create a new Sigma rule.
  """
  def create_sigma_rule(attrs) do
    %SigmaRule{}
    |> SigmaRule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a Sigma rule.
  """
  def update_sigma_rule(%SigmaRule{} = rule, attrs) do
    rule
    |> SigmaRule.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a Sigma rule.
  """
  def delete_sigma_rule(%SigmaRule{} = rule) do
    Repo.delete(rule)
  end

  @doc """
  Import a Sigma rule from YAML content.
  """
  def import_sigma_rule_from_yaml(yaml_content, organization_id \\ nil) do
    alias TamanduaServer.Detection.Rules.Sigma

    case Sigma.from_yaml(yaml_content) do
      {:ok, attrs} ->
        attrs = if organization_id, do: Map.put(attrs, :organization_id, organization_id), else: attrs
        create_sigma_rule(attrs)

      {:error, _} = error ->
        error
    end
  end

  # -------------------------------------------------------------------
  # IOCs (Indicators of Compromise)
  # -------------------------------------------------------------------

  @doc """
  List all enabled IOCs for an organization, formatted for agent distribution.

  Returns a list of maps with the fields needed by agents for local IOC matching:
  - `type`: The IOC type atom (:ip, :domain, :sha256, :sha1, :md5, :url, :email)
  - `value`: The normalized IOC value (lowercase)
  - `severity`: Severity level string
  - `description`: Human-readable description
  - `tags`: List of classification tags
  - `source`: Feed or manual source name

  ## Options
    - `:organization_id` - Filter to a specific organization (nil = global only)
    - `:limit` - Maximum IOCs to return (default: 50_000)
  """
  @spec list_iocs_for_agent(String.t() | nil) :: [map()]
  def list_iocs_for_agent(organization_id \\ nil) do
    query =
      from(i in IOC,
        where: i.enabled == true,
        order_by: [desc: i.severity, desc: i.inserted_at],
        limit: 50_000,
        select: %{
          type: i.type,
          value: i.value,
          severity: i.severity,
          description: i.description,
          source: i.source,
          tags: i.tags
        }
      )

    query =
      if organization_id do
        where(query, [i], i.organization_id == ^organization_id or is_nil(i.organization_id))
      else
        query
      end

    query
    |> Repo.all()
    |> Enum.map(&ioc_to_agent_format/1)
  rescue
    e ->
      require Logger
      Logger.error("[Detection] Failed to load IOCs for agent: #{Exception.message(e)}")
      []
  end

  @doc """
  Count enabled IOCs.
  """
  def count_iocs do
    IOCs.count(enabled: true)
  end

  defp ioc_to_agent_format(ioc) do
    %{
      type: normalize_ioc_type_for_agent(ioc.type),
      value: ioc.value,
      severity: ioc.severity || "medium",
      description: ioc.description || "IOC from threat feed",
      source: ioc.source,
      tags: ioc.tags || []
    }
  end

  # Normalizes database IOC type strings to the atom format agents expect
  defp normalize_ioc_type_for_agent(type) do
    case type do
      "hash_sha256" -> "sha256"
      "hash_sha1" -> "sha1"
      "hash_md5" -> "md5"
      "ip" -> "ip"
      "domain" -> "domain"
      "url" -> "url"
      "email" -> "email"
      "filename" -> "filename"
      other -> other
    end
  end

  # -------------------------------------------------------------------
  # Combined rule loading for agents
  # -------------------------------------------------------------------

  @doc """
  Get all detection rules for an agent.
  Returns a map with YARA rules, Sigma rules, and IOCs formatted for distribution.
  """
  def get_rules_for_agent(organization_id \\ nil) do
    %{
      yara_rules: list_yara_rules_for_agent(organization_id),
      sigma_rules: list_sigma_rules_for_agent(organization_id),
      iocs: list_iocs_for_agent(organization_id)
    }
  end

  # -------------------------------------------------------------------
  # Private functions
  # -------------------------------------------------------------------

  defp filter_by_org(query, nil) do
    # Return global rules (no organization) or all if no filter needed
    query
    |> where([r], is_nil(r.organization_id))
  end

  defp filter_by_org(query, organization_id) do
    # Return rules for specific org OR global rules
    query
    |> where([r], r.organization_id == ^organization_id or is_nil(r.organization_id))
  end

  defp sigma_rule_to_agent_format(%SigmaRule{} = rule) do
    logsource = rule.logsource || %{}

    %{
      id: rule.id,
      name: rule.name,
      description: rule.description,
      detection: rule.detection,
      logsource: logsource,
      logsource_category: Map.get(logsource, "category"),
      logsource_product: Map.get(logsource, "product"),
      tags: rule.tags || []
    }
  end

  @doc """
  Count detections from today.
  """
  def count_detections_today do
    today_start = DateTime.utc_now() |> DateTime.to_date() |> DateTime.new!(~T[00:00:00])

    from(a in Alert, where: a.inserted_at >= ^today_start)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Count enabled Sigma rules.
  """
  def count_sigma_rules do
    from(r in SigmaRule, where: r.enabled == true)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Count enabled YARA rules.
  """
  def count_yara_rules do
    from(r in YaraRule, where: r.enabled == true)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Count detections by severity.
  """
  def count_by_type do
    from(a in Alert,
      group_by: a.severity,
      select: {a.severity, count(a.id)}
    )
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Get top MITRE techniques by detection count.
  """
  def get_top_rules(opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)

    # Since we don't have rule_id, return top techniques as rules
    alerts = Repo.all(
      from a in Alert,
        where: not is_nil(a.mitre_techniques) and a.mitre_techniques != [],
        select: a.mitre_techniques
    )

    alerts
    |> List.flatten()
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_tech, count} -> -count end)
    |> Enum.take(limit)
    |> Enum.map(fn {technique_id, count} ->
      %{rule_id: technique_id, rule_name: get_technique_name(technique_id), count: count}
    end)
  end

  @doc """
  Get detection trend over time range.
  """
  def get_trend(time_range) do
    days = case time_range do
      "7d" -> 7
      "30d" -> 30
      "90d" -> 90
      _ -> 7
    end

    start_date = Date.utc_today() |> Date.add(-days)

    from(a in Alert,
      where: fragment("?::date", a.inserted_at) >= ^start_date,
      group_by: fragment("?::date", a.inserted_at),
      select: {fragment("?::date", a.inserted_at), count(a.id)},
      order_by: [asc: fragment("?::date", a.inserted_at)]
    )
    |> Repo.all()
    |> Enum.map(fn {date, count} -> %{date: Date.to_iso8601(date), count: count} end)
  end

  # ===========================================================================
  # Tenant-Scoped Functions
  # ===========================================================================

  @doc """
  Count detections from today for an organization.
  """
  def count_detections_today_for_org(organization_id) do
    today_start = DateTime.utc_now() |> DateTime.to_date() |> DateTime.new!(~T[00:00:00])

    from(a in Alert,
      where: a.inserted_at >= ^today_start and a.organization_id == ^organization_id
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Count detections by severity for an organization.
  """
  def count_by_type_for_org(organization_id) do
    from(a in Alert,
      where: a.organization_id == ^organization_id,
      group_by: a.severity,
      select: {a.severity, count(a.id)}
    )
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Get top MITRE techniques by detection count for an organization.
  """
  def get_top_rules_for_org(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)

    alerts = Repo.all(
      from a in Alert,
        where: a.organization_id == ^organization_id and
               not is_nil(a.mitre_techniques) and
               a.mitre_techniques != [],
        select: a.mitre_techniques
    )

    alerts
    |> List.flatten()
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_tech, count} -> -count end)
    |> Enum.take(limit)
    |> Enum.map(fn {technique_id, count} ->
      %{rule_id: technique_id, rule_name: get_technique_name(technique_id), count: count}
    end)
  end

  @doc """
  Get top detected MITRE techniques from alerts for an organization.
  """
  def get_top_techniques_for_org(organization_id, opts \\ []) do
    organization_id
    |> get_top_rules_for_org(opts)
    |> Enum.map(fn item ->
      {item.rule_id, item.rule_name, item.count}
    end)
  end

  @doc """
  Get detection trend over time range for an organization.
  """
  def get_trend_for_org(organization_id, time_range) do
    days = case time_range do
      "7d" -> 7
      "30d" -> 30
      "90d" -> 90
      _ -> 7
    end

    start_date = Date.utc_today() |> Date.add(-days)

    from(a in Alert,
      where: a.organization_id == ^organization_id and
             fragment("?::date", a.inserted_at) >= ^start_date,
      group_by: fragment("?::date", a.inserted_at),
      select: {fragment("?::date", a.inserted_at), count(a.id)},
      order_by: [asc: fragment("?::date", a.inserted_at)]
    )
    |> Repo.all()
    |> Enum.map(fn {date, count} -> %{date: Date.to_iso8601(date), count: count} end)
  end

  @doc """
  Get MITRE technique trends for an organization.
  """
  def get_mitre_trends_for_org(organization_id, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    _granularity = Keyword.get(opts, :granularity, "day")
    start_date = Date.utc_today() |> Date.add(-days)

    from(a in Alert,
      where: a.organization_id == ^organization_id and
             fragment("?::date", a.inserted_at) >= ^start_date and
             not is_nil(a.mitre_techniques) and
             a.mitre_techniques != [],
      select: {fragment("?::date", a.inserted_at), a.mitre_techniques}
    )
    |> Repo.all()
    |> Enum.group_by(fn {date, _techniques} -> date end, fn {_date, techniques} -> techniques end)
    |> Enum.map(fn {date, technique_lists} ->
      techniques = List.flatten(technique_lists)

      %{
        date: Date.to_iso8601(date),
        detections: length(techniques),
        techniques: Enum.uniq(techniques)
      }
    end)
    |> Enum.sort_by(& &1.date)
  end
end
