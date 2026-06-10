defmodule TamanduaServer.Detection.ExclusionRule do
  @moduledoc """
  Schema for alert exclusion/suppression rules.

  Exclusion rules allow SOC analysts to suppress specific alert patterns
  to reduce noise and focus on actionable threats.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "exclusion_rules" do
    field :name, :string
    field :description, :string
    field :enabled, :boolean, default: true

    # Rule type: whitelist, suppress, tune
    field :rule_type, :string

    # Match criteria (JSONB)
    field :criteria, :map, default: %{}

    # Specific pattern matchers
    field :hash_patterns, {:array, :string}, default: []
    field :path_patterns, {:array, :string}, default: []
    field :cmdline_patterns, {:array, :string}, default: []
    field :ip_patterns, {:array, :string}, default: []
    field :domain_patterns, {:array, :string}, default: []
    field :rule_name_patterns, {:array, :string}, default: []

    # Source/destination filters
    field :source_agent_ids, {:array, :binary_id}, default: []
    field :source_hostnames, {:array, :string}, default: []

    # Time-based suppression
    field :time_based, :boolean, default: false
    field :active_start, :time
    field :active_end, :time
    field :active_days, {:array, :integer}, default: []  # 1-7 for Mon-Sun

    # Expiration
    field :expires_at, :utc_datetime

    # Severity adjustment (for tuning)
    field :adjust_severity, :string  # nil, "low", "medium", "high", "critical"

    # Stats
    field :match_count, :integer, default: 0
    field :last_matched_at, :utc_datetime

    belongs_to :organization, Organization
    belongs_to :created_by, User, foreign_key: :created_by_id

    timestamps()
  end

  @valid_rule_types ~w(whitelist suppress tune)
  @valid_severities ~w(low medium high critical info)

  @doc false
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :name,
      :description,
      :enabled,
      :rule_type,
      :criteria,
      :hash_patterns,
      :path_patterns,
      :cmdline_patterns,
      :ip_patterns,
      :domain_patterns,
      :rule_name_patterns,
      :source_agent_ids,
      :source_hostnames,
      :time_based,
      :active_start,
      :active_end,
      :active_days,
      :expires_at,
      :adjust_severity,
      :match_count,
      :last_matched_at,
      :organization_id,
      :created_by_id
    ])
    |> validate_required([:name, :rule_type])
    |> validate_inclusion(:rule_type, @valid_rule_types)
    |> validate_inclusion(:adjust_severity, @valid_severities ++ [nil])
    |> validate_time_based_fields()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
  end

  defp validate_time_based_fields(changeset) do
    if get_field(changeset, :time_based) do
      changeset
      |> validate_required([:active_start, :active_end])
    else
      changeset
    end
  end

  @doc """
  Check if an event matches this exclusion rule.
  """
  def matches?(%__MODULE__{enabled: false}, _event), do: false

  def matches?(%__MODULE__{} = rule, event) do
    with true <- check_expiration(rule),
         true <- check_time_window(rule),
         true <- check_criteria(rule, event) do
      true
    else
      _ -> false
    end
  end

  defp check_expiration(%{expires_at: nil}), do: true
  defp check_expiration(%{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :lt
  end

  defp check_time_window(%{time_based: false}), do: true
  defp check_time_window(%{time_based: true, active_start: start, active_end: end_time, active_days: days}) do
    now = DateTime.utc_now()
    current_time = DateTime.to_time(now)
    current_day = Date.day_of_week(DateTime.to_date(now))

    day_matches = days == [] or current_day in days
    time_matches = Time.compare(current_time, start) != :lt and Time.compare(current_time, end_time) != :gt

    day_matches and time_matches
  end

  defp check_criteria(%{criteria: criteria} = rule, event) when criteria == %{} do
    check_patterns(rule, event)
  end

  defp check_criteria(%{criteria: criteria} = rule, event) do
    criteria_match = Enum.all?(criteria, fn {key, value} ->
      event_value = get_in(event, String.split(to_string(key), "."))
      matches_value?(event_value, value)
    end)

    criteria_match and check_patterns(rule, event)
  end

  defp check_patterns(rule, event) do
    checks = [
      {rule.hash_patterns, get_event_hash(event)},
      {rule.path_patterns, get_event_path(event)},
      {rule.cmdline_patterns, get_event_cmdline(event)},
      {rule.ip_patterns, get_event_ip(event)},
      {rule.domain_patterns, get_event_domain(event)},
      {rule.rule_name_patterns, get_event_rule_name(event)},
      {rule.source_agent_ids, [event["agent_id"] || event[:agent_id]]},
      {rule.source_hostnames, [event["hostname"] || event[:hostname]]}
    ]

    Enum.all?(checks, fn {patterns, values} ->
      patterns == [] or Enum.any?(values, &matches_any_pattern?(&1, patterns))
    end)
  end

  defp get_event_hash(event) do
    [
      get_in(event, ["payload", "sha256"]),
      get_in(event, [:payload, :sha256]),
      get_in(event, ["evidence", "process", "sha256"]),
      get_in(event, [:evidence, :process, :sha256])
    ] |> Enum.filter(&(&1 != nil))
  end

  defp get_event_path(event) do
    [
      get_in(event, ["payload", "path"]),
      get_in(event, [:payload, :path]),
      get_in(event, ["evidence", "process", "path"]),
      get_in(event, [:evidence, :process, :path])
    ] |> Enum.filter(&(&1 != nil))
  end

  defp get_event_cmdline(event) do
    [
      get_in(event, ["payload", "cmdline"]),
      get_in(event, [:payload, :cmdline]),
      get_in(event, ["evidence", "process", "cmdline"]),
      get_in(event, [:evidence, :process, :cmdline])
    ] |> Enum.filter(&(&1 != nil))
  end

  defp get_event_ip(event) do
    [
      get_in(event, ["payload", "dest_ip"]),
      get_in(event, [:payload, :dest_ip]),
      get_in(event, ["payload", "src_ip"]),
      get_in(event, [:payload, :src_ip])
    ] |> Enum.filter(&(&1 != nil))
  end

  defp get_event_domain(event) do
    [
      get_in(event, ["payload", "domain"]),
      get_in(event, [:payload, :domain]),
      get_in(event, ["payload", "hostname"]),
      get_in(event, [:payload, :hostname])
    ] |> Enum.filter(&(&1 != nil))
  end

  defp get_event_rule_name(event) do
    [
      get_in(event, ["detection_metadata", "rule_name"]),
      get_in(event, [:detection_metadata, :rule_name])
    ] |> Enum.filter(&(&1 != nil))
  end

  defp matches_value?(nil, _), do: false
  defp matches_value?(actual, expected) when is_list(expected), do: actual in expected
  defp matches_value?(actual, expected), do: actual == expected

  defp matches_any_pattern?(nil, _), do: false
  defp matches_any_pattern?(value, patterns) when is_binary(value) do
    Enum.any?(patterns, fn pattern ->
      cond do
        String.starts_with?(pattern, "regex:") ->
          regex = String.trim_leading(pattern, "regex:")
          case Regex.compile(regex, [:caseless]) do
            {:ok, re} -> Regex.match?(re, value)
            _ -> false
          end

        String.contains?(pattern, "*") ->
          regex = pattern
            |> String.replace(".", "\\.")
            |> String.replace("*", ".*")
          case Regex.compile("^#{regex}$", [:caseless]) do
            {:ok, re} -> Regex.match?(re, value)
            _ -> false
          end

        true ->
          String.downcase(value) == String.downcase(pattern)
      end
    end)
  end
  defp matches_any_pattern?(value, patterns), do: to_string(value) in patterns
end
