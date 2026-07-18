defmodule TamanduaServer.ThreatIntel.EmergingThreat do
  @moduledoc """
  Pure contract for emerging threat intelligence records.

  This module intentionally does not depend on Ecto or runtime processes. It is
  meant to normalize and score records assembled from existing feeds, analysts,
  or derived threat-intel pipelines before another layer decides where to store
  or expose them.
  """

  @enforce_keys [:id, :title, :summary, :category]
  defstruct [
    :id,
    :title,
    :summary,
    :category,
    :status,
    :severity,
    :confidence,
    :sources,
    :iocs,
    :ttps,
    :affected_products,
    :first_seen,
    :last_seen,
    :exploit_maturity,
    :local_relevance_score,
    :recommended_hunts,
    :recommended_actions,
    :coverage_gaps
  ]

  @type source :: %{
          optional(:name) => String.t(),
          optional(:url) => String.t(),
          optional(:type) => String.t(),
          optional(:published_at) => DateTime.t() | Date.t() | String.t(),
          optional(atom()) => term()
        }

  @type t :: %__MODULE__{
          id: String.t(),
          title: String.t(),
          summary: String.t(),
          category: String.t(),
          status: String.t(),
          severity: String.t(),
          confidence: float(),
          sources: [source()],
          iocs: [map()],
          ttps: [String.t() | map()],
          affected_products: [String.t() | map()],
          first_seen: DateTime.t() | Date.t() | String.t() | nil,
          last_seen: DateTime.t() | Date.t() | String.t() | nil,
          exploit_maturity: String.t(),
          local_relevance_score: non_neg_integer(),
          recommended_hunts: [String.t() | map()],
          recommended_actions: [String.t() | map()],
          coverage_gaps: [String.t() | map()]
        }

  @statuses ~w(new monitoring investigating validated archived)
  @severities ~w(info low medium high critical)
  @exploit_maturities ~w(unknown theoretical poc weaponized exploited widespread)
  @required_fields [:id, :title, :summary, :category]
  @list_fields [
    :sources,
    :iocs,
    :ttps,
    :affected_products,
    :recommended_hunts,
    :recommended_actions,
    :coverage_gaps
  ]

  @maturity_scores %{
    "unknown" => 10,
    "theoretical" => 25,
    "poc" => 45,
    "weaponized" => 65,
    "exploited" => 85,
    "widespread" => 100
  }

  @doc """
  Builds and validates an emerging threat from atom or string keyed attributes.
  """
  @spec new(map()) :: {:ok, t()} | {:error, map()}
  def new(attrs) when is_map(attrs) do
    attrs
    |> normalize_attrs()
    |> apply_defaults()
    |> validate_attrs()
    |> case do
      {:ok, normalized} -> {:ok, struct!(__MODULE__, normalized)}
      {:error, errors} -> {:error, errors}
    end
  end

  @doc """
  Builds a threat and raises on invalid input.
  """
  @spec new!(map()) :: t()
  def new!(attrs) do
    case new(attrs) do
      {:ok, threat} -> threat
      {:error, errors} -> raise ArgumentError, "invalid emerging threat: #{inspect(errors)}"
    end
  end

  @doc """
  Alias for `new/1` for callers assembling records from decoded JSON.
  """
  @spec from_map(map()) :: {:ok, t()} | {:error, map()}
  def from_map(attrs), do: new(attrs)

  @doc """
  Serializes the contract to an atom-keyed map.

  Pass `include_score: true` to include a deterministic `:score` and
  `:score_breakdown` for API read models without changing the core struct.
  """
  @spec to_map(t(), keyword()) :: map()
  def to_map(%__MODULE__{} = threat, opts \\ []) do
    base =
      threat
      |> Map.from_struct()
      |> Map.take(fields())

    if Keyword.get(opts, :include_score, false) do
      Map.merge(base, score(threat))
    else
      base
    end
  end

  @doc """
  Serializes the contract to a JSON-friendly string-keyed map.
  """
  @spec to_json_map(t(), keyword()) :: map()
  def to_json_map(%__MODULE__{} = threat, opts \\ []) do
    threat
    |> to_map(opts)
    |> stringify_keys()
  end

  @doc """
  Returns the stable contract fields in serialization order.
  """
  @spec fields() :: [atom()]
  def fields do
    [
      :id,
      :title,
      :summary,
      :category,
      :status,
      :severity,
      :confidence,
      :sources,
      :iocs,
      :ttps,
      :affected_products,
      :first_seen,
      :last_seen,
      :exploit_maturity,
      :local_relevance_score,
      :recommended_hunts,
      :recommended_actions,
      :coverage_gaps
    ]
  end

  @doc """
  Calculates a deterministic priority score in the 0..100 range.

  The score combines exploit maturity, confidence, local relevance, source
  count, and active exploitation hints. The returned breakdown is intentionally
  explicit so downstream ranking decisions can be inspected.
  """
  @spec score(t() | map()) :: %{score: non_neg_integer(), score_breakdown: map()}
  def score(%__MODULE__{} = threat) do
    maturity_score = Map.fetch!(@maturity_scores, threat.exploit_maturity)
    confidence_score = round(threat.confidence * 100)
    local_score = clamp_int(threat.local_relevance_score, 0, 100)
    source_score = source_count_score(threat.sources)
    active_score = active_exploitation_score(threat)

    score =
      maturity_score * 0.35 +
        confidence_score * 0.20 +
        local_score * 0.20 +
        source_score * 0.10 +
        active_score * 0.15

    %{
      score: score |> round() |> clamp_int(0, 100),
      score_breakdown: %{
        exploit_maturity: maturity_score,
        confidence: confidence_score,
        local_relevance: local_score,
        source_count: source_score,
        active_exploitation_hints: active_score,
        weights: %{
          exploit_maturity: 0.35,
          confidence: 0.20,
          local_relevance: 0.20,
          source_count: 0.10,
          active_exploitation_hints: 0.15
        }
      }
    }
  end

  def score(attrs) when is_map(attrs) do
    attrs
    |> new!()
    |> score()
  end

  @doc """
  Returns a severity derived from the deterministic score.
  """
  @spec severity_for_score(integer()) :: String.t()
  def severity_for_score(score) when score >= 85, do: "critical"
  def severity_for_score(score) when score >= 70, do: "high"
  def severity_for_score(score) when score >= 45, do: "medium"
  def severity_for_score(score) when score >= 20, do: "low"
  def severity_for_score(_score), do: "info"

  defp normalize_attrs(attrs) do
    Enum.reduce(fields(), %{}, fn field, normalized ->
      value = Map.get(attrs, field, Map.get(attrs, Atom.to_string(field)))
      Map.put(normalized, field, value)
    end)
  end

  defp apply_defaults(attrs) do
    attrs
    |> Map.update!(:status, &normalize_string(&1, "new"))
    |> Map.update!(:severity, &normalize_string(&1, "medium"))
    |> Map.update!(:confidence, &normalize_float(&1, 0.0))
    |> Map.update!(:exploit_maturity, &normalize_string(&1, "unknown"))
    |> Map.update!(:local_relevance_score, &normalize_integer(&1, 0))
    |> normalize_lists()
  end

  defp normalize_lists(attrs) do
    Enum.reduce(@list_fields, attrs, fn field, normalized ->
      Map.update!(normalized, field, &List.wrap(&1))
    end)
  end

  defp validate_attrs(attrs) do
    errors =
      %{}
      |> require_fields(attrs)
      |> validate_inclusion(attrs, :status, @statuses)
      |> validate_inclusion(attrs, :severity, @severities)
      |> validate_inclusion(attrs, :exploit_maturity, @exploit_maturities)
      |> validate_range(attrs, :confidence, 0.0, 1.0)
      |> validate_range(attrs, :local_relevance_score, 0, 100)

    if map_size(errors) == 0 do
      {:ok, attrs}
    else
      {:error, errors}
    end
  end

  defp require_fields(errors, attrs) do
    Enum.reduce(@required_fields, errors, fn field, acc ->
      case Map.fetch!(attrs, field) do
        value when is_binary(value) ->
          if String.trim(value) == "", do: Map.put(acc, field, "is required"), else: acc

        nil ->
          Map.put(acc, field, "is required")

        _value ->
          acc
      end
    end)
  end

  defp validate_inclusion(errors, attrs, field, allowed) do
    if Map.fetch!(attrs, field) in allowed do
      errors
    else
      Map.put(errors, field, "must be one of: #{Enum.join(allowed, ", ")}")
    end
  end

  defp validate_range(errors, attrs, field, min, max) do
    value = Map.fetch!(attrs, field)

    if is_number(value) and value >= min and value <= max do
      errors
    else
      Map.put(errors, field, "must be between #{min} and #{max}")
    end
  end

  defp normalize_string(nil, default), do: default
  defp normalize_string(value, _default) when is_atom(value), do: value |> Atom.to_string() |> String.downcase()
  defp normalize_string(value, _default) when is_binary(value), do: value |> String.trim() |> String.downcase()
  defp normalize_string(_value, default), do: default

  defp normalize_float(nil, default), do: default
  defp normalize_float(value, _default) when is_float(value), do: value
  defp normalize_float(value, _default) when is_integer(value), do: value / 1

  defp normalize_float(value, default) when is_binary(value) do
    case Float.parse(value) do
      {parsed, ""} -> parsed
      _error -> default
    end
  end

  defp normalize_float(_value, default), do: default

  defp normalize_integer(nil, default), do: default
  defp normalize_integer(value, _default) when is_integer(value), do: value
  defp normalize_integer(value, _default) when is_float(value), do: round(value)

  defp normalize_integer(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} -> parsed
      _error -> default
    end
  end

  defp normalize_integer(_value, default), do: default

  defp source_count_score(sources) do
    sources
    |> Enum.map(&source_identity/1)
    |> Enum.uniq()
    |> length()
    |> min(5)
    |> Kernel.*(20)
  end

  defp source_identity(%{} = source) do
    source[:name] || source["name"] || source[:url] || source["url"] || inspect(source)
  end

  defp source_identity(source), do: source

  defp active_exploitation_score(threat) do
    hint_count =
      [
        threat.exploit_maturity in ["exploited", "widespread"],
        text_has_active_hint?(threat.title),
        text_has_active_hint?(threat.summary),
        Enum.any?(threat.sources, &source_has_active_hint?/1)
      ]
      |> Enum.count(& &1)

    hint_count
    |> min(3)
    |> Kernel.*(100)
    |> div(3)
  end

  defp source_has_active_hint?(%{} = source) do
    truthy?(source[:active_exploitation] || source["active_exploitation"]) ||
      truthy?(source[:observed_in_the_wild] || source["observed_in_the_wild"]) ||
      text_has_active_hint?(source[:summary] || source["summary"] || source[:notes] || source["notes"]) ||
      Enum.any?(List.wrap(source[:tags] || source["tags"]), &text_has_active_hint?/1)
  end

  defp source_has_active_hint?(source), do: text_has_active_hint?(source)

  defp text_has_active_hint?(value) when is_binary(value) do
    normalized = String.downcase(value)

    Enum.any?(
      [
        "active exploitation",
        "actively exploited",
        "exploited in the wild",
        "observed in the wild",
        "mass exploitation",
        "ransomware"
      ],
      &String.contains?(normalized, &1)
    )
  end

  defp text_has_active_hint?(_value), do: false

  defp truthy?(value), do: value in [true, "true", "yes", "y", "1", 1]

  defp clamp_int(value, min, max), do: value |> max(min) |> min(max)

  defp stringify_keys(map) do
    Map.new(map, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), stringify_value(value)}
      {key, value} -> {key, stringify_value(value)}
    end)
  end

  defp stringify_value(value) when is_map(value), do: stringify_keys(value)
  defp stringify_value(value) when is_list(value), do: Enum.map(value, &stringify_value/1)
  defp stringify_value(value), do: value
end
