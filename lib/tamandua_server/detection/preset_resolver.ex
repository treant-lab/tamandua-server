defmodule TamanduaServer.Detection.PresetResolver do
  @moduledoc """
  Pure resolution + validation of FP-budget presets (Phase 66 / FPB-01, FPB-02).

  Presets are named tenant-profile bundles of EXISTING detection knobs. This module
  does not read ETS or the DB; callers pass in the parsed `presets:` map (from
  ThresholdConfig) and the org settings/license_tier. Keeps the resolution logic
  pure and unit-testable with no live data.
  """

  @preset_names ~w(soc-enterprise mssp mid-market)
  @fallback_preset "mid-market"

  # Knobs a preset is allowed to set, with [min, max] in-range validation bounds.
  @knob_ranges %{
    "threat_alert_threshold" => {0.5, 0.95},
    "threat_critical_threshold" => {0.75, 0.99},
    "risk_alert_threshold" => {50, 95},
    "suppression_occurrence_threshold" => {1, 50}
  }

  @doc "The three shipped preset names."
  def preset_names, do: @preset_names

  @doc "Hardcoded fallback preset name when nothing is configured."
  def fallback_preset, do: @fallback_preset

  @doc "Allowed knob keys for a preset."
  def knob_keys, do: Map.keys(@knob_ranges)

  @doc """
  Suggested default preset for a license tier. Suggestion only — an explicit
  Organization.settings["fp_preset"] always overrides this.
  """
  @spec suggested_for_tier(atom() | String.t()) :: String.t()
  def suggested_for_tier(:enterprise), do: "soc-enterprise"
  def suggested_for_tier("enterprise"), do: "soc-enterprise"
  def suggested_for_tier(:pro), do: "mssp"
  def suggested_for_tier("pro"), do: "mssp"
  def suggested_for_tier(:trial), do: "mid-market"
  def suggested_for_tier("trial"), do: "mid-market"
  def suggested_for_tier(_), do: @fallback_preset

  @doc """
  Resolve the active preset NAME and its source.

  Order: org settings["fp_preset"] -> global configured default -> mid-market fallback.
  Returns {preset_name, source} where source is :org | :global | :fallback.
  A blank/unknown org value is ignored (falls through to global/fallback).
  """
  @spec resolve_name(map() | nil, String.t() | nil) :: {String.t(), :org | :global | :fallback}
  def resolve_name(org_settings, global_default) do
    org_choice = org_settings && Map.get(org_settings, "fp_preset")

    cond do
      is_binary(org_choice) and org_choice in @preset_names ->
        {org_choice, :org}

      is_binary(global_default) and global_default in @preset_names ->
        {global_default, :global}

      true ->
        {@fallback_preset, :fallback}
    end
  end

  @doc """
  Resolve the full effective preset map for an org.

  `presets_block` is the parsed `presets:` map from the YAML (string keys).
  Returns {:ok, name, source, knobs_map} or {:error, reason}. `knobs_map` has
  string knob keys -> numeric values, validated in-range.
  """
  @spec resolve_preset(map(), map() | nil, String.t() | nil) ::
          {:ok, String.t(), :org | :global | :fallback, map()} | {:error, term()}
  def resolve_preset(presets_block, org_settings, global_default_override \\ nil) do
    global_default = global_default_override || Map.get(presets_block, "default")
    {name, source} = resolve_name(org_settings, global_default)

    case Map.get(presets_block, name) do
      nil ->
        {:error, {:unknown_preset, name}}

      preset_map when is_map(preset_map) ->
        knobs = Map.take(preset_map, knob_keys())

        case validate_preset(name, knobs) do
          :ok -> {:ok, name, source, knobs}
          {:error, _} = err -> err
        end
    end
  end

  @doc """
  Validate a preset: only known knob keys, all values numeric and in range.
  Returns :ok or {:error, {reason, detail}}.
  """
  @spec validate_preset(String.t(), map()) :: :ok | {:error, term()}
  def validate_preset(_name, knobs) when is_map(knobs) do
    unknown = Map.keys(knobs) -- knob_keys()

    cond do
      unknown != [] ->
        {:error, {:unknown_knobs, unknown}}

      true ->
        Enum.reduce_while(knobs, :ok, fn {k, v}, _acc ->
          {min, max} = Map.fetch!(@knob_ranges, k)

          if is_number(v) and v >= min and v <= max do
            {:cont, :ok}
          else
            {:halt, {:error, {:out_of_range, k, v, {min, max}}}}
          end
        end)
    end
  end
end
