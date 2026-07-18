defmodule TamanduaServer.Telemetry.EventModel do
  @moduledoc """
  Runtime entry point for the versioned Tamandua event envelope.

  The normative JSON Schema is `schemas/event_envelope_v1.schema.json`.
  """

  @version "tamandua.io/event-envelope/v1"
  @required_routing ~w(tenant_id agent_id platform collector_id event_type observed_at ingested_at)
  @required_event ~w(category action outcome)
  @outcomes ~w(success failure unknown)

  def version, do: @version

  def descriptor do
    %{
      version: @version,
      schema: "schemas/event_envelope_v1.schema.json",
      compatibility: "additive_within_major",
      required: %{routing: @required_routing, event: @required_event}
    }
  end

  def validate(envelope) when is_map(envelope) do
    routing = value(envelope, "routing")
    event = value(envelope, "event")

    errors =
      []
      |> add(value(envelope, "schema_version") == @version, "schema_version", "unsupported")
      |> add(is_map(routing), "routing", "must_be_object")
      |> add(is_map(event), "event", "must_be_object")
      |> require_fields("routing", routing, @required_routing)
      |> require_fields("event", event, @required_event)
      |> validate_outcome(event)
      |> Enum.reverse()

    if errors == [], do: :ok, else: {:error, errors}
  end

  def validate(_), do: {:error, [%{path: "$", reason: "must_be_object"}]}

  defp require_fields(errors, _prefix, value, _fields) when not is_map(value), do: errors

  defp require_fields(errors, prefix, value, fields) do
    Enum.reduce(fields, errors, fn field, acc ->
      add(acc, present?(value(value, field)), "#{prefix}.#{field}", "required")
    end)
  end

  defp validate_outcome(errors, event) when is_map(event) do
    outcome = value(event, "outcome")
    add(errors, is_nil(outcome) or outcome in @outcomes, "event.outcome", "invalid")
  end

  defp validate_outcome(errors, _), do: errors
  defp add(errors, true, _path, _reason), do: errors
  defp add(errors, false, path, reason), do: [%{path: path, reason: reason} | errors]

  defp value(map, key),
    do:
      Enum.find_value(map, fn {candidate, value} -> if to_string(candidate) == key, do: value end)

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(nil), do: false
  defp present?(_), do: true
end
