defmodule TamanduaServer.LiveResponse.ScreenCapturePolicy do
  @moduledoc """
  Read-only resolver for the effective agent screen-capture policy.

  Missing or malformed policy is always normalized to `disabled`. The evidence
  identifier describes the effective merge and is not presented as a database
  policy ID because `PolicyManager.compute_effective_policy/1` does not retain
  provenance.
  """

  alias TamanduaServer.Agents.PolicyManager

  @modes ~w(silent notify consent_required disabled)
  @notify_timings ~w(before_capture after_capture)
  @capture_scopes ~w(virtual_desktop monitor active_window)
  @resolution_ttl_seconds 300
  @policy_hash_algorithm "screen_capture_policy_hash_sha256_lexical_v2"

  @spec resolve(String.t()) :: map()
  def resolve(agent_id) do
    case PolicyManager.compute_effective_policy(agent_id) do
      {:ok, effective_policy} -> normalize(agent_id, effective_policy)
      _ -> normalize(agent_id, %{})
    end
  rescue
    _ -> normalize(agent_id, %{})
  end

  @spec normalize(String.t(), map()) :: map()
  def normalize(agent_id, effective_policy) when is_map(effective_policy) do
    response = map_get_any(effective_policy, [:response, "response"])
    config = map_get_any(response, [:screen_capture, "screen_capture"])
    {mode, notify_timing, allowed_scopes, redaction_required, source} = normalize_config(config)

    canonical =
      "mode=#{mode};notify_timing=#{notify_timing || "none"};allowed_scopes=#{Enum.join(allowed_scopes, ",")};redaction_required=#{redaction_required}"

    hash = :crypto.hash(:sha256, canonical) |> Base.encode16(case: :lower)
    issued_at = DateTime.utc_now() |> DateTime.truncate(:second)

    policy_evidence = %{
      id: "effective:#{agent_id}",
      version: 1,
      hash: hash,
      source: source,
      issued_at: DateTime.to_iso8601(issued_at),
      expires_at:
        issued_at |> DateTime.add(@resolution_ttl_seconds, :second) |> DateTime.to_iso8601()
    }

    policy_evidence =
      if length(allowed_scopes) > 1,
        do: Map.put(policy_evidence, :hash_algorithm, @policy_hash_algorithm),
        else: policy_evidence

    %{
      mode: mode,
      notify_timing: notify_timing,
      allowed_scopes: allowed_scopes,
      redaction_required: redaction_required,
      policy: policy_evidence
    }
  end

  def normalize(agent_id, _effective_policy), do: normalize(agent_id, %{})

  def modes, do: @modes
  def notify_timings, do: @notify_timings
  def hash_algorithm, do: @policy_hash_algorithm

  @spec for_command(map(), pos_integer()) :: map()
  def for_command(policy, ttl_seconds) when is_map(policy) and is_integer(ttl_seconds) do
    issued_at_ms = System.system_time(:millisecond)

    command_ttl_seconds = min(ttl_seconds, @resolution_ttl_seconds)

    command_evidence = %{
      id: policy.policy.id,
      version: policy.policy.version,
      mode: policy.mode,
      notify_timing: policy.notify_timing,
      allowed_scopes: policy.allowed_scopes,
      redaction_required: policy.redaction_required,
      hash: policy.policy.hash,
      issued_at_ms: issued_at_ms,
      expires_at_ms: issued_at_ms + command_ttl_seconds * 1_000
    }

    command_evidence =
      case Map.get(policy.policy, :hash_algorithm) do
        @policy_hash_algorithm ->
          Map.put(command_evidence, :hash_algorithm, @policy_hash_algorithm)

        _ ->
          command_evidence
      end

    %{policy | policy: command_evidence}
  end

  @spec usable?(map()) :: boolean()
  def usable?(%{mode: mode, policy: %{issued_at: issued_at, expires_at: expires_at}})
      when mode in @modes do
    with {:ok, issued, _} <- DateTime.from_iso8601(issued_at),
         {:ok, expires, _} <- DateTime.from_iso8601(expires_at) do
      now = DateTime.utc_now()

      DateTime.compare(issued, DateTime.add(now, 60, :second)) != :gt and
        DateTime.compare(expires, now) == :gt
    else
      _ -> false
    end
  end

  def usable?(%{
        mode: mode,
        policy: %{issued_at_ms: issued_at_ms, expires_at_ms: expires_at_ms}
      })
      when mode in @modes and is_integer(issued_at_ms) and is_integer(expires_at_ms) do
    now_ms = System.system_time(:millisecond)
    issued_at_ms <= now_ms + 60_000 and expires_at_ms > now_ms
  end

  def usable?(_policy), do: false

  defp normalize_config(config) when is_map(config) do
    mode = map_get_any(config, [:mode, "mode"]) |> normalize_value()
    timing = map_get_any(config, [:notify_timing, "notify_timing"]) |> normalize_value()
    allowed_scopes = normalize_scopes(map_get_any(config, [:allowed_scopes, "allowed_scopes"]))

    redaction_required =
      map_get_any(config, [:redaction_required, "redaction_required"])
      |> normalize_boolean(false)

    cond do
      mode not in @modes ->
        fail_closed_config()

      mode == "notify" and timing not in @notify_timings ->
        fail_closed_config()

      allowed_scopes == :invalid or redaction_required == :invalid ->
        fail_closed_config()

      mode == "notify" ->
        {mode, timing, allowed_scopes, redaction_required, "effective_agent_policy"}

      true ->
        {mode, nil, allowed_scopes, redaction_required, "effective_agent_policy"}
    end
  end

  defp normalize_config(_config), do: fail_closed_config()

  defp fail_closed_config,
    do: {"disabled", nil, ["virtual_desktop"], false, "fail_closed_default"}

  defp normalize_scopes(nil), do: ["virtual_desktop"]

  defp normalize_scopes(scopes) when is_list(scopes) do
    normalized = scopes |> Enum.map(&normalize_value/1) |> Enum.uniq() |> Enum.sort()

    if normalized != [] and Enum.all?(normalized, &(&1 in @capture_scopes)),
      do: normalized,
      else: :invalid
  end

  defp normalize_scopes(_scopes), do: :invalid

  defp normalize_boolean(nil, fallback), do: fallback
  defp normalize_boolean(value, _fallback) when is_boolean(value), do: value
  defp normalize_boolean(_value, _fallback), do: :invalid

  defp normalize_value(nil), do: nil

  defp normalize_value(value),
    do: value |> to_string() |> String.downcase() |> String.replace("-", "_")

  defp map_get_any(map, keys) when is_map(map), do: Enum.find_value(keys, &Map.get(map, &1))
  defp map_get_any(_map, _keys), do: nil
end
