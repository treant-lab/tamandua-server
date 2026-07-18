defmodule TamanduaServer.LiveResponse.ScreenSessionBroker do
  @moduledoc """
  Read-only, fail-closed health contract for the interactive user-session broker.

  This module does not notify a user, obtain consent, or create a session. It only
  normalizes state already reported in agent config for API and UI surfaces.
  """

  @schema_version "tamandua.screen_session_broker/v1"
  @states ~w(
    ready
    no_user_session
    locked
    consent_required
    permission_denied
    portal_unavailable
    broker_unavailable
    unsupported
  )
  @capture_capabilities ~w(screen_capture screen_snapshot screen.snapshot)
  @supported_platforms ~w(windows macos linux android ios)
  @transports ~w(
    windows_named_pipe unix_socket macos_xpc xdg_desktop_portal
    android_app_command ios_app_command none
  )
  @consent_models ~w(policy os_permission portal_prompt user_prompt user_initiated unsupported)
  @max_age_seconds 300
  @max_future_skew_seconds 60
  @policy_hash_algorithm "screen_capture_policy_hash_sha256_lexical_v2"

  @typedoc "One of the string values returned by `states/0`."
  @type state :: String.t()

  @spec status(atom(), map()) :: map()
  def status(os, config) when is_map(config) do
    platform = normalize_platform(os)
    report = broker_report(config)

    cond do
      platform not in @supported_platforms ->
        contract(
          platform,
          "unsupported",
          [],
          nil,
          "Session broker is not supported for screen capture on this platform.",
          "none",
          "unsupported",
          "platform_not_supported"
        )

      not is_map(report) ->
        contract(
          platform,
          "broker_unavailable",
          [],
          nil,
          "Agent did not report session broker health.",
          default_transport(platform),
          default_consent_model(platform),
          "health_not_reported"
        )

      true ->
        normalize_report(platform, report)
    end
  end

  def status(os, _config), do: status(os, %{})

  def states, do: @states

  defp normalize_report(platform, report) do
    reported_state =
      report
      |> map_get_any([:state, "state", :status, "status"])
      |> normalize_state()

    capabilities =
      report
      |> map_get_any([:capabilities, "capabilities"])
      |> normalize_capabilities()

    policy_hash_algorithms =
      report
      |> map_get_any([:policy_hash_algorithms, "policy_hash_algorithms"])
      |> normalize_policy_hash_algorithms()

    {observed_at, freshness} =
      report
      |> map_get_any([:observed_at, "observed_at", :last_seen_at, "last_seen_at"])
      |> normalize_observed_at()

    transport =
      report
      |> map_get_any([:transport, "transport"])
      |> normalize_enum(@transports, default_transport(platform))

    consent_model =
      report
      |> map_get_any([:consent_model, "consent_model"])
      |> normalize_enum(@consent_models, default_consent_model(platform))

    detail_code =
      report
      |> map_get_any([:detail_code, "detail_code", :reason, "reason"])
      |> normalize_detail_code()

    state =
      cond do
        freshness != :fresh -> "broker_unavailable"
        reported_state == "ready" and not capture_capable?(capabilities) -> "broker_unavailable"
        true -> reported_state
      end

    detail =
      case {state, reported_state, freshness} do
        {"broker_unavailable", _, :missing} ->
          "Session broker health has no observation timestamp."

        {"broker_unavailable", _, :invalid} ->
          "Session broker health timestamp is invalid."

        {"broker_unavailable", _, :stale} ->
          "Session broker health observation is stale."

        {"ready", _, _} ->
          "Interactive user session broker is ready for a single-frame capture request."

        {"no_user_session", _, _} ->
          "No interactive user session is available for capture."

        {"locked", _, _} ->
          "The interactive user session is locked."

        {"consent_required", _, _} ->
          "The endpoint user must grant capture consent."

        {"permission_denied", _, _} ->
          "The operating-system screen capture permission was denied."

        {"portal_unavailable", _, _} ->
          "The desktop capture portal is unavailable."

        {"unsupported", _, _} ->
          "The reported broker does not support screen capture."

        {"broker_unavailable", "ready", _} ->
          "Broker reported ready without a screen capture capability."

        {"broker_unavailable", _, _} ->
          "Session broker health is unavailable or invalid."
      end

    contract(
      platform,
      state,
      capabilities,
      observed_at,
      detail,
      transport,
      consent_model,
      detail_code || default_detail_code(state)
    )
    |> Map.put(:displays, normalize_displays(report))
    |> Map.put(:policy_hash_algorithms, policy_hash_algorithms)
    |> Map.put(
      :silent_supported,
      state == "ready" and
        strict_boolean(map_get_any(report, [:silent_supported, "silent_supported"]))
    )
    |> Map.put(
      :session_capture_supported,
      state not in ["broker_unavailable", "unsupported"] and
        strict_boolean(
          map_get_any(report, [:session_capture_supported, "session_capture_supported"])
        )
    )
    |> Map.put(
      :degraded_reason,
      normalize_optional_reason(map_get_any(report, [:degraded_reason, "degraded_reason"]))
    )
    |> Map.put(
      :unsupported_reason,
      normalize_optional_reason(map_get_any(report, [:unsupported_reason, "unsupported_reason"]))
    )
  end

  defp contract(
         platform,
         state,
         capabilities,
         observed_at,
         detail,
         transport,
         consent_model,
         detail_code
       ) do
    %{
      schema_version: @schema_version,
      platform: platform,
      state: state,
      ready: state == "ready",
      capabilities: capabilities,
      policy_hash_algorithms: [],
      observed_at: observed_at,
      transport: transport,
      consent_model: consent_model,
      silent_supported: false,
      session_capture_supported: false,
      degraded_reason: if(state == "ready", do: nil, else: detail_code),
      unsupported_reason: if(state == "unsupported", do: detail_code, else: nil),
      detail_code: detail_code,
      detail: detail
    }
  end

  defp broker_report(config) do
    runtime = map_get_any(config, [:runtime, "runtime"])

    map_get_any(config, [
      :screen_session_broker,
      "screen_session_broker",
      :session_broker,
      "session_broker"
    ]) ||
      map_get_any(runtime, [
        :screen_session_broker,
        "screen_session_broker",
        :session_broker,
        "session_broker"
      ])
  end

  defp normalize_state(value) do
    state = value |> to_string() |> String.downcase() |> String.replace("-", "_")
    if state in @states, do: state, else: "broker_unavailable"
  end

  defp normalize_capabilities(value) when is_list(value) do
    value
    |> Enum.map(&normalize_capability/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp normalize_capabilities(value) when is_map(value) do
    value
    |> Enum.filter(fn {_name, enabled} -> enabled in [true, "true", 1, "1"] end)
    |> Enum.map(fn {name, _enabled} -> normalize_capability(name) end)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp normalize_capabilities(_value), do: []

  defp normalize_policy_hash_algorithms(value) when is_list(value) do
    value
    |> Enum.filter(&(&1 == @policy_hash_algorithm))
    |> Enum.uniq()
  end

  defp normalize_policy_hash_algorithms(_value), do: []

  defp normalize_capability(value) do
    value |> to_string() |> String.downcase() |> String.replace("-", "_")
  end

  defp normalize_platform(value) do
    case value |> to_string() |> String.downcase() |> String.replace(~r/[^a-z0-9]/, "") do
      value when value in ["windows", "win32", "win64"] -> "windows"
      value when value in ["macos", "darwin", "osx"] -> "macos"
      "linux" -> "linux"
      value when value in ["ios", "ipados", "iphone", "ipad"] -> "ios"
      "android" -> "android"
      _ -> "unsupported"
    end
  end

  defp normalize_enum(value, allowed, fallback) do
    normalized = value |> to_string() |> String.downcase() |> String.replace("-", "_")
    if normalized in allowed, do: normalized, else: fallback
  end

  defp normalize_detail_code(value) when is_binary(value) do
    normalized =
      value |> String.trim() |> String.downcase() |> String.replace(~r/[^a-z0-9_]/, "_")

    if normalized == "", do: nil, else: String.slice(normalized, 0, 128)
  end

  defp normalize_detail_code(_value), do: nil

  defp strict_boolean(true), do: true
  defp strict_boolean(_value), do: false

  defp normalize_optional_reason(value) when is_binary(value) do
    case value |> String.trim() |> String.slice(0, 256) do
      "" -> nil
      reason -> reason
    end
  end

  defp normalize_optional_reason(_value), do: nil

  defp normalize_displays(report) do
    report
    |> map_get_any([:displays, "displays"])
    |> List.wrap()
    |> Enum.reduce([], fn display, acc ->
      id = map_get_any(display, [:id, "id"])
      x = map_get_any(display, [:x, "x"])
      y = map_get_any(display, [:y, "y"])
      width = map_get_any(display, [:width, "width"])
      height = map_get_any(display, [:height, "height"])
      primary = map_get_any(display, [:primary, "primary"])

      if is_binary(id) and byte_size(id) in 1..128 and is_integer(x) and is_integer(y) and
           is_integer(width) and width in 1..32_768 and is_integer(height) and
           height in 1..32_768 and is_boolean(primary) do
        [%{id: id, x: x, y: y, width: width, height: height, primary: primary} | acc]
      else
        acc
      end
    end)
    |> Enum.reverse()
    |> Enum.take(16)
  end

  defp default_transport("windows"), do: "windows_named_pipe"
  defp default_transport("macos"), do: "unix_socket"
  defp default_transport("linux"), do: "xdg_desktop_portal"
  defp default_transport("android"), do: "android_app_command"
  defp default_transport("ios"), do: "ios_app_command"
  defp default_transport(_platform), do: "none"

  defp default_consent_model("windows"), do: "policy"
  defp default_consent_model("macos"), do: "os_permission"
  defp default_consent_model("linux"), do: "portal_prompt"
  defp default_consent_model("android"), do: "user_prompt"
  defp default_consent_model("ios"), do: "user_initiated"
  defp default_consent_model(_platform), do: "unsupported"

  defp default_detail_code("ready"), do: "ready"
  defp default_detail_code("no_user_session"), do: "no_user_session"
  defp default_detail_code("locked"), do: "session_locked"
  defp default_detail_code("consent_required"), do: "consent_required"
  defp default_detail_code("permission_denied"), do: "permission_denied"
  defp default_detail_code("portal_unavailable"), do: "portal_unavailable"
  defp default_detail_code("unsupported"), do: "unsupported"
  defp default_detail_code(_state), do: "broker_unavailable"

  defp capture_capable?(capabilities),
    do: Enum.any?(capabilities, &(&1 in @capture_capabilities))

  defp normalize_observed_at(value) when is_binary(value) do
    value = String.trim(value)
    now = DateTime.utc_now()

    case DateTime.from_iso8601(value) do
      {:ok, observed_at, _offset} ->
        age = DateTime.diff(now, observed_at, :second)

        if age >= -@max_future_skew_seconds and age <= @max_age_seconds,
          do: {DateTime.to_iso8601(observed_at), :fresh},
          else: {DateTime.to_iso8601(observed_at), :stale}

      _ ->
        {nil, if(value == "", do: :missing, else: :invalid)}
    end
  end

  defp normalize_observed_at(_value), do: {nil, :missing}

  defp map_get_any(map, keys) when is_map(map), do: Enum.find_value(keys, &Map.get(map, &1))
  defp map_get_any(_map, _keys), do: nil
end
