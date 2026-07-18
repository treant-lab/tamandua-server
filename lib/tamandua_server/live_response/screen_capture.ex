defmodule TamanduaServer.LiveResponse.ScreenCapture do
  @moduledoc """
  Server-side contract for safe, single-frame endpoint screen capture.

  The command never carries image bytes. Agents return an artifact reference
  with bounded metadata using the `tamandua.screen_capture/v1` schema.
  Continuous viewing and remote input are deliberately outside this contract.
  """

  @schema_version "tamandua.screen_capture/v1"
  @default_ttl_seconds 300
  @min_ttl_seconds 60
  @max_ttl_seconds 900
  @capture_scopes ~w(virtual_desktop monitor active_window)
  @max_redactions 32
  @reported_capabilities ~w(screen_capture screen_snapshot screen.snapshot)
  @consent_capabilities ~w(
    screen_capture_consent_required
    screen_snapshot_consent_required
    screen.consent_required
  )

  @type capability_state :: String.t()

  def schema_version, do: @schema_version
  def default_ttl_seconds, do: @default_ttl_seconds

  @doc "Validate and normalize a screen-capture request body."
  def validate_request(params) when is_map(params) do
    reason = params |> Map.get("reason") |> normalize_string()
    display = Map.get(params, "display", "all")
    scope = Map.get(params, "scope", scope_from_display(display))

    with :ok <- validate_reason(reason),
         {:ok, ttl_seconds} <-
           normalize_ttl(Map.get(params, "ttl_seconds", @default_ttl_seconds)),
         {:ok, display} <- normalize_display(display),
         {:ok, scope} <- normalize_scope(scope),
         {:ok, monitor_id} <- normalize_monitor_id(scope, Map.get(params, "monitor_id")),
         {:ok, watermark} <- normalize_watermark(Map.get(params, "watermark", false)),
         {:ok, redactions} <- normalize_redactions(Map.get(params, "redactions", [])) do
      {:ok,
       %{
         reason: reason,
         ttl_seconds: ttl_seconds,
         display: display,
         scope: scope,
         monitor_id: monitor_id,
         watermark: watermark,
         redactions: redactions,
         continuous: false,
         input_control: false
       }}
    end
  end

  @doc """
  Determine whether an online agent can accept a snapshot request.

  Absence of an explicitly reported capability is unsupported rather than an
  optimistic fallback. Platforms whose native APIs require a user/OS grant are
  surfaced as `consent_required` even when the command itself is supported.
  """
  @spec capability_state(term(), list()) ::
          %{
            state: capability_state(),
            consent_required: boolean(),
            unsupported_reason: String.t() | nil
          }
  def capability_state(os_type, capabilities) do
    os = normalize_os(os_type)
    reported = normalize_capabilities(capabilities)
    capture_reported? = Enum.any?(@reported_capabilities, &MapSet.member?(reported, &1))
    explicit_consent? = Enum.any?(@consent_capabilities, &MapSet.member?(reported, &1))

    cond do
      not capture_reported? ->
        unsupported("agent_did_not_report_screen_capture_capability")

      os in ["ios", "iphone", "ipad", "ipados"] ->
        %{
          state: "consent_required",
          consent_required: true,
          consent_model: "user_initiated",
          capture_coverage: "current_tamandua_app_screen_single_frame",
          unsupported_reason: nil
        }

      explicit_consent? or os in ["macos", "darwin", "linux", "android"] ->
        %{state: "consent_required", consent_required: true, unsupported_reason: nil}

      os in ["windows", "win32", "win64"] ->
        %{state: "supported", consent_required: false, unsupported_reason: nil}

      true ->
        unsupported("platform_not_supported_for_screen_capture")
    end
  end

  @doc "Canonical response shape shared by queued and unsupported requests."
  def response(attrs \\ %{}) do
    %{
      schema_version: @schema_version,
      command_id: Map.get(attrs, :command_id),
      command_type: "screen_capture",
      status: Map.get(attrs, :status, "queued"),
      capability_state: Map.get(attrs, :capability_state),
      consent_required: Map.get(attrs, :consent_required, false),
      consent_model: Map.get(attrs, :consent_model),
      capture_coverage: Map.get(attrs, :capture_coverage),
      unsupported_reason: Map.get(attrs, :unsupported_reason),
      captured_at: Map.get(attrs, :captured_at),
      display: Map.get(attrs, :display, "all"),
      scope: Map.get(attrs, :scope, "virtual_desktop"),
      monitor_id: Map.get(attrs, :monitor_id),
      watermark: Map.get(attrs, :watermark, false),
      redaction_count: Map.get(attrs, :redaction_count, 0),
      artifact: Map.get(attrs, :artifact),
      expires_at: Map.get(attrs, :expires_at),
      continuous: false,
      input_control: false,
      policy_mode: Map.get(attrs, :policy_mode),
      notify_timing: Map.get(attrs, :notify_timing),
      policy: Map.get(attrs, :policy)
    }
  end

  defp validate_reason(nil), do: {:error, :reason_required}
  defp validate_reason(""), do: {:error, :reason_required}

  defp validate_reason(reason) when byte_size(reason) <= 500, do: :ok
  defp validate_reason(_reason), do: {:error, :reason_too_long}

  defp normalize_ttl(value)
       when is_integer(value) and value in @min_ttl_seconds..@max_ttl_seconds,
       do: {:ok, value}

  defp normalize_ttl(value) when is_binary(value) do
    case Integer.parse(value) do
      {ttl, ""} -> normalize_ttl(ttl)
      _ -> {:error, :invalid_ttl_seconds}
    end
  end

  defp normalize_ttl(_value), do: {:error, :invalid_ttl_seconds}

  defp normalize_display("all"), do: {:ok, "all"}
  defp normalize_display("virtual_desktop"), do: {:ok, "all"}

  defp normalize_display(_value), do: {:error, :invalid_display}

  defp scope_from_display("all"), do: "virtual_desktop"
  defp scope_from_display("virtual_desktop"), do: "virtual_desktop"
  defp scope_from_display(_display), do: nil

  defp normalize_scope(scope) when scope in @capture_scopes, do: {:ok, scope}
  defp normalize_scope(_scope), do: {:error, :invalid_scope}

  defp normalize_monitor_id("monitor", value) when is_binary(value) do
    value = String.trim(value)

    if value != "" and byte_size(value) <= 128,
      do: {:ok, value},
      else: {:error, :invalid_monitor_id}
  end

  defp normalize_monitor_id("monitor", _value), do: {:error, :invalid_monitor_id}
  defp normalize_monitor_id(_scope, nil), do: {:ok, nil}
  defp normalize_monitor_id(_scope, _value), do: {:error, :invalid_monitor_id}

  defp normalize_watermark(value) when is_boolean(value), do: {:ok, value}
  defp normalize_watermark(_value), do: {:error, :invalid_watermark}

  defp normalize_redactions(redactions)
       when is_list(redactions) and length(redactions) <= @max_redactions do
    redactions
    |> Enum.reduce_while({:ok, []}, fn redaction, {:ok, acc} ->
      case normalize_redaction(redaction) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      error -> error
    end
  end

  defp normalize_redactions(_redactions), do: {:error, :invalid_redactions}

  defp normalize_redaction(redaction) when is_map(redaction) do
    values =
      for key <- ~w(x y width height),
          do: redaction_value(redaction, key)

    case values do
      [x, y, width, height]
      when is_integer(x) and is_integer(y) and is_integer(width) and is_integer(height) and
             x >= 0 and y >= 0 and width > 0 and height > 0 and x + width <= 10_000 and
             y + height <= 10_000 ->
        {:ok, %{x: x, y: y, width: width, height: height}}

      _ ->
        {:error, :invalid_redactions}
    end
  end

  defp normalize_redaction(_redaction), do: {:error, :invalid_redactions}

  defp redaction_value(redaction, key) do
    Map.get(redaction, key) || Map.get(redaction, String.to_atom(key))
  end

  defp normalize_string(value) when is_binary(value), do: String.trim(value)
  defp normalize_string(_value), do: nil

  defp normalize_os(value) do
    value
    |> to_string()
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]/, "")
  end

  defp normalize_capabilities(capabilities) when is_list(capabilities) do
    capabilities
    |> Enum.reduce(MapSet.new(), fn
      capability, acc when is_binary(capability) or is_atom(capability) ->
        MapSet.put(acc, normalize_capability(capability))

      %{"name" => name}, acc ->
        MapSet.put(acc, normalize_capability(name))

      %{name: name}, acc ->
        MapSet.put(acc, normalize_capability(name))

      _, acc ->
        acc
    end)
  end

  defp normalize_capabilities(_), do: MapSet.new()

  defp normalize_capability(value) do
    value
    |> to_string()
    |> String.downcase()
    |> String.replace("-", "_")
  end

  defp unsupported(reason) do
    %{state: "unsupported", consent_required: false, unsupported_reason: reason}
  end
end
