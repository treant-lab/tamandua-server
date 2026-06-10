defmodule TamanduaServer.CLIAuth do
  @moduledoc """
  Short-lived browser authorization flow for tamandua-ctl.

  The CLI receives a device code and opens the browser. An authenticated operator
  approves the code in the web app, then the CLI polls once to receive a scoped
  dashboard socket token. State is intentionally ephemeral.
  """

  use GenServer
  require Logger

  @device_ttl_seconds 300
  # CLI sessions are used for long live-response and benchmark batches. Keep the
  # browser device code short, but allow the approved CLI token to survive a
  # multi-day validation run without interactive re-login.
  @cli_token_ttl_seconds 7 * 24 * 60 * 60
  @cli_token_salt "tamandua_cli_auth_v1"
  @poll_interval_seconds 2
  @cleanup_interval_ms 60_000

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def create_device(client_name \\ "tamandua-ctl", scopes \\ ["live_response:shell"]) do
    GenServer.call(__MODULE__, {:create_device, client_name, scopes})
  end

  def get_by_user_code(user_code) do
    GenServer.call(__MODULE__, {:get_by_user_code, normalize_user_code(user_code)})
  end

  def approve(user_code, user) do
    GenServer.call(__MODULE__, {:approve, normalize_user_code(user_code), user})
  end

  def poll(device_code) do
    GenServer.call(__MODULE__, {:poll, device_code})
  end

  def verify_token(token) when is_binary(token) do
    with {:ok, payload} <-
           Phoenix.Token.verify(
             TamanduaServerWeb.Endpoint,
             @cli_token_salt,
             token,
             max_age: @cli_token_ttl_seconds
           ),
         user_id when is_binary(user_id) <- map_value(payload, :user_id),
         user when not is_nil(user) <- TamanduaServer.Accounts.get_user(user_id) do
      {:ok, user}
    else
      _ -> {:error, "Invalid or expired token"}
    end
  end

  def verify_token(_), do: {:error, "Invalid or expired token"}

  @impl true
  def init(_opts) do
    schedule_cleanup()
    {:ok, %{devices: %{}}}
  end

  @impl true
  def handle_call({:create_device, client_name, scopes}, _from, state) do
    now = DateTime.utc_now()
    device_code = random_token(32)
    user_code = unique_user_code(state.devices)
    expires_at = DateTime.add(now, @device_ttl_seconds, :second)

    device = %{
      device_code: device_code,
      user_code: user_code,
      client_name: client_name || "tamandua-ctl",
      scopes: normalize_scopes(scopes),
      status: :pending,
      created_at: now,
      expires_at: expires_at,
      approved_by: nil,
      approved_at: nil,
      token: nil,
      token_expires_at: nil
    }

    {:reply,
     {:ok,
      %{
        device_code: device_code,
        user_code: user_code,
        expires_at: expires_at,
        expires_in: @device_ttl_seconds,
        interval: @poll_interval_seconds,
        scopes: device.scopes,
        client_name: device.client_name
      }}, %{state | devices: Map.put(state.devices, device_code, device)}}
  end

  def handle_call({:get_by_user_code, user_code}, _from, state) do
    case find_by_user_code(state.devices, user_code) do
      nil -> {:reply, {:error, :not_found}, state}
      {_device_code, device} -> {:reply, device_status(device), state}
    end
  end

  def handle_call({:approve, user_code, user}, _from, state) do
    case find_by_user_code(state.devices, user_code) do
      nil ->
        {:reply, {:error, :not_found}, state}

      {device_code, %{status: :approved} = device} ->
        {:reply, device_status(device), state}

      {_device_code, %{status: :consumed}} ->
        {:reply, {:error, :already_consumed}, state}

      {device_code, device} ->
        cond do
          expired?(device) ->
            {:reply, {:error, :expired}, state}

          true ->
            with {:ok, token, expires_at} <- issue_cli_token(user, device.scopes) do
              approved =
                device
                |> Map.put(:status, :approved)
                |> Map.put(:approved_by, user_identity(user))
                |> Map.put(:approved_at, DateTime.utc_now())
                |> Map.put(:token, token)
                |> Map.put(:token_expires_at, expires_at)

              Logger.info(
                "CLI device login approved user=#{inspect(user_identity(user))} code=#{user_code}"
              )

              {:reply, {:ok, device_status(approved)},
               %{state | devices: Map.put(state.devices, device_code, approved)}}
            else
              {:error, reason} -> {:reply, {:error, reason}, state}
            end
        end
    end
  end

  def handle_call({:poll, device_code}, _from, state) do
    case Map.get(state.devices, device_code) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{status: :approved, token: token} = device when is_binary(token) ->
        consumed = %{device | status: :consumed, token: nil}

        {:reply,
         {:ok,
         %{
           access_token: token,
            token_type: "tamandua_cli_api_token",
            scope: Enum.join(device.scopes, " "),
            expires_at: format_datetime(device.token_expires_at)
         }}, %{state | devices: Map.put(state.devices, device_code, consumed)}}

      %{status: :consumed} ->
        {:reply, {:error, :already_consumed}, state}

      device ->
        if expired?(device) do
          {:reply, {:error, :expired}, %{state | devices: Map.delete(state.devices, device_code)}}
        else
          {:reply, {:error, :authorization_pending}, state}
        end
    end
  end

  @impl true
  def handle_info(:cleanup, state) do
    devices =
      state.devices
      |> Enum.reject(fn {_code, device} -> expired?(device) or device.status == :consumed end)
      |> Map.new()

    schedule_cleanup()
    {:noreply, %{state | devices: devices}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp issue_cli_token(user, scopes) do
    expires_at = DateTime.add(DateTime.utc_now(), @cli_token_ttl_seconds, :second)

    token =
      Phoenix.Token.sign(
        TamanduaServerWeb.Endpoint,
        @cli_token_salt,
        %{
          user_id: user.id,
          scopes: normalize_scopes(scopes),
          client: "tamandua-ctl"
        }
      )

    {:ok, token, expires_at}
  end

  defp unique_user_code(devices) do
    code = random_user_code()

    if Enum.any?(devices, fn {_device_code, device} -> device.user_code == code end) do
      unique_user_code(devices)
    else
      code
    end
  end

  defp random_user_code do
    :crypto.strong_rand_bytes(5)
    |> Base.encode32(case: :upper, padding: false)
    |> binary_part(0, 8)
    |> then(fn code -> String.slice(code, 0, 4) <> "-" <> String.slice(code, 4, 4) end)
  end

  defp random_token(bytes) do
    bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp find_by_user_code(devices, user_code) do
    Enum.find(devices, fn {_device_code, device} -> device.user_code == user_code end)
  end

  defp normalize_user_code(code) when is_binary(code) do
    code
    |> String.trim()
    |> String.upcase()
    |> String.replace(~r/[^A-Z0-9]/, "")
    |> then(fn
      <<a::binary-size(4), b::binary-size(4), _rest::binary>> -> a <> "-" <> b
      other -> other
    end)
  end

  defp normalize_user_code(_), do: ""

  defp normalize_scopes(scopes) when is_list(scopes) do
    scopes
    |> Enum.map(&to_string/1)
    |> Enum.filter(&(&1 in ["live_response:shell"]))
    |> case do
      [] -> ["live_response:shell"]
      allowed -> allowed
    end
  end

  defp normalize_scopes(_), do: ["live_response:shell"]

  defp expired?(%{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  defp device_status(device) do
    {:ok,
     %{
       user_code: device.user_code,
       client_name: device.client_name,
       scopes: device.scopes,
       status: to_string(device.status),
       expires_at: format_datetime(device.expires_at),
       approved_at: format_datetime(device.approved_at),
       approved_by: device.approved_by
     }}
  end

  defp user_identity(%{id: id, email: email}), do: %{id: id, email: email}
  defp user_identity(%{id: id}), do: %{id: id}
  defp user_identity(_), do: %{}

  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(_), do: nil

  defp map_value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp map_value(_, _), do: nil

  defp schedule_cleanup, do: Process.send_after(self(), :cleanup, @cleanup_interval_ms)
end
