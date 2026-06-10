defmodule TamanduaServerWeb.CLIAuthController do
  @moduledoc """
  Browser approval page for tamandua-ctl device login.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.CLIAuth

  def show(conn, params) do
    code = params["code"] || ""

    case CLIAuth.get_by_user_code(code) do
      {:ok, device} ->
        html(conn, page_html(device, nil))

      {:error, :not_found} ->
        html(conn, page_html(%{user_code: code, status: "not_found"}, "Code not found or expired."))
    end
  end

  def approve(conn, %{"code" => code}) do
    user = conn.assigns[:current_user]

    case CLIAuth.approve(code, user) do
      {:ok, device} ->
        html(conn, page_html(device, "Tamandua CLI authorized. You can return to the terminal."))

      {:error, :expired} ->
        html(conn, page_html(%{user_code: code, status: "expired"}, "Code expired. Run tamandua-ctl remote login again."))

      {:error, :already_consumed} ->
        html(conn, page_html(%{user_code: code, status: "consumed"}, "This code was already used."))

      {:error, :not_found} ->
        html(conn, page_html(%{user_code: code, status: "not_found"}, "Code not found or expired."))

      {:error, reason} ->
        html(conn, page_html(%{user_code: code, status: "error"}, "Authorization failed: #{inspect(reason)}"))
    end
  end

  defp page_html(device, message) do
    code = escape(map_value(device, :user_code) || "")
    client = escape(map_value(device, :client_name) || "tamandua-ctl")
    raw_status = map_value(device, :status) || "pending"
    status = escape(raw_status)
    scopes = map_value(device, :scopes) || []
    scope_text = scopes |> Enum.map(&scope_label/1) |> Enum.map(&escape/1) |> Enum.join(", ")
    scope_text = if scope_text == "", do: "Live Response shell", else: scope_text
    state = page_state(raw_status)
    title = escape(state.title)
    subtitle = escape(state.subtitle)
    message_html = if message, do: ~s(<div class="notice #{state.kind}">#{escape(message)}</div>), else: ""
    action_html = action_html(raw_status, code)
    csrf = Plug.CSRFProtection.get_csrf_token()

    """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Tamandua CLI Authorization</title>
        <style>
          :root { color-scheme: dark; }
          body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #080d12; color: #e5edf5; font-family: Inter, system-ui, -apple-system, Segoe UI, sans-serif; }
          .panel { width: min(560px, calc(100vw - 32px)); border: 1px solid #243241; background: #101820; border-radius: 10px; padding: 28px; box-shadow: 0 24px 80px rgba(0,0,0,.35); }
          .icon { width: 44px; height: 44px; border-radius: 999px; display: grid; place-items: center; margin-bottom: 18px; font-weight: 800; }
          .icon.pending { background: #172554; color: #93c5fd; }
          .icon.success { background: #052e16; color: #86efac; }
          .icon.error { background: #3b1111; color: #fca5a5; }
          h1 { margin: 0 0 8px; font-size: 22px; letter-spacing: 0; }
          p { color: #91a4b7; line-height: 1.55; margin: 0 0 18px; }
          .code { letter-spacing: .18em; font-size: 28px; font-weight: 750; color: #7dd3fc; margin: 18px 0; overflow-wrap: anywhere; }
          .meta { border: 1px solid #243241; border-radius: 8px; padding: 14px; margin: 18px 0; color: #b8c7d6; display: grid; gap: 8px; }
          .meta strong { color: #dce7f2; }
          .notice { border-radius: 8px; padding: 12px; margin-bottom: 16px; }
          .notice.success { border: 1px solid #2f6f48; background: #0b2b1a; color: #9ee6b7; }
          .notice.pending { border: 1px solid #2563eb; background: #102040; color: #bfdbfe; }
          .notice.error { border: 1px solid #7f1d1d; background: #2d1111; color: #fecaca; }
          .actions { margin-top: 18px; }
          button, .done { width: 100%; border: 0; border-radius: 8px; padding: 12px 14px; font-weight: 700; box-sizing: border-box; text-align: center; }
          button { color: #061014; background: #30d158; cursor: pointer; }
          .done { display: block; color: #9fb0c2; background: #16212b; border: 1px solid #263746; }
        </style>
      </head>
      <body>
        <main class="panel">
          #{message_html}
          <div class="icon #{state.kind}">#{state.icon}</div>
          <h1>#{title}</h1>
          <p>#{subtitle}</p>
          <div class="code">#{code}</div>
          <div class="meta">
            <div><strong>Client:</strong> #{client}</div>
            <div><strong>Scope:</strong> #{scope_text}</div>
            <div><strong>Status:</strong> #{status}</div>
          </div>
          #{action_html.(csrf)}
        </main>
      </body>
    </html>
    """
  end

  defp page_state("pending") do
    %{
      kind: "pending",
      icon: "?",
      title: "Authorize Tamandua CLI",
      subtitle: "Approve this request only if the code shown here matches the code in your terminal."
    }
  end

  defp page_state(status) when status in ["approved", "consumed"] do
    %{
      kind: "success",
      icon: "OK",
      title: "Tamandua CLI Authorized",
      subtitle: "The terminal received access. You can close this tab and return to the command line."
    }
  end

  defp page_state(_status) do
    %{
      kind: "error",
      icon: "!",
      title: "CLI Authorization Unavailable",
      subtitle: "This code cannot be approved. Start a new login from tamandua-ctl and try again."
    }
  end

  defp action_html("pending", code) do
    fn csrf ->
      """
      <form class="actions" method="post" action="/cli/auth/approve">
        <input type="hidden" name="_csrf_token" value="#{csrf}" />
        <input type="hidden" name="code" value="#{code}" />
        <button type="submit">Authorize CLI</button>
      </form>
      """
    end
  end

  defp action_html(_status, _code) do
    fn _csrf -> ~s(<div class="actions"><span class="done">Return to terminal</span></div>) end
  end

  defp scope_label("live_response:shell"), do: "Live Response shell"
  defp scope_label(scope), do: to_string(scope)

  defp escape(value), do: Phoenix.HTML.html_escape(to_string(value)) |> Phoenix.HTML.safe_to_string()

  defp map_value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp map_value(_, _), do: nil
end
