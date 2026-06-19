defmodule TamanduaServerWeb.AgentDownloadController do
  use TamanduaServerWeb, :controller

  @allowed_files MapSet.new([
                   "tamandua-agent-windows-x64.msi",
                   "tamandua-agent-windows-x64.exe",
                   "tamandua-gui-windows-x64-setup.exe",
                   "tamandua-gui-windows-x64.msi",
                   "tamandua-agent-linux-x64",
                   "tamandua-agent-macos-arm64",
                   "tamandua-agent-macos-arm64.sha256"
                 ])

  def show(conn, %{"filename" => filename}) do
    if MapSet.member?(@allowed_files, filename) do
      path =
        binary_dir()
        |> Path.join(filename)
        |> Path.expand()

      root = Path.expand(binary_dir())

      if String.starts_with?(path, root) and File.regular?(path) do
        send_download(conn, {:file, path}, filename: filename)
      else
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent binary is not available on this server"})
      end
    else
      conn
      |> put_status(:not_found)
      |> json(%{error: "Unknown agent binary"})
    end
  end

  defp binary_dir do
    Application.get_env(:tamandua_server, :agent_binary_dir) ||
      System.get_env("AGENT_BINARY_DIR") ||
      System.get_env("TAMANDUA_AGENT_BINARY_DIR") ||
      Path.expand("priv/static/downloads/agents")
  end
end
