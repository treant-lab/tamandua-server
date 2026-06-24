defmodule TamanduaServerWeb.GuiDownloadController do
  use TamanduaServerWeb, :controller

  @allowed_files MapSet.new([
                   "tamandua-gui-windows-x64.exe",
                   "tamandua-gui-0.1.0-win64.zip",
                   "tamandua-gui-macos-universal.dmg",
                   "tamandua-gui-macos-aarch64.dmg",
                   "tamandua-gui-macos-x86_64.dmg"
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
        |> json(%{error: "GUI binary is not available on this server"})
      end
    else
      conn
      |> put_status(:not_found)
      |> json(%{error: "Unknown GUI binary"})
    end
  end

  defp binary_dir do
    Application.get_env(:tamandua_server, :gui_binary_dir) ||
      System.get_env("GUI_BINARY_DIR") ||
      System.get_env("TAMANDUA_GUI_BINARY_DIR") ||
      Path.expand("priv/static/downloads/gui")
  end
end
