defmodule TamanduaServerWeb.Vite do
  @moduledoc """
  Helper for loading Vite manifest and resolving asset paths.
  """

  @manifest_path "priv/static/assets/manifest.json"
  @entrypoint "src/main.tsx"

  def js_path do
    case get_manifest() do
      {:ok, %{@entrypoint => %{"file" => file}}} when is_binary(file) ->
        file

      _ ->
        "app.js"
    end
  end

  def css_path do
    case get_manifest() do
      {:ok, %{@entrypoint => %{"css" => [file | _]}}} when is_binary(file) ->
        file

      _ ->
        "app.css"
    end
  end

  defp get_manifest do
    path = Application.app_dir(:tamandua_server, @manifest_path)

    with {:ok, content} <- File.read(path),
         {:ok, decoded} <- Jason.decode(content) do
      {:ok, decoded}
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
