defmodule TamanduaServer.Notifications.Providers.Base do
  @moduledoc """
  Base behaviour for notification providers.

  All providers must implement send_notification/3 and test_connection/1.
  """

  @callback send_notification(integration :: map(), rendered_title :: String.t(), rendered_body :: String.t()) ::
              {:ok, map()} | {:error, String.t()}

  @callback test_connection(config :: map()) :: {:ok, String.t()} | {:error, String.t()}

  @doc """
  Render a template with the given variables.

  Uses basic string interpolation. In production, you'd use Solid (Liquid) or BBMustache.
  """
  def render_template(template, variables) when is_binary(template) do
    Enum.reduce(variables, template, fn {key, value}, acc ->
      # Convert key to string with braces
      pattern = "{{ #{key} }}"
      replacement = to_string(value)
      String.replace(acc, pattern, replacement)
    end)
  end

  def render_template(nil, _variables), do: ""

  @doc """
  Build template variables from alert and agent.
  """
  def build_variables(alert, agent \\ nil) do
    base_vars = %{
      "alert.id" => alert.id,
      "alert.title" => alert.title || "",
      "alert.severity" => alert.severity || "unknown",
      "alert.description" => alert.description || "",
      "alert.inserted_at" => format_datetime(alert.inserted_at),
      "alert.mitre_technique" => alert.mitre_technique || "N/A",
      "dashboard_url" => get_dashboard_url()
    }

    agent_vars =
      if agent do
        %{
          "agent.id" => agent.id,
          "agent.hostname" => agent.hostname || "unknown",
          "agent.os_type" => agent.os_type || "unknown",
          "agent.os_version" => agent.os_version || "unknown"
        }
      else
        %{
          "agent.hostname" => "unknown",
          "agent.os_type" => "unknown",
          "agent.os_version" => "unknown"
        }
      end

    Map.merge(base_vars, agent_vars)
  end

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    case DateTime.from_naive(datetime, "Etc/UTC") do
      {:ok, dt} -> Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
      _ -> to_string(datetime)
    end
  rescue
    _ -> to_string(datetime)
  end

  defp get_dashboard_url do
    Application.get_env(:tamandua_server, :dashboard_url, "https://localhost:4000")
  end

  @doc """
  Make an HTTP POST request with JSON body.
  """
  def http_post(url, body, headers \\ []) do
    default_headers = [{"Content-Type", "application/json"}]
    all_headers = default_headers ++ headers

    case TamanduaServer.HttpClient.post(url, Jason.encode!(body), all_headers, timeout: 10_000, recv_timeout: 10_000) do
      {:ok, %{status_code: code, body: resp_body}} when code >= 200 and code < 300 ->
        {:ok, %{status_code: code, body: resp_body}}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, reason} ->
        {:error, "HTTP error: #{inspect(reason)}"}
    end
  end
end
