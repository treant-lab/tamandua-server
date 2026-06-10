defmodule TamanduaServer.Integrations.MISP do
  @moduledoc """
  Integration with MISP (Malware Information Sharing Platform) for IOC export.

  Provides functionality to export workflow findings and IOCs to MISP for
  threat intelligence sharing.
  """

  require Logger

  @doc """
  Export IOCs to MISP.

  ## Examples

      iocs = %{
        ip_addresses: ["192.168.1.100", "10.0.0.5"],
        domains: ["evil.com", "malware.net"],
        file_hashes: ["abc123...", "def456..."],
        urls: ["http://evil.com/payload"]
      }

      MISP.export_iocs(iocs)
  """
  def export_iocs(iocs, opts \\ []) do
    if misp_enabled?() do
      event_info = Keyword.get(opts, :event_info, "Tamandua Workflow IOCs")
      event_id = create_event(event_info)

      case event_id do
        {:ok, id} ->
          add_attributes(id, iocs)
          {:ok, id}

        {:error, reason} ->
          Logger.error("Failed to create MISP event: #{inspect(reason)}")
          {:error, reason}
      end
    else
      Logger.info("MISP integration disabled, skipping IOC export")
      {:ok, :disabled}
    end
  end

  @doc """
  Create a new MISP event.
  """
  def create_event(info) do
    url = misp_url() <> "/events/add"
    headers = misp_headers()

    body = %{
      Event: %{
        info: info,
        distribution: 0,  # Your organization only
        threat_level_id: 2,  # Medium
        analysis: 1  # Ongoing
      }
    }

    case HTTPoison.post(url, Jason.encode!(body), headers) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"Event" => %{"id" => event_id}}} ->
            {:ok, event_id}

          _ ->
            {:error, :invalid_response}
        end

      {:ok, %{status_code: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("MISP event creation failed: #{inspect(e)}")
      {:error, e}
  end

  @doc """
  Add attributes (IOCs) to a MISP event.
  """
  def add_attributes(event_id, iocs) do
    # IP addresses
    Enum.each(iocs[:ip_addresses] || [], fn ip ->
      add_attribute(event_id, "ip-dst", ip)
    end)

    # Domains
    Enum.each(iocs[:domains] || [], fn domain ->
      add_attribute(event_id, "domain", domain)
    end)

    # File hashes
    Enum.each(iocs[:file_hashes] || [], fn hash ->
      type = determine_hash_type(hash)
      add_attribute(event_id, type, hash)
    end)

    # URLs
    Enum.each(iocs[:urls] || [], fn url ->
      add_attribute(event_id, "url", url)
    end)

    :ok
  end

  @doc """
  Add a single attribute to a MISP event.
  """
  def add_attribute(event_id, attribute_type, value) do
    url = misp_url() <> "/attributes/add/#{event_id}"
    headers = misp_headers()

    body = %{
      Attribute: %{
        type: attribute_type,
        value: value,
        category: "Network activity",
        to_ids: true
      }
    }

    case HTTPoison.post(url, Jason.encode!(body), headers) do
      {:ok, %{status_code: 200}} ->
        :ok

      {:ok, %{status_code: status}} ->
        Logger.warning("Failed to add MISP attribute: HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("Failed to add MISP attribute: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("MISP attribute add failed: #{inspect(e)}")
      {:error, e}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp misp_enabled? do
    Application.get_env(:tamandua_server, :misp_enabled, false)
  end

  defp misp_url do
    Application.get_env(:tamandua_server, :misp_url, "http://localhost")
  end

  defp misp_api_key do
    Application.get_env(:tamandua_server, :misp_api_key, "")
  end

  defp misp_headers do
    [
      {"Authorization", misp_api_key()},
      {"Accept", "application/json"},
      {"Content-Type", "application/json"}
    ]
  end

  defp determine_hash_type(hash) do
    case String.length(hash) do
      32 -> "md5"
      40 -> "sha1"
      64 -> "sha256"
      _ -> "other"
    end
  end
end
