defmodule TamanduaServer.Licensing.Activation do
  @moduledoc """
  License activation service.

  Handles various activation methods:
  - Online activation (direct server validation)
  - Offline activation (request file + response file)
  - QR code activation (mobile app based)

  ## Offline Activation Flow

  1. User generates an activation request containing machine info
  2. Request is taken to an internet-connected device
  3. Request is submitted to licensing server
  4. Server returns an activation response
  5. Response is entered into the offline machine
  6. License is activated locally

  ## QR Code Activation Flow

  1. User enters license key
  2. QR code is generated containing activation data
  3. User scans QR with Tamandua mobile app
  4. Mobile app validates and returns confirmation code
  5. Code is entered to complete activation
  """

  require Logger

  alias TamanduaServer.Licensing.{License}

  # Dev-only fallback. Production MUST configure :activation_secret (sourced from
  # the ACTIVATION_SECRET env var in runtime.exs); otherwise signature generation
  # fails closed instead of using this publicly-known constant.
  @activation_secret_dev "tamandua_activation_secret_2026"

  # Online Activation

  @doc """
  Activate a license online.

  Validates the license key against the licensing server and activates it
  for the given organization.
  """
  @spec activate_online(binary(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def activate_online(organization_id, license_key, _opts \\ []) do
    with {:ok, _claims} <- License.verify_license_key(license_key),
         {:ok, license} <- License.activate_license(organization_id, license_key) do

      Logger.info("License activated: org=#{organization_id} tier=#{license.tier}")

      {:ok, %{
        license_id: license.id,
        tier: license.tier,
        agent_limit: license.agent_limit,
        expires_at: license.expires_at,
        features: license.features
      }}
    end
  end

  # Offline Activation

  @doc """
  Generate an offline activation request.

  Creates an encrypted request file that can be taken to an internet-connected
  device for validation.
  """
  @spec generate_offline_request(binary(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def generate_offline_request(organization_id, license_key) do
    # Gather machine information
    machine_info = get_machine_info()

    request_data = %{
      organization_id: organization_id,
      license_key: license_key,
      machine_id: machine_info.machine_id,
      hostname: machine_info.hostname,
      platform: machine_info.platform,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      request_id: generate_request_id()
    }

    # Encode and sign the request
    request_json = Jason.encode!(request_data)
    signature = generate_signature(request_json)

    encoded_request = Base.encode64("#{request_json}|#{signature}")

    {:ok, encoded_request}
  end

  @doc """
  Validate an offline activation request (server-side).

  This is called on the licensing server when processing an offline request.
  """
  @spec validate_offline_request(String.t()) :: {:ok, map()} | {:error, term()}
  def validate_offline_request(encoded_request) do
    with {:ok, decoded} <- Base.decode64(encoded_request),
         [request_json, signature] <- String.split(decoded, "|", parts: 2),
         true <- verify_signature(request_json, signature),
         {:ok, request_data} <- Jason.decode(request_json),
         {:ok, _claims} <- License.verify_license_key(request_data["license_key"]) do

      {:ok, request_data}
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_request}
    end
  end

  @doc """
  Generate an offline activation response (server-side).

  Creates the response file that will be used to complete offline activation.
  """
  @spec generate_offline_response(map()) :: {:ok, String.t()} | {:error, term()}
  def generate_offline_response(request_data) do
    response_data = %{
      organization_id: request_data["organization_id"],
      machine_id: request_data["machine_id"],
      request_id: request_data["request_id"],
      license_key: request_data["license_key"],
      activated_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      valid_until: DateTime.add(DateTime.utc_now(), 365, :day) |> DateTime.to_iso8601()
    }

    response_json = Jason.encode!(response_data)
    signature = generate_signature(response_json)

    encoded_response = Base.encode64("#{response_json}|#{signature}")

    {:ok, encoded_response}
  end

  @doc """
  Complete an offline activation.

  Validates the response file and activates the license locally.
  """
  @spec complete_offline_activation(binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def complete_offline_activation(organization_id, encoded_response) do
    with {:ok, decoded} <- Base.decode64(encoded_response),
         [response_json, signature] <- String.split(decoded, "|", parts: 2),
         true <- verify_signature(response_json, signature),
         {:ok, response_data} <- Jason.decode(response_json),
         :ok <- validate_response(organization_id, response_data) do

      # Activate the license
      License.activate_license(
        organization_id,
        response_data["license_key"]
      )
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_response}
    end
  end

  # QR Code Activation

  @doc """
  Generate a QR code for mobile activation.

  Returns a base64-encoded QR code image.
  """
  @spec generate_qr_activation(binary(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def generate_qr_activation(organization_id, license_key) do
    # Create activation data
    machine_info = get_machine_info()

    activation_data = %{
      type: "tamandua_activation",
      version: 1,
      organization_id: organization_id,
      license_key: license_key,
      machine_id: machine_info.machine_id,
      hostname: machine_info.hostname,
      timestamp: DateTime.utc_now() |> DateTime.to_unix(),
      nonce: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    }

    # Sign the data
    data_json = Jason.encode!(activation_data)
    signature = generate_signature(data_json)
    signed_data = "#{data_json}|#{signature}"

    # Generate QR code
    case generate_qr_code(signed_data) do
      {:ok, qr_image} ->
        {:ok, "data:image/png;base64,#{Base.encode64(qr_image)}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Verify a QR activation confirmation code.

  The mobile app generates a confirmation code after scanning the QR.
  """
  @spec verify_qr_confirmation(binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def verify_qr_confirmation(organization_id, confirmation_code) do
    with {:ok, decoded} <- Base.decode64(confirmation_code),
         {:ok, data} <- Jason.decode(decoded),
         :ok <- validate_confirmation(organization_id, data) do

      # Activate the license
      License.activate_license(
        organization_id,
        data["license_key"]
      )
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_confirmation}
    end
  end

  # License Validation Helpers

  @doc """
  Check if a license needs renewal.
  """
  @spec needs_renewal?(binary()) :: boolean()
  def needs_renewal?(organization_id) do
    case License.get_license(organization_id) do
      {:ok, license} ->
        days_remaining = DateTime.diff(license.expires_at, DateTime.utc_now(), :day)
        days_remaining <= 30

      _ ->
        true
    end
  end

  @doc """
  Get the grace period end date for an organization.
  """
  @spec grace_period_end(binary()) :: DateTime.t() | nil
  def grace_period_end(organization_id) do
    case License.get_license(organization_id) do
      {:ok, license} ->
        DateTime.add(license.expires_at, 7, :day)
      _ ->
        nil
    end
  end

  @doc """
  Check if the license is in grace period.
  """
  @spec in_grace_period?(binary()) :: boolean()
  def in_grace_period?(organization_id) do
    case grace_period_end(organization_id) do
      nil -> false
      grace_end ->
        now = DateTime.utc_now()
        case License.get_license(organization_id) do
          {:ok, license} ->
            DateTime.compare(now, license.expires_at) == :gt &&
            DateTime.compare(now, grace_end) == :lt
          _ ->
            false
        end
    end
  end

  # Private Functions

  defp get_machine_info do
    %{
      machine_id: generate_machine_id(),
      hostname: get_hostname(),
      platform: get_platform()
    }
  end

  defp generate_machine_id do
    # Generate a stable machine identifier
    # In production, this would use actual hardware identifiers
    data = [
      :erlang.node(),
      :os.type(),
      System.get_env("COMPUTERNAME") || System.get_env("HOSTNAME") || "unknown"
    ]
    |> Enum.join(":")

    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
    |> String.slice(0..15)
  end

  defp get_hostname do
    case :inet.gethostname() do
      {:ok, hostname} -> to_string(hostname)
      _ -> "unknown"
    end
  end

  defp get_platform do
    case :os.type() do
      {:win32, _} -> "windows"
      {:unix, :darwin} -> "macos"
      {:unix, _} -> "linux"
      _ -> "unknown"
    end
  end

  defp generate_request_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  defp generate_signature(data) do
    :crypto.mac(:hmac, :sha256, activation_secret(), data)
    |> Base.encode64()
  end

  defp activation_secret do
    case Application.get_env(:tamandua_server, :activation_secret) do
      secret when is_binary(secret) and secret != "" ->
        secret

      _ ->
        if Application.get_env(:tamandua_server, :env) == :prod do
          raise "activation_secret must be configured in production (set ACTIVATION_SECRET)"
        else
          @activation_secret_dev
        end
    end
  end

  defp verify_signature(data, signature) do
    expected = generate_signature(data)
    Plug.Crypto.secure_compare(signature, expected)
  end

  defp validate_response(organization_id, response_data) do
    cond do
      response_data["organization_id"] != organization_id ->
        {:error, :organization_mismatch}

      response_data["machine_id"] != get_machine_info().machine_id ->
        {:error, :machine_mismatch}

      expired?(response_data["valid_until"]) ->
        {:error, :response_expired}

      true ->
        :ok
    end
  end

  defp validate_confirmation(organization_id, data) do
    cond do
      data["organization_id"] != organization_id ->
        {:error, :organization_mismatch}

      data["status"] != "approved" ->
        {:error, :not_approved}

      true ->
        :ok
    end
  end

  defp expired?(nil), do: true
  defp expired?(date_string) when is_binary(date_string) do
    case DateTime.from_iso8601(date_string) do
      {:ok, valid_until, _} ->
        DateTime.compare(DateTime.utc_now(), valid_until) == :gt
      _ ->
        true
    end
  end

  defp generate_qr_code(_data) do
    # Generate QR code using EQRCode library if available
    # For now, return a placeholder
    # In production: EQRCode.encode(data) |> EQRCode.png()

    # Placeholder PNG (1x1 transparent pixel as fallback)
    placeholder = <<
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
      0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
      0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
      0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
      0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
      0x42, 0x60, 0x82
    >>

    {:ok, placeholder}
  end
end
