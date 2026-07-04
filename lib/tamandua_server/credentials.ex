defmodule TamanduaServer.Credentials do
  @moduledoc """
  Credential validation and rotation status tracking for Tamandua Server.

  This module provides:
  - Startup validation to detect weak/default credentials
  - Rotation status tracking (age, expiry, recommendations)
  - Centralized credential path and environment variable documentation

  ## Credential Inventory

  | Credential             | Env Variable              | Purpose                           |
  |------------------------|---------------------------|-----------------------------------|
  | JWT Secret             | GUARDIAN_SECRET_KEY       | User session tokens               |
  | Agent Secret           | TAMANDUA_AGENT_SECRET     | Agent authentication              |
  | Secret Key Base        | SECRET_KEY_BASE           | Phoenix session encryption        |
  | Database URL           | DATABASE_URL              | PostgreSQL connection             |
  | Recording Key          | TAMANDUA_RECORDING_KEY    | Live response recording encryption|
  | Ticketing Encryption   | TICKETING_ENCRYPTION_KEY  | Jira/ServiceNow credential vault  |
  | mTLS CA Certificate    | CA_CERT_PATH              | Agent mTLS validation             |

  ## Usage

  Call `validate_all!/0` during application startup to ensure all credentials
  are properly configured. In production, weak credentials will raise errors.
  In development, warnings are logged.

  ```elixir
  # In application.ex start/2
  TamanduaServer.Credentials.validate_all!()
  ```
  """

  require Logger
  alias TamanduaServer.OSCommand

  # Known weak secrets that should never be used in production
  @known_weak_secrets [
    "secret",
    "changeme",
    "development",
    "test123",
    "password",
    "admin",
    "letmein",
    "12345678",
    "qwerty",
    "abc123",
    "tamandua",
    "default",
    "example",
    "mysecret",
    "supersecret"
  ]

  # Minimum lengths for various secrets
  @min_jwt_secret_length 64
  @min_agent_secret_length 32
  @min_secret_key_base_length 64
  @min_encryption_key_length 32

  # Entropy thresholds (bits per character)
  @min_entropy_threshold 3.5

  @type credential_status :: %{
          name: String.t(),
          configured: boolean(),
          weak: boolean(),
          age_days: non_neg_integer() | nil,
          rotation_recommended: boolean(),
          reason: String.t() | nil
        }

  @type rotation_status :: %{
          credentials: [credential_status()],
          overall_health: :healthy | :warning | :critical,
          recommendations: [String.t()]
        }

  @doc """
  Validates all credentials on startup.

  In production (:prod), raises on critical issues.
  In development (:dev/:test), logs warnings.

  ## Checks performed:
  - JWT secret is configured and not weak
  - Agent secret meets minimum length
  - Database URL is not using default credentials
  - Secret key base is sufficiently random
  - Recording encryption key is set (if recordings enabled)
  """
  @spec validate_all!() :: :ok
  def validate_all! do
    env = Application.get_env(:tamandua_server, :env, :prod)
    warnings = []

    warnings = warnings ++ validate_jwt_secret()
    warnings = warnings ++ validate_agent_secret()
    warnings = warnings ++ validate_database_credentials()
    warnings = warnings ++ validate_secret_key_base()
    warnings = warnings ++ validate_recording_key()
    warnings = warnings ++ validate_ticketing_key()
    warnings = warnings ++ validate_mtls_cert()

    if length(warnings) > 0 do
      log_credential_warnings(warnings, env)
    else
      Logger.info("[Credentials] All credential validations passed")
    end

    :ok
  end

  @doc """
  Returns the rotation status for all credentials.

  This can be used by admin dashboards to show credential health.
  """
  @spec rotation_status() :: rotation_status()
  def rotation_status do
    credentials = [
      check_jwt_secret_status(),
      check_agent_secret_status(),
      check_database_status(),
      check_secret_key_base_status(),
      check_recording_key_status(),
      check_ticketing_key_status(),
      check_mtls_cert_status()
    ]

    overall_health = determine_overall_health(credentials)
    recommendations = generate_recommendations(credentials)

    %{
      credentials: credentials,
      overall_health: overall_health,
      recommendations: recommendations
    }
  end

  @doc """
  Checks if any credentials need immediate rotation.
  """
  @spec rotation_needed?() :: boolean()
  def rotation_needed? do
    status = rotation_status()

    status.overall_health == :critical or
      Enum.any?(status.credentials, & &1.rotation_recommended)
  end

  @doc """
  Returns a summary suitable for logging or alerts.
  """
  @spec summary() :: String.t()
  def summary do
    status = rotation_status()

    health_emoji =
      case status.overall_health do
        :healthy -> "[OK]"
        :warning -> "[WARN]"
        :critical -> "[CRITICAL]"
      end

    configured_count = Enum.count(status.credentials, & &1.configured)
    total_count = length(status.credentials)
    weak_count = Enum.count(status.credentials, & &1.weak)
    rotation_count = Enum.count(status.credentials, & &1.rotation_recommended)

    """
    #{health_emoji} Credential Status: #{configured_count}/#{total_count} configured, \
    #{weak_count} weak, #{rotation_count} need rotation
    #{if length(status.recommendations) > 0, do: "\nRecommendations:\n" <> Enum.join(status.recommendations, "\n"), else: ""}
    """
  end

  # ==========================================================================
  # Validation Functions
  # ==========================================================================

  defp validate_jwt_secret do
    secret = Application.get_env(:tamandua_server, TamanduaServer.Guardian)[:secret_key]

    cond do
      is_nil(secret) or secret == "" ->
        [{:error, "GUARDIAN_SECRET_KEY is not configured"}]

      String.length(secret) < @min_jwt_secret_length ->
        [
          {:warning,
           "GUARDIAN_SECRET_KEY is shorter than recommended (#{@min_jwt_secret_length} chars)"}
        ]

      is_weak_secret?(secret) ->
        [{:error, "GUARDIAN_SECRET_KEY appears to be a weak/default secret"}]

      low_entropy?(secret) ->
        [{:warning, "GUARDIAN_SECRET_KEY has low entropy - consider regenerating"}]

      true ->
        []
    end
  end

  defp validate_agent_secret do
    secret = Application.get_env(:tamandua_server, :agent_secret)

    cond do
      is_nil(secret) or secret == "" ->
        [{:error, "TAMANDUA_AGENT_SECRET is not configured"}]

      String.length(secret) < @min_agent_secret_length ->
        [
          {:error,
           "TAMANDUA_AGENT_SECRET must be at least #{@min_agent_secret_length} characters"}
        ]

      is_weak_secret?(secret) ->
        [{:error, "TAMANDUA_AGENT_SECRET appears to be a weak/default secret"}]

      true ->
        []
    end
  end

  defp validate_database_credentials do
    url = System.get_env("DATABASE_URL") || ""

    cond do
      url == "" ->
        # Will be caught by runtime.exs raise
        []

      contains_weak_password?(url) ->
        [{:warning, "DATABASE_URL may contain a weak password"}]

      String.contains?(url, "localhost") and Application.get_env(:tamandua_server, :env) == :prod ->
        [{:warning, "DATABASE_URL points to localhost in production"}]

      true ->
        []
    end
  end

  defp validate_secret_key_base do
    secret = Application.get_env(:tamandua_server, TamanduaServerWeb.Endpoint)[:secret_key_base]

    cond do
      is_nil(secret) or secret == "" ->
        [{:error, "SECRET_KEY_BASE is not configured"}]

      String.length(secret) < @min_secret_key_base_length ->
        [
          {:warning,
           "SECRET_KEY_BASE is shorter than recommended (#{@min_secret_key_base_length} chars)"}
        ]

      is_weak_secret?(secret) ->
        [{:error, "SECRET_KEY_BASE appears to be a weak/default secret"}]

      true ->
        []
    end
  end

  defp validate_recording_key do
    config =
      Application.get_env(:tamandua_server, TamanduaServer.LiveResponse.SessionRecording, [])

    key = config[:encryption_key]

    cond do
      is_nil(key) or key == "" ->
        [
          {:warning,
           "TAMANDUA_RECORDING_KEY is not set - live response recordings will not be encrypted"}
        ]

      String.length(key) < @min_encryption_key_length ->
        [
          {:warning,
           "TAMANDUA_RECORDING_KEY should be at least #{@min_encryption_key_length} characters"}
        ]

      true ->
        []
    end
  end

  defp validate_ticketing_key do
    key = Application.get_env(:tamandua_server, :ticketing_encryption_key)
    ticketing_enabled = Application.get_env(:tamandua_server, :ticketing_enabled, false)

    cond do
      not ticketing_enabled ->
        []

      is_nil(key) or key == "" ->
        [
          {:warning,
           "TICKETING_ENCRYPTION_KEY not set but ticketing is enabled - credentials stored unencrypted"}
        ]

      not valid_aes_key?(key) ->
        [{:warning, "TICKETING_ENCRYPTION_KEY should be 32 bytes base64-encoded for AES-256-GCM"}]

      true ->
        []
    end
  end

  defp validate_mtls_cert do
    require_mtls = Application.get_env(:tamandua_server, :require_mtls, true)
    ca_cert_path = Application.get_env(:tamandua_server, :ca_cert_path)

    cond do
      not require_mtls ->
        [{:warning, "mTLS is disabled - agent connections are not mutually authenticated"}]

      is_nil(ca_cert_path) or ca_cert_path == "" ->
        [{:error, "CA_CERT_PATH is required when mTLS is enabled"}]

      not File.exists?(ca_cert_path) ->
        [{:error, "CA certificate file does not exist: #{ca_cert_path}"}]

      certificate_expiring_soon?(ca_cert_path) ->
        [{:warning, "CA certificate at #{ca_cert_path} is expiring soon"}]

      true ->
        []
    end
  end

  # ==========================================================================
  # Status Check Functions
  # ==========================================================================

  defp check_jwt_secret_status do
    secret = Application.get_env(:tamandua_server, TamanduaServer.Guardian)[:secret_key]

    %{
      name: "JWT Secret (GUARDIAN_SECRET_KEY)",
      configured: not is_nil(secret) and secret != "",
      weak: is_weak_secret?(secret || ""),
      # We don't track secret age currently
      age_days: nil,
      rotation_recommended: is_weak_secret?(secret || "") or low_entropy?(secret || ""),
      reason:
        cond do
          is_nil(secret) or secret == "" -> "Not configured"
          is_weak_secret?(secret) -> "Weak/default secret detected"
          low_entropy?(secret) -> "Low entropy"
          true -> nil
        end
    }
  end

  defp check_agent_secret_status do
    secret = Application.get_env(:tamandua_server, :agent_secret)

    %{
      name: "Agent Secret (TAMANDUA_AGENT_SECRET)",
      configured: not is_nil(secret) and secret != "",
      weak:
        is_weak_secret?(secret || "") or String.length(secret || "") < @min_agent_secret_length,
      age_days: nil,
      rotation_recommended: is_weak_secret?(secret || ""),
      reason:
        cond do
          is_nil(secret) or secret == "" -> "Not configured"
          String.length(secret) < @min_agent_secret_length -> "Too short"
          is_weak_secret?(secret) -> "Weak/default secret detected"
          true -> nil
        end
    }
  end

  defp check_database_status do
    url = System.get_env("DATABASE_URL") || ""

    %{
      name: "Database (DATABASE_URL)",
      configured: url != "",
      weak: contains_weak_password?(url),
      age_days: nil,
      rotation_recommended: contains_weak_password?(url),
      reason: if(contains_weak_password?(url), do: "Weak password detected", else: nil)
    }
  end

  defp check_secret_key_base_status do
    secret = Application.get_env(:tamandua_server, TamanduaServerWeb.Endpoint)[:secret_key_base]

    %{
      name: "Secret Key Base (SECRET_KEY_BASE)",
      configured: not is_nil(secret) and secret != "",
      weak: is_weak_secret?(secret || ""),
      age_days: nil,
      rotation_recommended: is_weak_secret?(secret || ""),
      reason: if(is_weak_secret?(secret || ""), do: "Weak/default secret detected", else: nil)
    }
  end

  defp check_recording_key_status do
    config =
      Application.get_env(:tamandua_server, TamanduaServer.LiveResponse.SessionRecording, [])

    key = config[:encryption_key]

    %{
      name: "Recording Key (TAMANDUA_RECORDING_KEY)",
      configured: not is_nil(key) and key != "",
      weak: false,
      age_days: nil,
      rotation_recommended: is_nil(key) or key == "",
      reason:
        if(is_nil(key) or key == "", do: "Not configured - recordings unencrypted", else: nil)
    }
  end

  defp check_ticketing_key_status do
    key = Application.get_env(:tamandua_server, :ticketing_encryption_key)
    ticketing_enabled = Application.get_env(:tamandua_server, :ticketing_enabled, false)

    %{
      name: "Ticketing Key (TICKETING_ENCRYPTION_KEY)",
      configured: not is_nil(key) and key != "",
      weak: not valid_aes_key?(key || ""),
      age_days: nil,
      rotation_recommended: ticketing_enabled and (is_nil(key) or key == ""),
      reason:
        cond do
          not ticketing_enabled -> "Ticketing disabled"
          is_nil(key) or key == "" -> "Not configured"
          not valid_aes_key?(key) -> "Invalid AES key format"
          true -> nil
        end
    }
  end

  defp check_mtls_cert_status do
    ca_cert_path = Application.get_env(:tamandua_server, :ca_cert_path)
    require_mtls = Application.get_env(:tamandua_server, :require_mtls, true)

    expiring =
      if ca_cert_path && File.exists?(ca_cert_path) do
        certificate_expiring_soon?(ca_cert_path)
      else
        false
      end

    %{
      name: "mTLS CA Certificate (CA_CERT_PATH)",
      configured: require_mtls and not is_nil(ca_cert_path) and File.exists?(ca_cert_path || ""),
      weak: false,
      age_days: nil,
      rotation_recommended: expiring,
      reason:
        cond do
          not require_mtls -> "mTLS disabled"
          is_nil(ca_cert_path) -> "Path not configured"
          not File.exists?(ca_cert_path) -> "Certificate file not found"
          expiring -> "Certificate expiring soon"
          true -> nil
        end
    }
  end

  # ==========================================================================
  # Helper Functions
  # ==========================================================================

  defp is_weak_secret?(secret) when is_binary(secret) do
    normalized = String.downcase(secret)

    # All lowercase letters
    # All digits
    Enum.any?(@known_weak_secrets, fn weak ->
      String.contains?(normalized, weak)
    end) or
      String.match?(normalized, ~r/^[a-z]+$/) or
      String.match?(normalized, ~r/^[0-9]+$/)
  end

  defp is_weak_secret?(_), do: true

  defp low_entropy?(secret) when is_binary(secret) and byte_size(secret) > 0 do
    entropy = calculate_entropy(secret)
    entropy < @min_entropy_threshold
  end

  defp low_entropy?(_), do: true

  defp calculate_entropy(string) do
    # Shannon entropy calculation
    frequencies =
      string
      |> String.graphemes()
      |> Enum.frequencies()

    len = String.length(string)

    frequencies
    |> Map.values()
    |> Enum.map(fn count ->
      probability = count / len
      -probability * :math.log2(probability)
    end)
    |> Enum.sum()
  end

  defp contains_weak_password?(url) when is_binary(url) do
    # Check for common weak passwords in database URLs
    # Format: postgres://user:password@host/db
    case Regex.run(~r/:([^:@]+)@/, url) do
      [_, password] ->
        is_weak_secret?(password) or String.length(password) < 12

      _ ->
        false
    end
  end

  defp contains_weak_password?(_), do: false

  defp valid_aes_key?(key) when is_binary(key) do
    # AES-256-GCM needs 32 bytes, which is 44 chars base64 encoded (with padding)
    # or 43 chars without padding
    case Base.decode64(key) do
      {:ok, decoded} -> byte_size(decoded) == 32
      :error -> false
    end
  end

  defp valid_aes_key?(_), do: false

  defp certificate_expiring_soon?(cert_path) do
    # Check if certificate expires within 30 days
    # This is a simplified check - production should use proper X.509 parsing
    case OSCommand.run("openssl", ["x509", "-enddate", "-noout", "-in", cert_path],
           stderr_to_stdout: true
         ) do
      {output, 0} ->
        case Regex.run(~r/notAfter=(.+)/, output) do
          [_, date_str] ->
            case parse_openssl_date(date_str) do
              {:ok, expiry} ->
                days_until_expiry = DateTime.diff(expiry, DateTime.utc_now(), :day)
                days_until_expiry < 30

              _ ->
                false
            end

          _ ->
            false
        end

      _ ->
        # openssl not available or failed, skip check
        false
    end
  rescue
    _ -> false
  end

  defp parse_openssl_date(date_str) do
    # OpenSSL date format: "Jan  1 00:00:00 2026 GMT"
    # This is a simplified parser
    date_str = String.trim(date_str)

    case Regex.run(~r/(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)/, date_str) do
      [_, month_str, day, hour, minute, second, year] ->
        month = month_to_number(month_str)

        if month > 0 do
          case DateTime.new(
                 Date.new!(String.to_integer(year), month, String.to_integer(day)),
                 Time.new!(
                   String.to_integer(hour),
                   String.to_integer(minute),
                   String.to_integer(second)
                 )
               ) do
            {:ok, dt} -> {:ok, dt}
            _ -> :error
          end
        else
          :error
        end

      _ ->
        :error
    end
  end

  defp month_to_number(month) do
    case String.downcase(month) do
      "jan" -> 1
      "feb" -> 2
      "mar" -> 3
      "apr" -> 4
      "may" -> 5
      "jun" -> 6
      "jul" -> 7
      "aug" -> 8
      "sep" -> 9
      "oct" -> 10
      "nov" -> 11
      "dec" -> 12
      _ -> 0
    end
  end

  defp determine_overall_health(credentials) do
    cond do
      Enum.any?(credentials, fn c ->
        not c.configured and c.name =~ ~r/JWT|Agent|Database|Secret Key/
      end) ->
        :critical

      Enum.any?(credentials, & &1.weak) ->
        :critical

      Enum.any?(credentials, & &1.rotation_recommended) ->
        :warning

      true ->
        :healthy
    end
  end

  defp generate_recommendations(credentials) do
    credentials
    |> Enum.filter(& &1.rotation_recommended)
    |> Enum.map(fn c ->
      "- #{c.name}: #{c.reason || "rotation recommended"}"
    end)
  end

  @doc false
  # Hard-fail production boot when credential validation reported errors.
  #
  # Escape hatch: setting the environment variable
  # `TAMANDUA_ALLOW_DEGRADED_CREDENTIALS=true` (or the application config
  # `config :tamandua_server, :allow_degraded_credentials, true`) allows the
  # node to boot anyway. This is intended ONLY for lab/dev-like profiles that
  # run a :prod release without real secrets; its use is logged as CRITICAL so
  # it is impossible to miss in production logs.
  #
  # Exposed as a public function (with @doc false) so the enforcement logic is
  # unit-testable without having to fabricate a full production credential set.
  @spec enforce_production_credentials!([{:error, String.t()}]) :: :ok
  def enforce_production_credentials!(errors) do
    if degraded_credentials_allowed?() do
      Logger.critical(
        "[Credentials] TAMANDUA_ALLOW_DEGRADED_CREDENTIALS is set: booting DESPITE " <>
          "#{length(errors)} credential validation error(s). This escape hatch is for " <>
          "lab/dev profiles only and MUST NOT be used in a real production deployment."
      )

      :ok
    else
      raise "Credential validation failed in production: #{length(errors)} error(s). " <>
              "Fix the credentials listed above, or (lab/dev profiles ONLY) set " <>
              "TAMANDUA_ALLOW_DEGRADED_CREDENTIALS=true to boot degraded."
    end
  end

  defp degraded_credentials_allowed? do
    System.get_env("TAMANDUA_ALLOW_DEGRADED_CREDENTIALS") == "true" or
      Application.get_env(:tamandua_server, :allow_degraded_credentials, false) == true
  end

  defp log_credential_warnings(warnings, env) do
    errors = Enum.filter(warnings, fn {level, _} -> level == :error end)
    warns = Enum.filter(warnings, fn {level, _} -> level == :warning end)

    if length(errors) > 0 do
      error_messages = Enum.map(errors, fn {_, msg} -> "  - #{msg}" end) |> Enum.join("\n")

      if env == :prod do
        Logger.critical("""
        [Credentials] CRITICAL: Credential validation failed in production!

        #{error_messages}

        These issues MUST be fixed before running in production.
        See docs/security/CREDENTIAL_ROTATION.md for rotation procedures.
        """)

        enforce_production_credentials!(errors)
      else
        Logger.error("""
        [Credentials] Credential validation errors (non-production):

        #{error_messages}
        """)
      end
    end

    if length(warns) > 0 do
      warn_messages = Enum.map(warns, fn {_, msg} -> "  - #{msg}" end) |> Enum.join("\n")

      Logger.warning("""
      [Credentials] Credential warnings:

      #{warn_messages}

      Run `TamanduaServer.Credentials.rotation_status()` for full status.
      """)
    end
  end
end
