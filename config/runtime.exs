import Config

ioc_snapshot_provider =
  case System.get_env("IOC_SNAPSHOT_PROVIDER", "legacy") |> String.trim() |> String.downcase() do
    "legacy" ->
      :legacy

    "authority_v1" ->
      :authority_v1

    unsupported ->
      raise "IOC_SNAPSHOT_PROVIDER must be 'legacy' or 'authority_v1', got: #{inspect(unsupported)}"
  end

ioc_snapshot_authority_repo_enabled =
  case System.get_env("IOC_SNAPSHOT_AUTHORITY_REPO_ENABLED", "false")
       |> String.trim()
       |> String.downcase() do
    "true" ->
      true

    "false" ->
      false

    unsupported ->
      raise "IOC_SNAPSHOT_AUTHORITY_REPO_ENABLED must be 'true' or 'false', got: #{inspect(unsupported)}"
  end

if ioc_snapshot_provider == :authority_v1 != ioc_snapshot_authority_repo_enabled do
  raise "authority_v1 requires its dedicated IOC snapshot repository enabled, and legacy requires it disabled"
end

config :tamandua_server,
  ioc_snapshot_provider: ioc_snapshot_provider,
  ioc_snapshot_authority_repo_enabled: ioc_snapshot_authority_repo_enabled

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# temporary file watchers are started.

decision_engine_autonomous_response_enabled =
  case System.get_env("TAMANDUA_DECISION_ENGINE_AUTONOMOUS_RESPONSE", "false")
       |> String.trim()
       |> String.downcase() do
    "true" ->
      true

    "false" ->
      false

    unsupported ->
      raise "TAMANDUA_DECISION_ENGINE_AUTONOMOUS_RESPONSE must be 'true' or 'false', got: #{inspect(unsupported)}"
  end

config :tamandua_server,
       :decision_engine_autonomous_response_enabled,
       decision_engine_autonomous_response_enabled

shadow_alert_trigger =
  case System.get_env("TAMANDUA_SHADOW_ALERT_TRIGGER", "off")
       |> String.trim()
       |> String.downcase() do
    "off" ->
      :off

    "shadow" ->
      :shadow

    unsupported ->
      raise "TAMANDUA_SHADOW_ALERT_TRIGGER must be 'off' or 'shadow', got: #{inspect(unsupported)}"
  end

config :tamandua_server, TamanduaServer.Investigations.ShadowOrchestrator,
  alert_creation_trigger: shadow_alert_trigger,
  max_active_per_tenant:
    System.get_env("TAMANDUA_SHADOW_MAX_ACTIVE_PER_TENANT", "2") |> String.to_integer(),
  max_admissions_per_minute:
    System.get_env("TAMANDUA_SHADOW_MAX_ADMISSIONS_PER_MINUTE", "10") |> String.to_integer(),
  worker_timeout_ms:
    System.get_env("TAMANDUA_SHADOW_WORKER_TIMEOUT_MS", "30000") |> String.to_integer()

migration_release_task =
  config_env() == :prod and System.get_env("TAMANDUA_RELEASE_TASK") == "migrate"

if migration_release_task do
  migrator_database_url =
    System.get_env("MIGRATOR_DATABASE_URL") ||
      raise "MIGRATOR_DATABASE_URL is required for the migrate release task"

  config :tamandua_server, TamanduaServer.Repo,
    url: migrator_database_url,
    pool_size: 1,
    socket_options: if(System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []),
    ssl: System.get_env("DATABASE_SSL") == "true"
end

if config_env() == :prod and not migration_release_task do
  # Database configuration
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :tamandua_server, TamanduaServer.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    timeout: String.to_integer(System.get_env("DB_TIMEOUT") || "15000"),
    queue_target: String.to_integer(System.get_env("DB_QUEUE_TARGET") || "5000"),
    queue_interval: String.to_integer(System.get_env("DB_QUEUE_INTERVAL") || "1000"),
    socket_options: maybe_ipv6,
    ssl: System.get_env("DATABASE_SSL") == "true"

  authority_repo_enabled = System.get_env("AUTHORITY_REPO_ENABLED") == "true"
  config :tamandua_server, :authority_repo_enabled, authority_repo_enabled

  if authority_repo_enabled do
    authority_database_url =
      System.get_env("AUTHORITY_DATABASE_URL") ||
        raise "AUTHORITY_DATABASE_URL is required when AUTHORITY_REPO_ENABLED=true"

    if authority_database_url == database_url do
      raise "AUTHORITY_DATABASE_URL must use a separate database identity"
    end

    authority_database_role =
      System.get_env("AUTHORITY_DATABASE_ROLE") ||
        raise "AUTHORITY_DATABASE_ROLE is required when AUTHORITY_REPO_ENABLED=true"

    authority_pool_size =
      System.get_env("AUTHORITY_POOL_SIZE", "2") |> String.to_integer()

    if authority_pool_size < 1 or authority_pool_size > 5 do
      raise "AUTHORITY_POOL_SIZE must be between 1 and 5"
    end

    config :tamandua_server, :authority_database_role, authority_database_role

    config :tamandua_server, TamanduaServer.AuthorityRepo,
      url: authority_database_url,
      pool_size: authority_pool_size,
      timeout: String.to_integer(System.get_env("AUTHORITY_DB_TIMEOUT") || "15000"),
      queue_target: 1_000,
      queue_interval: 1_000,
      socket_options: maybe_ipv6,
      ssl: System.get_env("AUTHORITY_DATABASE_SSL") == "true"
  end

  agentic_restore_authority_repo_enabled =
    System.get_env("AGENTIC_RESTORE_AUTHORITY_REPO_ENABLED") == "true"

  config :tamandua_server,
         :agentic_restore_authority_repo_enabled,
         agentic_restore_authority_repo_enabled

  if agentic_restore_authority_repo_enabled do
    agentic_restore_authority_database_url =
      System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_URL") ||
        raise "AGENTIC_RESTORE_AUTHORITY_DATABASE_URL is required when its pool is enabled"

    if agentic_restore_authority_database_url == database_url or
         agentic_restore_authority_database_url == System.get_env("AUTHORITY_DATABASE_URL") do
      raise "agentic restore authority must use a dedicated database identity"
    end

    agentic_restore_authority_database_role =
      System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_ROLE") ||
        raise "AGENTIC_RESTORE_AUTHORITY_DATABASE_ROLE is required when its pool is enabled"

    config :tamandua_server,
           :agentic_restore_authority_database_role,
           agentic_restore_authority_database_role

    config :tamandua_server, TamanduaServer.AgenticRestoreAuthorityRepo,
      url: agentic_restore_authority_database_url,
      pool_size: 1,
      timeout:
        String.to_integer(System.get_env("AGENTIC_RESTORE_AUTHORITY_DB_TIMEOUT") || "15000"),
      queue_target: 1_000,
      queue_interval: 1_000,
      socket_options: maybe_ipv6,
      ssl: System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_SSL") == "true"
  end

  decision_engine_authority_repo_enabled =
    System.get_env("DECISION_ENGINE_AUTHORITY_REPO_ENABLED") == "true"

  config :tamandua_server,
         :decision_engine_authority_repo_enabled,
         decision_engine_authority_repo_enabled

  if decision_engine_authority_repo_enabled do
    decision_engine_authority_database_url =
      System.get_env("DECISION_ENGINE_AUTHORITY_DATABASE_URL") ||
        raise "DECISION_ENGINE_AUTHORITY_DATABASE_URL is required when its pool is enabled"

    peer_urls = [
      database_url,
      System.get_env("AUTHORITY_DATABASE_URL"),
      System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_URL"),
      System.get_env("ENROLLMENT_LOCATOR_DATABASE_URL"),
      System.get_env("IOC_SNAPSHOT_AUTHORITY_DATABASE_URL")
    ]

    if decision_engine_authority_database_url in peer_urls do
      raise "DecisionEngine authority must use a dedicated database identity"
    end

    decision_engine_authority_database_role =
      System.get_env("DECISION_ENGINE_AUTHORITY_DATABASE_ROLE") ||
        raise "DECISION_ENGINE_AUTHORITY_DATABASE_ROLE is required when its pool is enabled"

    peer_roles =
      [
        System.get_env("RUNTIME_DATABASE_ROLE"),
        System.get_env("MIGRATOR_DATABASE_ROLE"),
        System.get_env("AUTHORITY_DATABASE_ROLE"),
        System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_ROLE"),
        System.get_env("ENROLLMENT_LOCATOR_DATABASE_ROLE"),
        System.get_env("IOC_SNAPSHOT_AUTHORITY_DATABASE_ROLE")
      ]
      |> Enum.reject(&is_nil/1)

    if decision_engine_authority_database_role in peer_roles do
      raise "DecisionEngine authority database role must be distinct from every peer role"
    end

    config :tamandua_server,
           :decision_engine_authority_database_role,
           decision_engine_authority_database_role

    config :tamandua_server, TamanduaServer.DecisionEngineAuthorityRepo,
      url: decision_engine_authority_database_url,
      pool_size: 1,
      timeout:
        String.to_integer(System.get_env("DECISION_ENGINE_AUTHORITY_DB_TIMEOUT") || "15000"),
      queue_target: 1_000,
      queue_interval: 1_000,
      socket_options: maybe_ipv6,
      ssl: System.get_env("DECISION_ENGINE_AUTHORITY_DATABASE_SSL") == "true"
  end

  remediation_approval_authority_repo_enabled =
    System.get_env("REMEDIATION_APPROVAL_AUTHORITY_REPO_ENABLED") == "true"

  config :tamandua_server,
         :remediation_approval_authority_repo_enabled,
         remediation_approval_authority_repo_enabled

  if remediation_approval_authority_repo_enabled do
    fetch_remediation_identity = fn url_env, role_env ->
      url =
        System.get_env(url_env) ||
          raise "#{url_env} is required when the remediation approval authority pool is enabled"

      role =
        System.get_env(role_env) ||
          raise "#{role_env} is required when the remediation approval authority pool is enabled"

      unless Regex.match?(~r/^[a-z_][a-z0-9_]{0,62}$/, role) do
        raise "#{role_env} is invalid"
      end

      identity =
        try do
          uri =
            case URI.new(url) do
              {:ok, uri} -> uri
              {:error, _reason} -> raise ArgumentError
            end

          scheme =
            case uri.scheme && String.downcase(uri.scheme) do
              scheme when scheme in ["ecto", "postgres", "postgresql"] -> "postgresql"
              _ -> raise ArgumentError
            end

          [encoded_user | _] = String.split(uri.userinfo || "", ":", parts: 2)
          user = URI.decode(encoded_user)

          encoded_database =
            case uri.path do
              "/" <> encoded_database when encoded_database != "" -> encoded_database
              _ -> raise ArgumentError
            end

          database = URI.decode(encoded_database)

          host =
            case uri.host do
              host when is_binary(host) and host != "" ->
                case :inet.parse_address(String.to_charlist(host)) do
                  {:ok, address} -> address |> :inet.ntoa() |> List.to_string()
                  {:error, _reason} -> host |> String.downcase() |> String.trim_trailing(".")
                end

              _ ->
                raise ArgumentError
            end

          if host == "" or user == "" or database == "" or uri.query != nil or
               uri.fragment != nil or
               String.contains?(database, "/") do
            raise ArgumentError
          end

          {scheme, host, uri.port || 5432, database, user}
        rescue
          _ -> raise "#{url_env} has an invalid database identity"
        end

      if elem(identity, 4) != role do
        raise "#{url_env} user must exactly match #{role_env}"
      end

      {url, role, identity}
    end

    remediation_identity_specs = [
      {"DATABASE_URL", "RUNTIME_DATABASE_ROLE"},
      {"MIGRATOR_DATABASE_URL", "MIGRATOR_DATABASE_ROLE"},
      {"AUTHORITY_DATABASE_URL", "AUTHORITY_DATABASE_ROLE"},
      {"AGENTIC_RESTORE_AUTHORITY_DATABASE_URL", "AGENTIC_RESTORE_AUTHORITY_DATABASE_ROLE"},
      {"DECISION_ENGINE_AUTHORITY_DATABASE_URL", "DECISION_ENGINE_AUTHORITY_DATABASE_ROLE"},
      {"ENROLLMENT_LOCATOR_DATABASE_URL", "ENROLLMENT_LOCATOR_DATABASE_ROLE"},
      {"IOC_SNAPSHOT_AUTHORITY_DATABASE_URL", "IOC_SNAPSHOT_AUTHORITY_DATABASE_ROLE"},
      {"REMEDIATION_APPROVAL_AUTHORITY_DATABASE_URL",
       "REMEDIATION_APPROVAL_AUTHORITY_DATABASE_ROLE"}
    ]

    remediation_identities =
      Enum.map(remediation_identity_specs, fn {url_env, role_env} ->
        fetch_remediation_identity.(url_env, role_env)
      end)

    if remediation_identities |> Enum.map(&elem(&1, 2)) |> Enum.uniq() |> length() !=
         length(remediation_identities) do
      raise "remediation approval authority database identities must be pairwise distinct"
    end

    if remediation_identities |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> length() !=
         length(remediation_identities) do
      raise "remediation approval authority database roles must be pairwise distinct"
    end

    {remediation_approval_authority_database_url,
     remediation_approval_authority_database_role, _remediation_identity} =
      List.last(remediation_identities)

    config :tamandua_server,
           :remediation_approval_authority_database_role,
           remediation_approval_authority_database_role

    config :tamandua_server, TamanduaServer.RemediationApprovalAuthorityRepo,
      url: remediation_approval_authority_database_url,
      pool_size: 1,
      timeout:
        String.to_integer(System.get_env("REMEDIATION_APPROVAL_AUTHORITY_DB_TIMEOUT") || "15000"),
      queue_target: 1_000,
      queue_interval: 1_000,
      socket_options: maybe_ipv6,
      ssl: System.get_env("REMEDIATION_APPROVAL_AUTHORITY_DATABASE_SSL") == "true"
  end

  enrollment_locator_repo_enabled =
    System.get_env("ENROLLMENT_LOCATOR_REPO_ENABLED") == "true"

  config :tamandua_server, :enrollment_locator_repo_enabled, enrollment_locator_repo_enabled

  if enrollment_locator_repo_enabled do
    enrollment_locator_database_url =
      System.get_env("ENROLLMENT_LOCATOR_DATABASE_URL") ||
        raise "ENROLLMENT_LOCATOR_DATABASE_URL is required when its pool is enabled"

    if enrollment_locator_database_url in [
         database_url,
         System.get_env("AUTHORITY_DATABASE_URL"),
         System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_URL")
       ] do
      raise "enrollment locator must use a dedicated database identity"
    end

    enrollment_locator_database_role =
      System.get_env("ENROLLMENT_LOCATOR_DATABASE_ROLE") ||
        raise "ENROLLMENT_LOCATOR_DATABASE_ROLE is required when its pool is enabled"

    enrollment_locator_peer_roles =
      [
        System.get_env("RUNTIME_DATABASE_ROLE") ||
          raise("RUNTIME_DATABASE_ROLE is required when the enrollment locator pool is enabled"),
        System.get_env("MIGRATOR_DATABASE_ROLE") ||
          raise("MIGRATOR_DATABASE_ROLE is required when the enrollment locator pool is enabled"),
        System.get_env("AUTHORITY_DATABASE_ROLE") ||
          raise("AUTHORITY_DATABASE_ROLE is required when the enrollment locator pool is enabled"),
        System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_ROLE") ||
          raise(
            "AGENTIC_RESTORE_AUTHORITY_DATABASE_ROLE is required when the enrollment locator pool is enabled"
          )
      ]

    if enrollment_locator_database_role in enrollment_locator_peer_roles or
         Enum.uniq(enrollment_locator_peer_roles) != enrollment_locator_peer_roles do
      raise "enrollment locator, runtime, migrator, retention and agentic database roles must be distinct"
    end

    config :tamandua_server,
           :enrollment_locator_database_role,
           enrollment_locator_database_role

    config :tamandua_server, TamanduaServer.EnrollmentLocatorRepo,
      url: enrollment_locator_database_url,
      pool_size: 1,
      timeout: String.to_integer(System.get_env("ENROLLMENT_LOCATOR_DB_TIMEOUT") || "15000"),
      queue_target: 1_000,
      queue_interval: 1_000,
      socket_options: maybe_ipv6,
      ssl: System.get_env("ENROLLMENT_LOCATOR_DATABASE_SSL") == "true"
  end

  if ioc_snapshot_authority_repo_enabled do
    ioc_snapshot_authority_database_url =
      System.get_env("IOC_SNAPSHOT_AUTHORITY_DATABASE_URL") ||
        raise "IOC_SNAPSHOT_AUTHORITY_DATABASE_URL is required for authority_v1"

    peer_urls = [
      database_url,
      System.get_env("AUTHORITY_DATABASE_URL"),
      System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_URL"),
      System.get_env("ENROLLMENT_LOCATOR_DATABASE_URL")
    ]

    if ioc_snapshot_authority_database_url in peer_urls do
      raise "IOC snapshot authority must use a dedicated database identity"
    end

    ioc_snapshot_authority_database_role =
      System.get_env("IOC_SNAPSHOT_AUTHORITY_DATABASE_ROLE") ||
        raise "IOC_SNAPSHOT_AUTHORITY_DATABASE_ROLE is required for authority_v1"

    peer_roles =
      [
        System.get_env("RUNTIME_DATABASE_ROLE"),
        System.get_env("MIGRATOR_DATABASE_ROLE"),
        System.get_env("AUTHORITY_DATABASE_ROLE"),
        System.get_env("AGENTIC_RESTORE_AUTHORITY_DATABASE_ROLE"),
        System.get_env("ENROLLMENT_LOCATOR_DATABASE_ROLE")
      ]
      |> Enum.reject(&is_nil/1)

    if ioc_snapshot_authority_database_role in peer_roles do
      raise "IOC snapshot authority database role must be distinct from every peer role"
    end

    config :tamandua_server,
           :ioc_snapshot_authority_database_role,
           ioc_snapshot_authority_database_role

    config :tamandua_server, TamanduaServer.IocSnapshotAuthorityRepo,
      url: ioc_snapshot_authority_database_url,
      pool_size: 1,
      timeout: String.to_integer(System.get_env("IOC_SNAPSHOT_AUTHORITY_DB_TIMEOUT") || "15000"),
      queue_target: 1_000,
      queue_interval: 1_000,
      socket_options: maybe_ipv6,
      ssl: System.get_env("IOC_SNAPSHOT_AUTHORITY_DATABASE_SSL") == "true"
  end

  # Guardian secret (required in production)
  guardian_secret =
    System.get_env("GUARDIAN_SECRET_KEY") ||
      raise """
      environment variable GUARDIAN_SECRET_KEY is missing.
      Generate one with: mix guardian.gen.secret
      """

  config :tamandua_server, TamanduaServer.Guardian, secret_key: guardian_secret

  # Agent authentication secret (required in production)
  agent_secret =
    System.get_env("TAMANDUA_AGENT_SECRET") ||
      raise """
      environment variable TAMANDUA_AGENT_SECRET is missing.
      Must be at least 32 characters.
      """

  if byte_size(agent_secret) < 32 do
    raise "TAMANDUA_AGENT_SECRET must be at least 32 characters"
  end

  config :tamandua_server,
    agent_secret: agent_secret

  # License activation HMAC secret (required in production)
  activation_secret =
    System.get_env("ACTIVATION_SECRET") ||
      raise """
      environment variable ACTIVATION_SECRET is missing.
      Must be a high-entropy random string (>= 32 characters).
      """

  if byte_size(activation_secret) < 32 do
    raise "ACTIVATION_SECRET must be at least 32 characters"
  end

  config :tamandua_server,
    activation_secret: activation_secret

  # Endpoint configuration
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"
  port = String.to_integer(System.get_env("PORT") || "4000")
  agent_mtls_enabled? = System.get_env("AGENT_MTLS_ENABLED", "false") == "true"
  agent_mtls_port = String.to_integer(System.get_env("AGENT_MTLS_PORT") || "8443")
  lab_light? = System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true"
  endpoint_scheme = if(lab_light?, do: "http", else: "https")
  endpoint_port = if(lab_light?, do: port, else: 443)

  default_check_origins =
    [
      "#{endpoint_scheme}://#{host}",
      "https://#{host}",
      "http://#{host}",
      "http://#{host}:#{port}",
      "https://tamandua.treantlab.org",
      "http://tamandua.treantlab.org",
      "http://192.168.12.146:#{port}"
    ]
    |> Enum.uniq()

  check_origins =
    case System.get_env("PHX_CHECK_ORIGINS") do
      nil ->
        default_check_origins

      "" ->
        default_check_origins

      "false" ->
        false

      origins ->
        origins
        |> String.split(",", trim: true)
        |> Enum.map(&String.trim/1)
    end

  endpoint_config = [
    url: [host: host, port: endpoint_port, scheme: endpoint_scheme],
    server: true,
    http: [
      ip: {0, 0, 0, 0},
      port: port
    ],
    check_origin: check_origins,
    force_ssl: if(lab_light?, do: false, else: [rewrite_on: [:x_forwarded_proto]]),
    secret_key_base: secret_key_base
  ]

  endpoint_config =
    if agent_mtls_enabled? do
      server_certfile =
        System.get_env("AGENT_MTLS_CERTFILE") ||
          raise "AGENT_MTLS_ENABLED=true requires AGENT_MTLS_CERTFILE"

      server_keyfile =
        System.get_env("AGENT_MTLS_KEYFILE") ||
          raise "AGENT_MTLS_ENABLED=true requires AGENT_MTLS_KEYFILE"

      client_ca_certfile =
        System.get_env("AGENT_MTLS_CLIENT_CA_CERTFILE") ||
          System.get_env("CA_CERT_PATH") ||
          raise "AGENT_MTLS_ENABLED=true requires AGENT_MTLS_CLIENT_CA_CERTFILE or CA_CERT_PATH"

      Keyword.put(endpoint_config, :https,
        ip: {0, 0, 0, 0},
        port: agent_mtls_port,
        certfile: server_certfile,
        keyfile: server_keyfile,
        cacertfile: client_ca_certfile,
        verify: :verify_peer,
        fail_if_no_peer_cert: true,
        reuse_sessions: true,
        secure_renegotiate: true,
        versions: [:"tlsv1.2", :"tlsv1.3"]
      )
    else
      endpoint_config
    end

  config :tamandua_server, TamanduaServerWeb.Endpoint, endpoint_config

  # CORS Configuration
  # In production, explicitly set allowed origins. Wildcard "*" is insecure
  # with session-based authentication (credentials leak to any origin).
  # Format: comma-separated list e.g., "https://app.example.com,https://admin.example.com"
  cors_origins = System.get_env("CORS_ORIGINS")

  cors_config =
    cond do
      cors_origins == "*" ->
        Logger.warning(
          "[Security] CORS_ORIGINS='*' is insecure in production. " <>
            "Set to specific origins or leave unset for default (same-origin only)."
        )

        "*"

      is_binary(cors_origins) and cors_origins != "" ->
        cors_origins

      true ->
        # Default: only allow same-origin (the Phoenix host)
        "https://#{host}"
    end

  config :tamandua_server,
    cors_origins: cors_config

  # mTLS Configuration
  # Enforces mutual TLS on agent connections and telemetry endpoints
  # Environment Variables:
  #   - MTLS_REQUIRED: "true" to force mTLS validation (default: true in prod)
  #   - CA_CERT_PATH: Path to CA certificate for client cert validation
  #
  # Protected paths: /socket/agent, /api/v1/agents/telemetry
  config :tamandua_server,
    require_mtls: System.get_env("MTLS_REQUIRED", "true") == "true",
    ca_cert_path: System.get_env("CA_CERT_PATH", "/etc/tamandua/ca.crt"),
    mtls_trust_proxy_headers: System.get_env("MTLS_TRUST_PROXY_HEADERS", "false") == "true",
    mtls_paths: ["/socket/agent", "/api/v1/agents/telemetry"]

  # ML service configuration
  ml_service_url = System.get_env("ML_SERVICE_URL") || "http://localhost:8000"

  config :tamandua_server,
    ml_service_url: ml_service_url

  # Stripe billing configuration (required for production billing)
  if System.get_env("STRIPE_SECRET_KEY") do
    config :stripity_stripe,
      api_key: System.fetch_env!("STRIPE_SECRET_KEY"),
      webhook_signing_secret: System.get_env("STRIPE_WEBHOOK_SECRET")
  end

  config :tamandua_server, TamanduaServer.Detection.ML.Client,
    base_url: ml_service_url,
    timeout: String.to_integer(System.get_env("ML_TIMEOUT") || "30000")

  # LLM / AI Integration (for NL Hunt, alert summarization, etc.)
  # Supports OpenAI (default) or Anthropic. Set LLM_PROVIDER to switch.
  llm_provider =
    case System.get_env("LLM_PROVIDER", "openai") do
      "anthropic" -> :anthropic
      _ -> :openai
    end

  config :tamandua_server, TamanduaServer.AI.LLMClient,
    provider: llm_provider,
    model: System.get_env("OPENAI_MODEL") || "gpt-4o-mini",
    openai_api_key: System.get_env("OPENAI_API_KEY"),
    anthropic_api_key: System.get_env("ANTHROPIC_API_KEY"),
    timeout: String.to_integer(System.get_env("LLM_TIMEOUT") || "60000"),
    max_retries: String.to_integer(System.get_env("LLM_MAX_RETRIES") || "3")

  # Redis/Message Queue (if using external broker)
  if rabbitmq_url = System.get_env("RABBITMQ_URL") do
    config :tamandua_server, TamanduaServer.Telemetry.Ingestor,
      producer_module: BroadwayRabbitMQ.Producer,
      producer_config: [
        queue: "tamandua.telemetry",
        connection: [url: rabbitmq_url]
      ]
  end

  # Oban configuration for production
  config :tamandua_server, Oban,
    repo: TamanduaServer.Repo,
    plugins: [
      {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 7},
      {Oban.Plugins.Cron,
       crontab: [
         {"0 * * * *", TamanduaServer.Workers.CleanupWorker},
         # Daily recording retention cleanup at 3:00 AM UTC
         {"0 3 * * *", TamanduaServer.Workers.RecordingRetentionWorker},
         # Threat intel feed sync every 4 hours (at minute 15 to stagger)
         {"15 */4 * * *", TamanduaServer.Workers.ThreatIntelSyncWorker},
         # Alert digest every 15 minutes
         {"*/15 * * * *", TamanduaServer.Workers.DigestWorker},
         # Erase expired screen-capture bytes and one-time credentials
         {"*/5 * * * *", TamanduaServer.Workers.ScreenCaptureRetentionWorker},
         {"*/5 * * * *", TamanduaServer.Workers.EvidenceSessionRetentionWorker}
       ]}
    ],
    queues: [
      default: 10,
      alerts: 5,
      ml: 3,
      reports: 2,
      threat_intel: 2,
      notifications: 5,
      escalations: 3,
      blockchain: 3,
      ai_investigations: 2
    ]

  # Live Response Session Recording configuration
  recording_retention =
    String.to_integer(System.get_env("TAMANDUA_RECORDING_RETENTION_DAYS") || "90")

  config :tamandua_server, TamanduaServer.LiveResponse.SessionRecording,
    recording_dir: System.get_env("TAMANDUA_RECORDING_DIR") || "priv/live_response_recordings",
    encryption_key: System.get_env("TAMANDUA_RECORDING_KEY"),
    retention_days: recording_retention

  # Threat Intelligence API Keys (optional but recommended)
  config :tamandua_server, :threat_intel,
    virustotal_api_key: System.get_env("VT_API_KEY"),
    alienvault_api_key: System.get_env("OTX_API_KEY"),
    shodan_api_key: System.get_env("SHODAN_API_KEY"),
    abuseipdb_api_key: System.get_env("ABUSEIPDB_API_KEY")

  # Threat Intelligence Feed Sync configuration (production overrides)
  # Free feeds are enabled by default. Set env vars for premium feeds.
  otx_enabled = System.get_env("OTX_API_KEY") != nil
  misp_enabled = System.get_env("MISP_API_KEY") != nil and System.get_env("MISP_URL") != nil

  config :tamandua_server, TamanduaServer.Detection.ThreatIntelFeeds,
    enabled: System.get_env("THREAT_INTEL_FEEDS_ENABLED", "true") == "true",
    sync_interval_hours: String.to_integer(System.get_env("THREAT_INTEL_SYNC_HOURS", "4")),
    initial_sync_delay_seconds:
      String.to_integer(System.get_env("THREAT_INTEL_INITIAL_DELAY", "30")),
    feeds: %{
      abusech_feodo: %{enabled: true, description: "Abuse.ch Feodo Tracker"},
      abusech_urlhaus: %{enabled: true, description: "Abuse.ch URLhaus"},
      abusech_threatfox: %{enabled: true, description: "Abuse.ch ThreatFox"},
      abusech_malware_bazaar: %{enabled: true, description: "Abuse.ch Malware Bazaar"},
      abusech_ssl_blacklist: %{enabled: true, description: "Abuse.ch SSL Blacklist"},
      emergingthreats: %{enabled: true, description: "EmergingThreats compromised IPs"},
      tor_exit_nodes: %{enabled: true, description: "Tor exit nodes"},
      phishtank: %{enabled: true, description: "PhishTank phishing URLs"},
      openphish: %{enabled: true, description: "OpenPhish phishing URLs"},
      spamhaus_drop: %{enabled: true, description: "Spamhaus DROP list"},
      firehol_level1: %{enabled: true, description: "FireHOL Level 1"},
      c2_intel_feeds: %{enabled: true, description: "C2 Intel Feeds"},
      otx: %{enabled: otx_enabled, description: "AlienVault OTX"},
      misp: %{enabled: misp_enabled, description: "MISP"}
    }

  # Cloud provider credentials (optional — if not set, cloud CSPM scans are skipped)
  config :tamandua_server, TamanduaServer.Cloud.AWS,
    access_key_id: System.get_env("AWS_ACCESS_KEY_ID"),
    secret_access_key: System.get_env("AWS_SECRET_ACCESS_KEY"),
    regions: String.split(System.get_env("AWS_REGIONS", "us-east-1,us-west-2,eu-west-1"), ",")

  config :tamandua_server, TamanduaServer.Cloud.Azure,
    tenant_id: System.get_env("AZURE_TENANT_ID"),
    client_id: System.get_env("AZURE_CLIENT_ID"),
    client_secret: System.get_env("AZURE_CLIENT_SECRET")

  gcp_key_path = System.get_env("GCP_SERVICE_ACCOUNT_KEY_PATH")

  gcp_key =
    if gcp_key_path && File.exists?(gcp_key_path) do
      case File.read(gcp_key_path) do
        {:ok, contents} ->
          case Jason.decode(contents) do
            {:ok, key} -> key
            _ -> nil
          end

        _ ->
          nil
      end
    else
      nil
    end

  config :tamandua_server, TamanduaServer.Cloud.GCP,
    service_account_key: gcp_key,
    service_account_key_path: gcp_key_path

  otel_enabled? = System.get_env("OTEL_ENABLED", "false") == "true"
  otel_exporter_available? = Application.spec(:opentelemetry_exporter) != nil

  if otel_enabled? and otel_exporter_available? do
    # OpenTelemetry distributed tracing. Disabled by default so an unavailable
    # local collector cannot delay control-plane or agent socket startup.
    config :opentelemetry,
      resource: [
        service: [
          name: "tamandua-server",
          version: "0.1.0",
          namespace: System.get_env("OTEL_SERVICE_NAMESPACE", "tamandua")
        ]
      ]

    config :opentelemetry, :processors,
      otel_batch_processor: %{
        exporter: {
          :opentelemetry_exporter,
          %{
            endpoints: [
              {:http, System.get_env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")}
            ],
            headers: []
          }
        }
      }

    # Sampling: Parent-based with 1% ratio for new traces
    config :opentelemetry,
           :sampler,
           {:parent_based,
            %{
              root: {:trace_id_ratio_based, 0.01},
              remote_parent_sampled: :always_on,
              remote_parent_not_sampled: :always_off,
              local_parent_sampled: :always_on,
              local_parent_not_sampled: :always_off
            }}
  else
    if otel_enabled? do
      IO.warn(
        "OTEL_ENABLED=true ignored because opentelemetry_exporter is not included in this release"
      )
    end
  end

  # Trivy vulnerability scanner configuration
  # Use TRIVY_MODE=server and TRIVY_SERVER_URL for server mode
  trivy_mode =
    case System.get_env("TRIVY_MODE", "cli") do
      "server" -> :server
      _ -> :cli
    end

  config :tamandua_server, :trivy,
    enabled: System.get_env("TRIVY_ENABLED", "true") == "true",
    mode: trivy_mode,
    server_url: System.get_env("TRIVY_SERVER_URL", "http://localhost:4954"),
    timeout: String.to_integer(System.get_env("TRIVY_TIMEOUT", "120000")),
    severity: System.get_env("TRIVY_SEVERITY", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"),
    ignore_unfixed: System.get_env("TRIVY_IGNORE_UNFIXED", "false") == "true"

  # ClickHouse — high-volume telemetry storage
  # Uses the HTTP interface on port 8123. All event types are dual-written:
  # PostgreSQL for relational queries, ClickHouse for analytics/search.
  # The ClickHouseWriter GenServer batches events and flushes asynchronously
  # with a circuit breaker to prevent cascading failures.
  config :tamandua_server, TamanduaServer.Telemetry.ClickHouse,
    enabled: System.get_env("CLICKHOUSE_ENABLED", "true") == "true",
    url: System.get_env("CLICKHOUSE_URL") || "http://localhost:8123",
    database: System.get_env("CLICKHOUSE_DATABASE") || "tamandua",
    username:
      System.get_env("CLICKHOUSE_USERNAME") || System.get_env("CLICKHOUSE_USER") || "default",
    password: System.get_env("CLICKHOUSE_PASSWORD") || "",
    batch_size: String.to_integer(System.get_env("CLICKHOUSE_BATCH_SIZE") || "1000"),
    flush_interval_ms:
      String.to_integer(System.get_env("CLICKHOUSE_FLUSH_INTERVAL_MS") || "5000"),
    retry_count: String.to_integer(System.get_env("CLICKHOUSE_RETRY_COUNT") || "3"),
    max_consecutive_failures: String.to_integer(System.get_env("CLICKHOUSE_MAX_FAILURES") || "5"),
    circuit_open_duration_ms:
      String.to_integer(System.get_env("CLICKHOUSE_CIRCUIT_OPEN_MS") || "60000"),
    query_timeout: String.to_integer(System.get_env("CLICKHOUSE_QUERY_TIMEOUT") || "30000")
end

# Test environment configuration
if config_env() == :test do
  config :tamandua_server, TamanduaServerWeb.Endpoint,
    http: [ip: {127, 0, 0, 1}, port: 4002],
    secret_key_base: "test_secret_key_base_for_testing_only",
    server: false

  config :tamandua_server, TamanduaServer.Guardian, secret_key: "test_secret_key_for_testing_only"

  config :tamandua_server,
    agent_secret: "test_agent_secret_for_testing_only_min32",
    env: :test,
    require_mtls: false

  config :tamandua_server, Oban, testing: :manual

  # Disable Trivy in tests by default (can be enabled for integration tests)
  config :tamandua_server, :trivy,
    enabled: System.get_env("TRIVY_ENABLED", "false") == "true",
    mode: :cli,
    timeout: 30_000

  # Disable ClickHouse in tests — Broadway tests should not hit real ClickHouse
  config :tamandua_server, TamanduaServer.Telemetry.ClickHouse, enabled: false

  config :bcrypt_elixir, :log_rounds, 1
  config :logger, level: :warning
end

# ===========================================================================
# Alert Notification Configuration (All Environments)
# ===========================================================================

# Base URL for links in notifications
config :tamandua_server,
  base_url: System.get_env("TAMANDUA_BASE_URL") || "http://localhost:4000"

# Email Notifications (via Swoosh)
config :tamandua_server,
  email_enabled: System.get_env("EMAIL_ENABLED") == "true",
  notification_from_email: System.get_env("NOTIFICATION_FROM_EMAIL") || "alerts@tamandua.local"

config :tamandua_server, TamanduaServer.Alerts.Notifier.Email,
  adapter: Swoosh.Adapters.SMTP,
  relay: System.get_env("SMTP_SERVER") || "localhost",
  port: String.to_integer(System.get_env("SMTP_PORT") || "587"),
  username: System.get_env("SMTP_USERNAME"),
  password: System.get_env("SMTP_PASSWORD"),
  ssl: System.get_env("SMTP_SSL") == "true",
  tls: :always,
  auth: :always,
  retries: 2

# SMS Notifications (via Twilio)
config :tamandua_server,
  twilio_enabled: System.get_env("TWILIO_ENABLED") == "true",
  twilio_account_sid: System.get_env("TWILIO_ACCOUNT_SID"),
  twilio_auth_token: System.get_env("TWILIO_AUTH_TOKEN"),
  twilio_phone_number: System.get_env("TWILIO_PHONE_NUMBER")

# Slack Notifications
config :tamandua_server,
  slack_enabled: System.get_env("SLACK_ENABLED") == "true",
  slack_webhook_url: System.get_env("SLACK_WEBHOOK_URL")

# Notification Deduplication
config :tamandua_server,
  notification_dedup_minutes:
    String.to_integer(System.get_env("NOTIFICATION_DEDUP_MINUTES") || "15")

# Digest Configuration
config :tamandua_server,
  digest_period_minutes: String.to_integer(System.get_env("DIGEST_PERIOD_MINUTES") || "15")

# Alert Deduplication Window
config :tamandua_server,
  alert_dedup_window_seconds:
    String.to_integer(System.get_env("ALERT_DEDUP_WINDOW_SECONDS") || "300")

# ===========================================================================
# Solana Blockchain Integration (Hackathon MVP)
# ===========================================================================
#
# Enables on-chain incident attestations and detection bounties.
# Uses Solana devnet by default. Set SOLANA_CLUSTER=mainnet-beta for production.
#
# Environment Variables:
#   SOLANA_ENABLED        - Enable/disable Solana integration (default: true)
#   SOLANA_RPC_URL        - Solana RPC endpoint (default: devnet)
#   SOLANA_PROGRAM_ID     - Tamanduá Attestation program ID
#   SOLANA_KEYPAIR_PATH   - Path to wallet keypair JSON
#   SOLANA_ATTESTATION_RECIPIENT - Optional recipient for memo attestations
#   SOLANA_BOUNTY_ENABLED - Enable detection bounties (default: true)

solana_enabled = System.get_env("SOLANA_ENABLED", "true") == "true"
solana_cluster = System.get_env("SOLANA_CLUSTER", "devnet")
solana_attestation_mode = System.get_env("SOLANA_ATTESTATION_MODE", "memo")

solana_rpc_url =
  case solana_cluster do
    "mainnet-beta" -> System.get_env("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
    "testnet" -> System.get_env("SOLANA_RPC_URL", "https://api.testnet.solana.com")
    _ -> System.get_env("SOLANA_RPC_URL", "https://api.devnet.solana.com")
  end

config :tamandua_server, TamanduaServer.Solana.Client,
  enabled: solana_enabled,
  rpc_url: solana_rpc_url,
  attestation_mode: solana_attestation_mode,
  program_id: System.get_env("SOLANA_PROGRAM_ID", "TamaNduA1111111111111111111111111111111111"),
  keypair_path: System.get_env("SOLANA_KEYPAIR_PATH", "~/.config/solana/id.json"),
  attestation_recipient: System.get_env("SOLANA_ATTESTATION_RECIPIENT")

config :tamandua_server, TamanduaServer.Solana.Bounty,
  enabled: System.get_env("SOLANA_BOUNTY_ENABLED", "true") == "true",
  default_bounty_lamports: String.to_integer(System.get_env("SOLANA_DEFAULT_BOUNTY", "100000000"))

# SOAR Integration
config :tamandua_server,
  soar_enabled: System.get_env("SOAR_ENABLED") == "true"

# Ticketing Integration (Jira, ServiceNow)
config :tamandua_server,
  ticketing_enabled: System.get_env("TICKETING_ENABLED") == "true",
  # AES-256-GCM key for credential encryption (32 bytes base64-encoded)
  ticketing_encryption_key: System.get_env("TICKETING_ENCRYPTION_KEY")
