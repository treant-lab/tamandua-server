defmodule TamanduaServer.Deception.BreadcrumbGenerator do
  @moduledoc """
  Content generation for breadcrumbs (honeyfiles/honeytokens).

  Generates realistic fake credentials, documents, and configuration files
  that can be deployed to agent endpoints as deception artifacts.
  """

  alias TamanduaServer.Deception.Breadcrumbs

  @doc """
  Generate breadcrumb content based on type and OS.

  Returns a map with:
  - content: The file content (binary)
  - filename: Suggested filename
  - extension: File extension
  - path_suggestions: Recommended deployment paths for this OS
  """
  @spec generate(Breadcrumbs.decoy_type(), String.t()) :: %{
          content: binary(),
          filename: String.t(),
          extension: String.t(),
          path_suggestions: [String.t()]
        }
  def generate(type, os_type) do
    case type do
      :credential -> generate_credential_file(os_type)
      :document -> generate_document(os_type)
      :ssh_key -> generate_ssh_key(os_type)
      :api_token -> generate_api_token(os_type)
      :cloud_credential -> generate_cloud_credential(os_type)
      :browser_password -> generate_browser_password(os_type)
      :kube_config -> generate_kube_config(os_type)
      :env_file -> generate_env_file(os_type)
      :database -> generate_database_config(os_type)
      :network_share -> generate_network_share(os_type)
    end
  end

  # ============================================================================
  # Generators
  # ============================================================================

  defp generate_document(os_type) do
    canary = generate_canary_token()
    year = DateTime.utc_now().year

    content = """
    CONFIDENTIAL - Internal Financial Report Q4 #{year - 1}

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    INTERNAL USE ONLY - DO NOT DISTRIBUTE
    Document ID: #{canary}
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    EXECUTIVE SUMMARY

    Total Revenue: $15,432,890.00
    Operating Costs: $9,876,543.00
    Net Profit: $5,556,347.00
    Growth Rate: +18.3% YoY

    KEY ACCOUNTS & CONTRACTS

    1. Enterprise Client Alpha Corp
       - Annual Contract Value: $3,200,000
       - Renewal Date: #{year}/06/30
       - Contact: Sarah Johnson (sjohnson@alphacorp.com)

    2. Government Contract - DHS-2024-8765
       - Contract Value: $2,450,000
       - Classification: CUI
       - Program Manager: David Chen (david.chen@dhs.gov)

    3. Healthcare Division - St. Mary's Hospital Network
       - Contract Value: $4,100,000
       - Services: Cloud Infrastructure, SOC Operations
       - HIPAA Compliance Required

    BANKING DETAILS (Wire Transfers)

    Primary Operating Account:
    Bank: First National Corporate Bank
    Account Number: 4532-8876-2341-9087
    Routing: 021000089
    SWIFT: FNBCUS33XXX

    Payroll Account:
    Account Number: 7845-2341-8876-4532

    CREDENTIALS (Emergency Access)

    Financial System Login: finance_admin
    Temporary Password: TAMANDUA_DECOY_PASSWORD_#{String.slice(canary, 0..7)}
    VPN: vpn.internal.financecorp.local

    For questions contact: CFO Office
    Email: cfo@internal.financecorp.com
    Phone: +1 (555) 0123-4567

    Tracking: TAMANDUA-#{canary}
    """

    %{
      content: content,
      filename: "Financial_Report_Q4_#{year - 1}_CONFIDENTIAL",
      extension: "txt",
      path_suggestions: document_paths(os_type)
    }
  end

  defp generate_credential_file(os_type) do
    canary = generate_canary_token()

    content = """
    # Production System Credentials
    # Last Updated: #{Date.utc_today()}
    # CONFIDENTIAL - Authorized Personnel Only
    # Document ID: TAMANDUA-#{canary}

    [VPN Access]
    Server: vpn-gateway.internal.corp.local
    Port: 1194
    Username: vpn_admin_backup
    Password: TAMANDUA_DECOY_VPN_PASSWORD_#{String.slice(canary, 0..7)}
    Certificate: /etc/vpn/corp-admin.pem

    [Production Database]
    Host: db-prod-master-01.internal
    Port: 5432
    Database: production
    Username: app_admin
    Password: TAMANDUA_DECOY_DB_PASSWORD_#{String.slice(canary, 8..15)}
    SSL Mode: require

    [Redis Cache]
    Host: redis-prod.internal
    Port: 6379
    Password: TAMANDUA_DECOY_REDIS_PASSWORD_#{String.slice(canary, 16..23)}

    [Admin Portal]
    URL: https://admin.internal.corp.local
    Username: system_administrator
    Password: TAMANDUA_DECOY_ADMIN_PASSWORD_#{String.slice(canary, 24..31)}
    MFA Backup Codes:
      - 1234-5678-9012
      - 3456-7890-1234
      - 5678-9012-3456

    [Emergency Break-Glass Account]
    Username: root_recovery
    Password: TAMANDUA_DECOY_BREAKGLASS_PASSWORD_#{String.slice(canary, 32..39)}
    """

    %{
      content: content,
      filename: "system_credentials_backup",
      extension: "txt",
      path_suggestions: credential_paths(os_type)
    }
  end

  defp generate_ssh_key(os_type) do
    canary = generate_canary_token()

    # Generate fake but realistic-looking SSH private key
    content = """
    -----BEGIN TAMANDUA DECOY SSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACDK8R5M#{String.slice(canary, 0..31)}V3QaZGN2Uy
    AAAAECkR5M#{String.slice(canary, 0..47)}V3QaZGN2Uy
    3K8R5M#{String.slice(canary, 0..31)}V3QaZGN2UyAAAAIXByb2R1Y3Rpb25fc2VydmVyX2
    FkbWluQGludGVybmFsLmNvcnABAgMEBQYH
    -----END TAMANDUA DECOY SSH PRIVATE KEY-----

    # Production Server Admin Key
    # Authorized for: prod-web-{01..05}.internal
    # Canary Token: TAMANDUA-#{canary}
    # Created: #{Date.utc_today()}
    #
    # Usage:
    #   ssh -i id_rsa_prod admin@prod-web-01.internal
    #
    # Passphrase: TAMANDUA_DECOY_SSH_PASSPHRASE_#{String.slice(canary, 0..7)} (if prompted)
    """

    %{
      content: content,
      filename: "id_rsa_prod_servers",
      extension: "",
      path_suggestions: ssh_key_paths(os_type)
    }
  end

  defp generate_api_token(os_type) do
    canary = generate_canary_token()

    content = """
    {
      "api_credentials": {
        "production": {
          "service": "Internal API Gateway",
          "base_url": "https://api.internal.corp.local/v2",
          "api_key": "tamandua-decoy-api-key-#{String.slice(canary, 0..31)}",
          "api_secret": "#{canary}",
          "created_at": "#{DateTime.utc_now() |> DateTime.to_iso8601()}",
          "permissions": ["read", "write", "admin", "delete"],
          "rate_limit": "10000/hour"
        },
        "stripe": {
          "publishable_key": "tamandua-decoy-publishable-key-#{String.slice(canary, 0..15)}",
          "secret_key": "tamandua-decoy-secret-key-#{String.slice(canary, 16..31)}",
          "webhook_secret": "tamandua-decoy-webhook-secret-#{String.slice(canary, 0..31)}"
        },
        "sendgrid": {
          "api_key": "tamandua-decoy-sendgrid-key-#{String.slice(canary, 0..21)}"
        },
        "twilio": {
          "account_sid": "AC#{String.slice(canary, 0..31)}",
          "auth_token": "tamandua-decoy-auth-token-#{String.slice(canary, 0..31)}",
          "phone_number": "+15550123456"
        },
        "slack": {
          "bot_token": "tamandua-decoy-slack-bot-token-#{String.slice(canary, 0..47)}",
          "webhook_url": "https://hooks.slack.invalid/services/T00/B00/#{String.slice(canary, 0..23)}"
        }
      },
      "_metadata": {
        "environment": "production",
        "created_by": "devops-admin",
        "last_rotated": "#{Date.utc_today()}",
        "canary_token": "TAMANDUA-#{canary}"
      }
    }
    """

    %{
      content: content,
      filename: "api_credentials_production",
      extension: "json",
      path_suggestions: api_token_paths(os_type)
    }
  end

  defp generate_cloud_credential(os_type) do
    canary = generate_canary_token()

    content = """
    # AWS Credentials File
    # Path: ~/.aws/credentials
    # Canary Token: TAMANDUA-#{canary}

    [default]
    aws_access_key_id = TAMANDUADECOY#{String.slice(canary, 0..11) |> String.upcase()}
    aws_secret_access_key = TAMANDUA_DECOY_AWS_SECRET_#{String.slice(canary, 0..15)}
    region = us-east-1

    [production]
    aws_access_key_id = TAMANDUADECOY#{String.slice(canary, 8..19) |> String.upcase()}
    aws_secret_access_key = TAMANDUA_DECOY_AWS_PROD_SECRET_#{String.slice(canary, 16..31)}
    region = us-west-2
    role_arn = arn:aws:iam::123456789012:role/ProductionAdmin

    [terraform]
    aws_access_key_id = TAMANDUADECOY#{String.slice(canary, 16..27) |> String.upcase()}
    aws_secret_access_key = TAMANDUA_DECOY_TF_SECRET_#{String.slice(canary, 0..15)}
    region = us-east-1

    # Azure Service Principal (stored separately)
    # File: ~/.azure/credentials.json
    # {
    #   "clientId": "12345678-1234-5678-#{String.slice(canary, 0..11)}",
    #   "clientSecret": "azure_#{canary}",
    #   "tenantId": "87654321-4321-8765-#{String.slice(canary, 12..23)}",
    #   "subscriptionId": "abcdef01-2345-6789-#{String.slice(canary, 24..35)}"
    # }

    # GCP Service Account Key Path
    # ~/.config/gcloud/application_default_credentials.json
    """

    %{
      content: content,
      filename: "credentials",
      extension: "",
      path_suggestions: cloud_credential_paths(os_type)
    }
  end

  defp generate_browser_password(os_type) do
    canary = generate_canary_token()

    # Simulated Chrome/Edge password database (SQLite format marker)
    content = """
    SQLite format 3\x00
    -- Chrome/Edge Password Database Backup
    -- Canary: TAMANDUA-#{canary}
    --
    -- This is a simulated password database file
    -- Real browsers encrypt passwords with OS keychain
    --
    CREATE TABLE logins (
      origin_url TEXT NOT NULL,
      action_url TEXT,
      username_element TEXT,
      username_value TEXT,
      password_element TEXT,
      password_value BLOB,
      submit_element TEXT,
      signon_realm TEXT NOT NULL,
      date_created INTEGER NOT NULL,
      blacklisted_by_user INTEGER NOT NULL,
      scheme INTEGER NOT NULL,
      password_type INTEGER,
      times_used INTEGER,
      form_data BLOB,
      date_synced INTEGER,
      display_name TEXT,
      icon_url TEXT,
      federation_url TEXT,
      skip_zero_click INTEGER,
      generation_upload_status INTEGER,
      possible_username_pairs BLOB,
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date_last_used INTEGER,
      moving_blocked_for BLOB,
      date_password_modified INTEGER
    );

    -- Sample entries (passwords would be encrypted in real DB)
    -- Mail: admin@company.com / #{String.slice(canary, 0..15)}
    -- AWS: root-account / AWS#{String.slice(canary, 0..11)}
    -- GitHub: enterprise-admin / GH#{String.slice(canary, 0..15)}
    -- Azure: admin@company.onmicrosoft.com / Azure#{String.slice(canary, 0..11)}
    """

    %{
      content: content,
      filename: "Login Data.bak",
      extension: "",
      path_suggestions: browser_password_paths(os_type)
    }
  end

  defp generate_kube_config(os_type) do
    canary = generate_canary_token()

    content = """
    apiVersion: v1
    kind: Config
    clusters:
    - cluster:
        certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWM=TAMANDUA#{String.slice(canary, 0..15)}
        server: https://k8s-prod-master.internal.corp.local:6443
      name: production-cluster
    - cluster:
        certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM=
        server: https://k8s-staging.internal.corp.local:6443
      name: staging-cluster
    - cluster:
        certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
        server: https://eks-prod-#{String.slice(canary, 0..7)}.us-west-2.eks.amazonaws.com
      name: aws-eks-production
    contexts:
    - context:
        cluster: production-cluster
        user: cluster-admin
        namespace: default
      name: production
    - context:
        cluster: staging-cluster
        user: developer
        namespace: development
      name: staging
    - context:
        cluster: aws-eks-production
        user: eks-admin
        namespace: kube-system
      name: eks-prod
    current-context: production
    preferences: {}
    users:
    - name: cluster-admin
      user:
        token: eyJhbGciOiJSUzI1NiIsImtpZCI6IlRBTUFORFVBLXt9In0.#{canary}.SIGNATURE
    - name: developer
      user:
        client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN=
        client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==
    - name: eks-admin
      user:
        exec:
          apiVersion: client.authentication.k8s.io/v1beta1
          command: aws
          args:
            - eks
            - get-token
            - --cluster-name
            - prod-cluster-#{String.slice(canary, 0..7)}
          env:
            - name: AWS_PROFILE
              value: production

    # Canary Token: TAMANDUA-#{canary}
    # Created: #{DateTime.utc_now() |> DateTime.to_iso8601()}
    # Cluster: production-cluster (k8s-prod-master.internal.corp.local)
    """

    %{
      content: content,
      filename: "config",
      extension: "",
      path_suggestions: kube_config_paths(os_type)
    }
  end

  defp generate_env_file(os_type) do
    canary = generate_canary_token()

    content = """
    # Production Environment Variables
    # DO NOT COMMIT TO VERSION CONTROL
    # Last Updated: #{Date.utc_today()}
    # Canary: TAMANDUA-#{canary}

    # Application
    NODE_ENV=production
    APP_ENV=production
    DEBUG=false
    LOG_LEVEL=info

    # Security
    SECRET_KEY=#{canary}
    JWT_SECRET=jwt_#{String.slice(canary, 0..31)}
    ENCRYPTION_KEY=#{String.slice(canary, 0..31)}
    SESSION_SECRET=sess_#{String.slice(canary, 0..23)}

    # Database
    DATABASE_URL=postgresql://admin:ProdDB!2024@prod-db-master.internal:5432/production?sslmode=require
    DB_POOL_SIZE=20
    DB_TIMEOUT=5000

    # Redis
    REDIS_URL=redis://:R3d1s_Pr0d!Auth@redis-prod.internal:6379/0
    REDIS_CACHE_TTL=3600

    # RabbitMQ
    RABBITMQ_URL=amqp://admin:R@bb1tMQ!Pr0d@rabbitmq-prod.internal:5672/production

    # Third-party APIs
    STRIPE_SECRET_KEY=tamandua-decoy-stripe-secret-#{String.slice(canary, 0..31)}
    STRIPE_WEBHOOK_SECRET=tamandua-decoy-stripe-webhook-#{String.slice(canary, 0..31)}

    SENDGRID_API_KEY=tamandua-decoy-sendgrid-key-#{String.slice(canary, 0..21)}

    TWILIO_ACCOUNT_SID=AC#{String.slice(canary, 0..31)}
    TWILIO_AUTH_TOKEN=#{String.slice(canary, 0..31)}

    SLACK_WEBHOOK_URL=https://hooks.slack.invalid/services/T00/B00/#{String.slice(canary, 0..23)}
    SLACK_BOT_TOKEN=tamandua-decoy-slack-bot-token-#{String.slice(canary, 0..47)}

    # AWS
    AWS_ACCESS_KEY_ID=TAMANDUADECOY#{String.slice(canary, 0..11) |> String.upcase()}
    AWS_SECRET_ACCESS_KEY=#{String.slice(canary, 0..39)}
    AWS_REGION=us-west-2
    AWS_S3_BUCKET=prod-app-storage-#{String.slice(canary, 0..7)}

    # OAuth
    GITHUB_CLIENT_ID=Iv1.#{String.slice(canary, 0..15)}
    GITHUB_CLIENT_SECRET=#{String.slice(canary, 0..39)}

    GOOGLE_CLIENT_ID=123456789-#{String.slice(canary, 0..11)}.apps.googleusercontent.com
    GOOGLE_CLIENT_SECRET=GOCSPX-#{String.slice(canary, 0..23)}

    # Monitoring
    SENTRY_DSN=https://#{String.slice(canary, 0..31)}@sentry.io/1234567
    DATADOG_API_KEY=#{String.slice(canary, 0..31)}

    # Feature Flags
    ENABLE_BETA_FEATURES=true
    ENABLE_ADMIN_API=true
    """

    %{
      content: content,
      filename: ".env.production",
      extension: "",
      path_suggestions: env_file_paths(os_type)
    }
  end

  defp generate_database_config(os_type) do
    canary = generate_canary_token()

    content = """
    -- Production Database Connection Configuration
    -- Generated: #{DateTime.utc_now() |> DateTime.to_iso8601()}
    -- Canary Token: TAMANDUA-#{canary}

    -- PostgreSQL Configuration
    -- File: pg_service.conf or database.yml

    [production]
    host=db-prod-master-01.internal.corp.local
    port=5432
    dbname=production
    user=app_admin
    password=ProdDB_S3cr3t!2024#{String.slice(canary, 0..7)}
    sslmode=require
    connect_timeout=10

    [production_replica]
    host=db-prod-replica-01.internal.corp.local
    port=5432
    dbname=production
    user=readonly_user
    password=R3adonlyU53r!2024
    sslmode=require

    -- MySQL Configuration (if applicable)
    -- [mysql-production]
    -- host=mysql-prod.internal.corp.local
    -- port=3306
    -- database=production
    -- user=app_user
    -- password=MySQL!Pr0d#{String.slice(canary, 0..7)}

    -- MongoDB Connection String
    -- mongodb://admin:M0ng0!Pr0d@mongo-prod-01.internal:27017,mongo-prod-02.internal:27017,mongo-prod-03.internal:27017/production?replicaSet=rs0&authSource=admin

    -- Redis Connection
    -- redis://:R3d1s!Auth#{String.slice(canary, 0..7)}@redis-prod.internal:6379/0

    -- Admin Database Credentials (Break-Glass)
    -- Username: postgres
    -- Password: TAMANDUA_DECOY_POSTGRES_PASSWORD_#{String.slice(canary, 0..7)}
    --
    -- Usage: psql -h db-prod-master-01.internal.corp.local -U postgres
    """

    %{
      content: content,
      filename: "database_production.conf",
      extension: "",
      path_suggestions: database_config_paths(os_type)
    }
  end

  defp generate_network_share(os_type) do
    canary = generate_canary_token()

    case os_type do
      "windows" ->
        # Windows shortcut (.lnk format simulation)
        content = """
        [InternetShortcut]
        URL=file://fileserver-prod.internal.corp.local/finance/confidential
        IconFile=\\\\fileserver-prod.internal.corp.local\\icons\\folder.ico
        IconIndex=0

        [Shell]
        Command=2
        IconFile=imageres.dll
        IconIndex=3

        ; Network Share Credentials
        ; Server: \\\\fileserver-prod.internal.corp.local
        ; Share: \\\\fileserver-prod.internal.corp.local\\finance
        ; Username: CORP\\finance_admin
        ; Password: TAMANDUA_DECOY_SHARE_PASSWORD_#{String.slice(canary, 0..7)}
        ;
        ; Alternative Shares:
        ; \\\\fileserver-prod.internal.corp.local\\hr
        ; \\\\fileserver-prod.internal.corp.local\\legal
        ; \\\\fileserver-prod.internal.corp.local\\executives
        ;
        ; Canary: TAMANDUA-#{canary}
        """

        %{
          content: content,
          filename: "Finance_Share",
          extension: "lnk",
          path_suggestions: ["Desktop", "Documents"]
        }

      _ ->
        # Linux/macOS - SMBFS mount script
        content = """
        #!/bin/bash
        # SMB/CIFS Network Share Mount Script
        # Canary: TAMANDUA-#{canary}
        # Last Updated: #{Date.utc_today()}

        # Finance File Server
        SHARE_SERVER="fileserver-prod.internal.corp.local"
        SHARE_NAME="finance"
        MOUNT_POINT="/mnt/finance"
        USERNAME="finance_admin"
        PASSWORD="F1n@nce!Shr!2024"
        DOMAIN="CORP"

        # Create mount point if it doesn't exist
        mkdir -p "$MOUNT_POINT"

        # Mount the share
        mount -t cifs "//$SHARE_SERVER/$SHARE_NAME" "$MOUNT_POINT" \\
          -o username="$USERNAME",password="$PASSWORD",domain="$DOMAIN",vers=3.0

        # Alternative mount command for macOS
        # mount_smbfs "//$DOMAIN;$USERNAME:$PASSWORD@$SHARE_SERVER/$SHARE_NAME" "$MOUNT_POINT"

        # Check mount status
        if mountpoint -q "$MOUNT_POINT"; then
          echo "Successfully mounted $SHARE_SERVER/$SHARE_NAME to $MOUNT_POINT"
        else
          echo "Failed to mount share"
          exit 1
        fi

        # Other available shares:
        # //fileserver-prod.internal.corp.local/hr
        # //fileserver-prod.internal.corp.local/legal
        # //fileserver-prod.internal.corp.local/executives
        """

        %{
          content: content,
          filename: "mount_finance_share",
          extension: "sh",
          path_suggestions: ["Documents", "scripts", "bin"]
        }
    end
  end

  # ============================================================================
  # Path Suggestions by OS
  # ============================================================================

  defp document_paths("windows"), do: ["Documents", "Desktop", "Downloads"]
  defp document_paths("macos"), do: ["Documents", "Desktop", "Downloads"]
  defp document_paths(_), do: ["Documents", "Downloads", "~"]

  defp credential_paths("windows"), do: ["Documents", "AppData\\Local", "AppData\\Roaming"]
  defp credential_paths("macos"), do: ["Documents", ".config", "Library/Application Support"]
  defp credential_paths(_), do: [".config", "Documents", "~"]

  defp ssh_key_paths(_), do: [".ssh"]

  defp api_token_paths("windows"), do: [".config", "AppData\\Roaming", "Documents"]
  defp api_token_paths("macos"), do: [".config", "Library/Application Support", "Documents"]
  defp api_token_paths(_), do: [".config", ".local/share", "Documents"]

  defp cloud_credential_paths(_), do: [".aws", ".azure", ".config/gcloud"]

  defp browser_password_paths("windows") do
    [
      "AppData\\Local\\Google\\Chrome\\User Data\\Default",
      "AppData\\Local\\Microsoft\\Edge\\User Data\\Default",
      "AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
    ]
  end

  defp browser_password_paths("macos") do
    [
      "Library/Application Support/Google/Chrome/Default",
      "Library/Application Support/Firefox/Profiles",
      "Library/Safari"
    ]
  end

  defp browser_password_paths(_) do
    [
      ".config/google-chrome/Default",
      ".mozilla/firefox",
      ".config/chromium/Default"
    ]
  end

  defp kube_config_paths(_), do: [".kube"]

  defp env_file_paths(_), do: ["projects", "code", "app", "src", "~"]

  defp database_config_paths("windows"), do: ["Documents", ".config", "AppData\\Roaming"]
  defp database_config_paths(_), do: [".config", ".local/share", "Documents"]

  # ============================================================================
  # Utilities
  # ============================================================================

  defp generate_canary_token do
    Ecto.UUID.generate() |> String.replace("-", "")
  end
end
