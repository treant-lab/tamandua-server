defmodule TamanduaServer.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/treant-lab/tamandua-server"

  def project do
    [
      app: :tamandua_server,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test
      ],

      # Docs
      name: "Tamandua Server",
      source_url: @source_url,
      docs: docs(),

      # License
      licenses: ["Apache-2.0"]
    ]
  end

  def application do
    [
      mod: {TamanduaServer.Application, []},
      extra_applications: [:logger, :runtime_tools, :os_mon]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Phoenix
      {:phoenix, "~> 1.7.10"},
      {:phoenix_ecto, "~> 4.4"},
      {:phoenix_html, "~> 4.0"},
      {:phoenix_live_reload, "~> 1.4", only: :dev},
      {:phoenix_live_view, "~> 1.0"},
      {:phoenix_live_dashboard, "~> 0.8.2"},
      {:floki, ">= 0.30.0"},
      {:esbuild, "~> 0.8", runtime: Mix.env() == :dev},
      {:tailwind, "~> 0.2.0", runtime: Mix.env() == :dev},
      {:heroicons, "~> 0.5"},

      # Database
      {:ecto_sql, "~> 3.11"},
      {:postgrex, ">= 0.0.0"},

      # Authentication & Authorization
      {:guardian, "~> 2.3"},
      {:bcrypt_elixir, "~> 3.0"},
      {:argon2_elixir, "~> 4.0"},
      {:bodyguard, "~> 2.4"},

      # HTTP Client
      {:req, "~> 0.4"},
      {:finch, "~> 0.17"},

      # JSON / YAML
      {:jason, "~> 1.4"},
      {:yaml_elixir, "~> 2.9"},

      # Inertia.js
      {:inertia, "~> 2.5"},

      # Protocol Buffers
      {:protobuf, "~> 0.12"},

      # Message Queue
      {:broadway, "~> 1.0"},
      {:broadway_rabbitmq, "~> 0.8"},
      {:amqp, "~> 4.0"},

      # Caching
      {:nebulex, "~> 2.5"},
      {:shards, "~> 1.1"},
      {:decorator, "~> 1.4"},
      {:redix, "~> 1.2"},

      # Telemetry & Monitoring
      {:telemetry_metrics, "~> 0.6"},
      {:telemetry_poller, "~> 1.0"},
      {:phoenix_pubsub, "~> 2.1"},

      # OpenTelemetry
      {:opentelemetry, "~> 1.3"},
      {:opentelemetry_exporter, "~> 1.6"},
      {:opentelemetry_api, "~> 1.2"},
      {:opentelemetry_phoenix, "~> 1.1"},
      {:opentelemetry_ecto, "~> 1.1"},

      # Background Jobs
      {:oban, "~> 2.16"},

      # Utilities
      {:timex, "~> 3.7"},
      {:uuid, "~> 1.1"},
      {:slugify, "~> 1.3"},
      {:libgraph, "~> 0.16"},

      # Security
      {:plug_cowboy, "~> 2.6"},
      {:cors_plug, "~> 3.0"},
      {:hammer, "~> 6.1"},
      {:fuse, "~> 2.5"},

      # Secrets Management
      {:libvault, "~> 0.2"},
      {:ex_aws, "~> 2.5"},
      {:ex_aws_s3, "~> 2.5"},
      {:ex_aws_secretsmanager, "~> 2.0"},
      {:hackney, "~> 1.18"},
      {:sweet_xml, "~> 0.7"},

      # Email
      {:swoosh, "~> 1.14"},

      # PDF Generation
      {:chromic_pdf, "~> 1.15"},

      # Cron Expression Parsing
      {:crontab, "~> 1.1"},

      # CSV Generation
      {:nimble_csv, "~> 1.2"},

      # Markdown Processing
      {:earmark, "~> 1.4"},

      # Development & Testing
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:faker, "~> 0.17", only: [:dev, :test]},
      {:mox, "~> 1.1", only: :test},
      {:mix_test_watch, "~> 1.1", only: [:dev, :test], runtime: false},
      {:wallaby, "~> 0.30", only: :test, runtime: false},
      {:ex_machina, "~> 2.7", only: :test},
      {:stream_data, "~> 1.0", only: :test},
      {:benchee, "~> 1.1", only: [:dev, :test]},
      {:benchee_html, "~> 1.0", only: [:dev, :test]},

      # Release
      {:gettext, "~> 0.24"},
      {:dns_cluster, "~> 0.1.1"},

      # GraphQL
      {:absinthe, "~> 1.7"},
      {:absinthe_plug, "~> 1.5"},
      {:absinthe_phoenix, "~> 2.0"},
      {:dataloader, "~> 2.0"},

      # Billing / Payments
      {:stripity_stripe, "~> 3.2"},

      # Native performance (Rust NIFs) - disabled for Docker builds
      # {:tamandua_nif, in_umbrella: true, optional: true}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup", "assets.setup", "assets.build"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      "assets.setup": ["tailwind.install --if-missing", "esbuild.install --if-missing"],
      "assets.build": ["tailwind default", "esbuild default", "assets.build.react"],
      "assets.deploy": [
        "tailwind default --minify",
        "esbuild default --minify",
        "assets.build.react",
        "phx.digest"
      ],
      "assets.setup.react": ["cmd npm install --prefix assets"],
      "assets.build.react": ["cmd npm run build --prefix assets"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end
end
