defmodule TamanduaServer.Release do
  @moduledoc """
  Release-safe database tasks used by deployment automation.

  These functions run through `bin/tamandua_server eval` and do not start the
  web endpoint. The Evidence Session preflight fails closed when historical
  rows would violate the tenant-scoped foreign keys added by the release.

  Migrations require `MIGRATOR_DATABASE_URL` and never fall back to the web
  runtime identity. The URL must address PostgreSQL directly or through a
  session pool because the global advisory lock is session-scoped.
  """

  import Ecto.Query, only: [from: 2]

  @app :tamandua_server
  @smoke_bearer_ttl {5, :minute}
  @transaction_pool_query_keys ~w(pool_mode pooling_mode pgbouncer_pool_mode)

  @evidence_tenant_checks [
    {"evidence session agent", "screen_capture_evidence_sessions", "agents",
     "s.agent_id = p.id AND s.organization_id <> p.organization_id"},
    {"evidence session mobile command", "screen_capture_evidence_sessions", "mdm_commands",
     "s.mobile_command_id = p.id AND s.organization_id <> p.organization_id"},
    {"evidence session alert", "screen_capture_evidence_sessions", "alerts",
     "s.alert_id = p.id AND s.organization_id <> p.organization_id"},
    {"evidence session investigation", "screen_capture_evidence_sessions", "investigations",
     "s.investigation_id = p.id AND s.organization_id <> p.organization_id"},
    {"evidence session case", "screen_capture_evidence_sessions", "case_investigations",
     "s.case_id = p.id AND s.organization_id <> p.organization_id"},
    {"screen artifact agent", "screen_capture_artifacts", "agents",
     "s.agent_id = p.id AND s.organization_id <> p.organization_id"},
    {"screen artifact mobile command", "screen_capture_artifacts", "mdm_commands",
     "s.mobile_command_id = p.id AND s.organization_id <> p.organization_id"},
    {"screen artifact evidence session", "screen_capture_artifacts",
     "screen_capture_evidence_sessions",
     "s.evidence_session_id = p.id AND (s.organization_id <> p.organization_id OR s.agent_id <> p.agent_id)"},
    {"evidence export session", "evidence_session_exports", "screen_capture_evidence_sessions",
     "s.evidence_session_id = p.id AND s.organization_id <> p.organization_id"},
    {"evidence diff session", "evidence_session_diffs", "screen_capture_evidence_sessions",
     "s.evidence_session_id = p.id AND s.organization_id <> p.organization_id"},
    {"evidence diff left artifact", "evidence_session_diffs", "screen_capture_artifacts",
     "s.left_artifact_id = p.id AND (s.organization_id <> p.organization_id OR s.evidence_session_id <> p.evidence_session_id)"},
    {"evidence diff right artifact", "evidence_session_diffs", "screen_capture_artifacts",
     "s.right_artifact_id = p.id AND (s.organization_id <> p.organization_id OR s.evidence_session_id <> p.evidence_session_id)"}
  ]

  def migrate do
    load_app()
    migrator_url = System.get_env("MIGRATOR_DATABASE_URL")
    migration_connection_preflight!(migrator_url)

    for repo <- repos() do
      with_migrator_url(repo, migrator_url, fn ->
        {:ok, _, _} =
          Ecto.Migrator.with_repo(repo, fn started_repo ->
            assert_migration_target_identity!(started_repo)
            Ecto.Migrator.run(started_repo, :up, all: true)
          end)
      end)
    end
  end

  @doc false
  def migration_target_identity! do
    load_app()
    migrator_url = System.get_env("MIGRATOR_DATABASE_URL")
    migration_connection_preflight!(migrator_url)

    identities =
      for repo <- repos() do
        with_migrator_url(repo, migrator_url, fn ->
          {:ok, identity, _} =
            Ecto.Migrator.with_repo(repo, fn started_repo ->
              migration_target_identity(started_repo)
            end)

          identity
        end)
      end

    case Enum.uniq(identities) do
      [identity] -> IO.write(identity)
      _ -> raise "configured migrator repositories do not resolve to one database target"
    end

    :ok
  end

  @doc false
  def migration_connection_preflight!(url) when not is_binary(url) or url == "" do
    raise "MIGRATOR_DATABASE_URL is required; DATABASE_URL is never used for migrations"
  end

  def migration_connection_preflight!(url) do
    if transaction_pooling_url?(url) do
      raise "migration connection must use a direct or session-pooled PostgreSQL endpoint"
    end

    :ok
  end

  defp transaction_pooling_url?(url) when is_binary(url) do
    query = URI.parse(url).query

    if is_binary(query) do
      query
      # Preserve duplicate keys so an appended benign value cannot hide an
      # earlier transaction-pooling declaration.
      |> URI.query_decoder()
      |> Enum.any?(fn {key, value} ->
        String.downcase(key) in @transaction_pool_query_keys and
          value |> String.trim() |> String.downcase() == "transaction"
      end)
    else
      false
    end
  rescue
    ArgumentError -> raise "MIGRATOR_DATABASE_URL contains an invalid query"
  end

  defp transaction_pooling_url?(_url), do: false

  defp with_migrator_url(repo, migrator_url, callback) do
    original = Application.get_env(@app, repo, [])
    Application.put_env(@app, repo, Keyword.put(original, :url, migrator_url), persistent: false)

    try do
      callback.()
    after
      Application.put_env(@app, repo, original, persistent: false)
    end
  end

  def evidence_tenant_preflight! do
    load_app()
    migrator_url = System.get_env("MIGRATOR_DATABASE_URL")
    migration_connection_preflight!(migrator_url)

    for repo <- repos() do
      with_migrator_url(repo, migrator_url, fn ->
        {:ok, _, _} =
          Ecto.Migrator.with_repo(repo, fn started_repo ->
            started_repo.transaction(fn ->
              Ecto.Adapters.SQL.query!(started_repo, "SET LOCAL app.rls_bypass = TRUE", [])

              case tenant_conflicts(started_repo) do
                [] -> :ok
                conflicts -> raise "Evidence Session tenant preflight failed: #{inspect(conflicts)}"
              end
            end)
          end)

        :ok
      end)
    end

    :ok
  end

  @doc false
  def smoke_bearer_token! do
    load_app()
    now = DateTime.utc_now()

    token =
      Enum.find_value(repos(), fn repo ->
        {:ok, token, _apps} =
          Ecto.Migrator.with_repo(repo, fn started_repo ->
            {:ok, user} =
              started_repo.transaction(fn ->
                Ecto.Adapters.SQL.query!(started_repo, "SET LOCAL app.rls_bypass = TRUE", [])

                from(u in TamanduaServer.Accounts.User,
                  join: organization in TamanduaServer.Accounts.Organization,
                  on: organization.id == u.organization_id,
                  join: user_role in TamanduaServer.Accounts.UserRole,
                  on:
                    user_role.user_id == u.id and
                      (is_nil(user_role.expires_at) or user_role.expires_at > ^now),
                  join: assigned_role in TamanduaServer.Accounts.Role,
                  on:
                    assigned_role.id == user_role.role_id and
                      (is_nil(assigned_role.organization_id) or
                         assigned_role.organization_id == u.organization_id),
                  where: u.is_active == true,
                  where: organization.is_active == true,
                  where: not is_nil(u.organization_id),
                  where: assigned_role.builtin == true and assigned_role.slug == "admin",
                  order_by: [asc: u.inserted_at],
                  limit: 1
                )
                |> started_repo.one()
              end)

            case user do
              nil ->
                nil

              user ->
                case TamanduaServer.Guardian.encode_and_sign(user, %{},
                       ttl: @smoke_bearer_ttl
                     ) do
                  {:ok, token, _claims} -> token
                  {:error, reason} -> raise "failed to mint deploy smoke bearer: #{inspect(reason)}"
                end
            end
          end)

        token
      end) || raise "no active tenant user is available for authenticated deploy smoke"

    # This release task is consumed through command substitution. Never add
    # metadata, user details, or a trailing status line to stdout.
    IO.write(token)
    :ok
  end

  @doc false
  def smoke_bearer_ttl, do: @smoke_bearer_ttl

  def evidence_tenant_checks, do: @evidence_tenant_checks

  defp tenant_conflicts(repo) do
    @evidence_tenant_checks
    |> Enum.filter(fn {_label, child, parent, _predicate} ->
      relation_exists?(repo, child) and relation_exists?(repo, parent)
    end)
    |> Enum.flat_map(fn {label, child, parent, predicate} ->
      sql = "SELECT count(*) FROM #{child} s JOIN #{parent} p ON #{predicate}"
      %{rows: [[count]]} = Ecto.Adapters.SQL.query!(repo, sql, [])
      if count == 0, do: [], else: [{label, count}]
    end)
  end

  defp relation_exists?(repo, relation) do
    %{rows: [[exists?]]} =
      Ecto.Adapters.SQL.query!(repo, "SELECT to_regclass($1) IS NOT NULL", ["public.#{relation}"])

    exists?
  end

  defp assert_migration_target_identity!(repo) do
    expected = System.get_env("MIGRATOR_EXPECTED_DATABASE_IDENTITY")

    if not is_binary(expected) or not Regex.match?(~r/^\d+:\d+$/, expected) do
      raise "MIGRATOR_EXPECTED_DATABASE_IDENTITY is required in system_identifier:database_oid form"
    end

    if migration_target_identity(repo) != expected do
      raise "migrator database target identity changed after backup"
    end

    :ok
  end

  defp migration_target_identity(repo) do
    %{rows: [[system_identifier, database_oid]]} =
      Ecto.Adapters.SQL.query!(
        repo,
        "SELECT system_identifier::text, oid::text FROM pg_control_system(), pg_database WHERE datname = current_database()",
        []
      )

    "#{system_identifier}:#{database_oid}"
  end

  defp repos, do: Application.fetch_env!(@app, :ecto_repos)

  defp load_app do
    Application.load(@app)
  end
end
