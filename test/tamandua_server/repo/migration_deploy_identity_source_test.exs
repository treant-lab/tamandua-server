defmodule TamanduaServer.Repo.MigrationDeployIdentitySourceTest do
  use ExUnit.Case, async: true

  @raw_deployment "../../deploy/kubernetes/backend/deployment.yaml"
  @raw_job "../../deploy/kubernetes/backend/migration-job.yaml"
  @helm_deployment "../../deploy/helm/tamandua/templates/server-deployment.yaml"
  @helm_job "../../deploy/helm/tamandua/templates/server-migration-job.yaml"
  @helm_helpers "../../deploy/helm/tamandua/templates/_helpers.tpl"
  @ansible "../../deploy/ansible/playbooks/tamandua-stack.yml"
  @raw_renderer "../../deploy/kubernetes/scripts/render-server-release-manifests.py"
  @proxmox "../../deploy/scripts/proxmox/deploy-tamandua-server-light-safe.ps1"

  test "ordinary server deployments have no per-pod migration or migrator secret" do
    for path <- [@raw_deployment, @helm_deployment] do
      source = File.read!(path)
      refute source =~ "db-migrate"
      refute source =~ "MIGRATOR_DATABASE_URL"
      refute source =~ "migrator-database-url"
      refute source =~ "/app/bin/migrate"
    end

    deploy_sources =
      "../../deploy/**/*"
      |> Path.wildcard()
      |> Enum.filter(&File.regular?/1)
      |> Enum.map(&File.read!/1)
      |> Enum.join("\n")

    refute deploy_sources =~ "/app/bin/migrate"
  end

  test "raw Kubernetes migration is an explicit one-shot job" do
    source = File.read!(@raw_job)

    assert source =~ "kind: Job"
    assert source =~ "completions: 1"
    assert source =~ "parallelism: 1"
    assert source =~ "backoffLimit: 0"
    assert source =~ "MIGRATOR_DATABASE_URL"
    refute source =~ "- name: DATABASE_URL\n"
    assert source =~ "/app/bin/tamandua_server"
    assert source =~ "TamanduaServer.Release.migrate()"
    refute source =~ "/app/bin/migrate"
  end

  test "raw Kubernetes pair fails closed until one identical digest is rendered" do
    deployment = File.read!(@raw_deployment)
    job = File.read!(@raw_job)
    renderer = File.read!(@raw_renderer)

    assert deployment =~ ~s(image: "__TAMANDUA_SERVER_IMAGE__")
    assert job =~ ~s(image: "__TAMANDUA_SERVER_IMAGE__")
    refute deployment =~ "tamandua/server:1.0.0"
    refute job =~ "tamandua/server:1.0.0"
    assert renderer =~ "registry/repository@sha256:<64 lowercase hex>"
    assert renderer =~ "migration Job and server Deployment must use the requested identical digest"
    assert renderer =~ "unresolved image placeholder"
  end

  test "Proxmox migration secret is publisher-supplied and ephemeral" do
    source = File.read!(@proxmox)

    refute source =~ "set -a"
    refute source =~ ". ./.env"
    assert source =~ "$env:MIGRATOR_DATABASE_URL"
    assert source =~ "migration_secret_provenance=authorized_publisher_environment"
    assert source =~ "chmod 600 '$remoteMigratorSecret'"
    assert source =~ "trap cleanup_migrator_secret EXIT HUP INT TERM"
    assert source =~ ~s(provenance = "authorized-publisher-environment")
    assert source =~ "Remove-Item -LiteralPath $migratorSecretPath"
    refute source =~ "Get-FileHash -LiteralPath $migratorSecretPath"
  end

  test "Helm blocks install and upgrade on one migration hook" do
    source = File.read!(@helm_job)

    assert source =~ ~s("helm.sh/hook": pre-install,pre-upgrade)
    assert source =~ "completions: 1"
    assert source =~ "parallelism: 1"
    assert source =~ "server.migrations.serviceAccountName"
    refute source =~ ~s(serviceAccountName: {{ include "tamandua.serviceAccountName" . }})
    assert source =~ "server.image.digest is required"
    assert source =~ ~s(regexMatch "^sha256:[a-f0-9]{64}$")
    assert source =~ "MIGRATOR_DATABASE_URL"
    refute source =~ "- name: DATABASE_URL\n"
    assert source =~ "/app/bin/tamandua_server"
    assert source =~ "TamanduaServer.Release.migrate()"

    helpers = File.read!(@helm_helpers)
    assert helpers =~ ~s(printf "%s/%s@%s")
    assert helpers =~ ~s(printf "%s@%s")
  end

  test "Ansible runs one release task and aborts before cutover on failure" do
    source = File.read!(@ansible)
    migration_at = byte_offset(source, "- name: Run database migrations")
    cutover_at = byte_offset(source, "- name: Start services with Docker Compose")
    migration_lane = binary_part(source, migration_at, cutover_at - migration_at)

    assert migration_at < cutover_at
    assert source =~ "run_once: true"
    assert source =~ "MIGRATOR_DATABASE_URL"
    assert source =~ "/app/bin/tamandua_server"
    assert source =~ "TamanduaServer.Release.migrate()"
    refute migration_lane =~ "ignore_errors: yes"
    refute migration_lane =~ "/app/bin/migrate"
  end

  defp byte_offset(source, marker) do
    {offset, _length} = :binary.match(source, marker)
    offset
  end
end
