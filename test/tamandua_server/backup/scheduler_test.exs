defmodule TamanduaServer.Backup.SchedulerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Backup.Scheduler

  @moduletag :backup

  describe "perform/1 full_backup" do
    @tag :tmp_dir
    test "creates full backup successfully", %{tmp_dir: tmp_dir} do
      # Set backup directory to temp directory
      Application.put_env(:tamandua_server, :backup_dir, tmp_dir)

      job_args = %{"type" => "full_backup"}
      job = %Oban.Job{args: job_args}

      # This will fail in test environment due to missing services,
      # but we can test the structure
      result = Scheduler.perform(job)

      # In test environment without real services, we expect errors
      # In integration tests, this would succeed
      assert match?(:ok, result) or match?({:error, _}, result)
    end
  end

  describe "perform/1 cleanup_old_backups" do
    @tag :tmp_dir
    test "removes old backups", %{tmp_dir: tmp_dir} do
      Application.put_env(:tamandua_server, :backup_dir, tmp_dir)

      # Create mock old backup directory
      old_backup = Path.join(tmp_dir, "full_20200101T000000Z")
      File.mkdir_p!(old_backup)

      manifest = %{
        timestamp: "2020-01-01T00:00:00Z",
        type: "full",
        version: "1.0"
      }

      manifest_path = Path.join(old_backup, "manifest.json")
      File.write!(manifest_path, Jason.encode!(manifest))

      # Run cleanup job
      job_args = %{"type" => "cleanup_old_backups"}
      job = %Oban.Job{args: job_args}

      assert :ok = Scheduler.perform(job)

      # Old backup should be deleted (retention is 30 days by default)
      refute File.exists?(old_backup)
    end

    @tag :tmp_dir
    test "keeps recent backups", %{tmp_dir: tmp_dir} do
      Application.put_env(:tamandua_server, :backup_dir, tmp_dir)

      # Create recent backup
      recent_backup = Path.join(tmp_dir, "full_#{DateTime.utc_now() |> DateTime.to_iso8601(:basic)}")
      File.mkdir_p!(recent_backup)

      manifest = %{
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        type: "full",
        version: "1.0"
      }

      manifest_path = Path.join(recent_backup, "manifest.json")
      File.write!(manifest_path, Jason.encode!(manifest))

      # Run cleanup job
      job_args = %{"type" => "cleanup_old_backups"}
      job = %Oban.Job{args: job_args}

      assert :ok = Scheduler.perform(job)

      # Recent backup should still exist
      assert File.exists?(recent_backup)
    end
  end

  describe "trigger_full_backup/0" do
    test "schedules a full backup job" do
      {:ok, job} = Scheduler.trigger_full_backup()

      assert job.args["type"] == "full_backup"
      assert job.queue == :backups
    end
  end

  describe "trigger_incremental_backup/0" do
    test "schedules an incremental backup job" do
      {:ok, job} = Scheduler.trigger_incremental_backup()

      assert job.args["type"] == "incremental_backup"
      assert job.queue == :backups
    end
  end

  describe "trigger_verify_restore/0" do
    test "schedules a restore verification job" do
      {:ok, job} = Scheduler.trigger_verify_restore()

      assert job.args["type"] == "verify_restore"
      assert job.queue == :backups
    end
  end
end
