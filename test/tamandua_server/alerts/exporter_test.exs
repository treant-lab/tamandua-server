defmodule TamanduaServer.Alerts.ExporterTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts.{Exporter, ExportJob, ExportTemplate}
  alias TamanduaServer.Repo

  describe "create_export/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{organization: org, user: user}
    end

    test "creates export job with valid params", %{organization: org, user: user} do
      assert {:ok, job} =
               Exporter.create_export(
                 org.id,
                 user.id,
                 format: "csv",
                 columns: ["severity", "title"],
                 delivery_method: "download"
               )

      assert job.organization_id == org.id
      assert job.user_id == user.id
      assert job.format == "csv"
      assert job.status == "pending"
    end

    test "enqueues Oban job", %{organization: org, user: user} do
      {:ok, _job} =
        Exporter.create_export(
          org.id,
          user.id,
          format: "json",
          delivery_method: "download"
        )

      assert_enqueued(worker: TamanduaServer.Workers.ExportWorker)
    end
  end

  describe "list_export_jobs/2" do
    test "lists jobs for organization" do
      org1 = insert(:organization)
      org2 = insert(:organization)
      user1 = insert(:user, organization: org1)

      job1 = insert(:export_job, organization: org1, user: user1)
      job2 = insert(:export_job, organization: org1, user: user1)
      _job3 = insert(:export_job, organization: org2)

      jobs = Exporter.list_export_jobs(org1.id)

      assert length(jobs) == 2
      assert job1.id in Enum.map(jobs, & &1.id)
      assert job2.id in Enum.map(jobs, & &1.id)
    end

    test "respects limit and offset" do
      org = insert(:organization)
      user = insert(:user, organization: org)

      for _ <- 1..10 do
        insert(:export_job, organization: org, user: user)
      end

      jobs = Exporter.list_export_jobs(org.id, limit: 5, offset: 0)
      assert length(jobs) == 5

      jobs = Exporter.list_export_jobs(org.id, limit: 5, offset: 5)
      assert length(jobs) == 5
    end
  end

  describe "create_template/1" do
    test "creates template with valid params" do
      org = insert(:organization)
      user = insert(:user, organization: org)

      attrs = %{
        name: "Weekly Report",
        format: "pdf",
        columns: ["severity", "title", "status"],
        organization_id: org.id,
        created_by_id: user.id
      }

      assert {:ok, template} = Exporter.create_template(attrs)
      assert template.name == "Weekly Report"
      assert template.format == "pdf"
    end

    test "validates required fields" do
      assert {:error, changeset} = Exporter.create_template(%{})
      assert "can't be blank" in errors_on(changeset).name
      assert "can't be blank" in errors_on(changeset).format
    end

    test "validates format inclusion" do
      org = insert(:organization)
      user = insert(:user, organization: org)

      attrs = %{
        name: "Test",
        format: "xml",
        organization_id: org.id,
        created_by_id: user.id
      }

      assert {:error, changeset} = Exporter.create_template(attrs)
      assert "is invalid" in errors_on(changeset).format
    end
  end

  describe "list_templates/2" do
    test "lists user's own templates and shared templates" do
      org = insert(:organization)
      user1 = insert(:user, organization: org)
      user2 = insert(:user, organization: org)

      # User1's private template
      template1 = insert(:export_template, organization: org, created_by: user1, is_shared: false)

      # User2's private template (should not be visible to user1)
      _template2 = insert(:export_template, organization: org, created_by: user2, is_shared: false)

      # User2's shared template (should be visible to user1)
      template3 = insert(:export_template, organization: org, created_by: user2, is_shared: true)

      templates = Exporter.list_templates(org.id, user1.id)

      assert length(templates) == 2
      assert template1.id in Enum.map(templates, & &1.id)
      assert template3.id in Enum.map(templates, & &1.id)
    end
  end

  describe "cancel_export_job/1" do
    test "cancels pending job" do
      job = insert(:export_job, status: "pending")

      assert {:ok, updated_job} = Exporter.cancel_export_job(job.id)
      assert updated_job.status == "cancelled"
      assert updated_job.completed_at
    end

    test "cancels processing job" do
      job = insert(:export_job, status: "processing")

      assert {:ok, updated_job} = Exporter.cancel_export_job(job.id)
      assert updated_job.status == "cancelled"
    end

    test "cannot cancel completed job" do
      job = insert(:export_job, status: "completed")

      assert {:error, :cannot_cancel_completed_job} = Exporter.cancel_export_job(job.id)
    end
  end

  describe "cleanup_expired_exports/0" do
    test "deletes expired export files" do
      expired_time = DateTime.utc_now() |> DateTime.add(-25, :hour)

      job = insert(:export_job, status: "completed", url_expires_at: expired_time)

      # Create a dummy file
      File.mkdir_p!("priv/static/exports")
      file_path = "priv/static/exports/test_export.csv"
      File.write!(file_path, "test data")

      job
      |> Ecto.Changeset.change(%{file_path: file_path})
      |> Repo.update!()

      assert File.exists?(file_path)

      Exporter.cleanup_expired_exports()

      refute File.exists?(file_path)
    end

    test "deletes old job records" do
      old_time = DateTime.utc_now() |> DateTime.add(-8, :day)

      old_job = insert(:export_job, completed_at: old_time)
      recent_job = insert(:export_job)

      Exporter.cleanup_expired_exports()

      assert Repo.get(ExportJob, recent_job.id)
      refute Repo.get(ExportJob, old_job.id)
    end
  end
end
