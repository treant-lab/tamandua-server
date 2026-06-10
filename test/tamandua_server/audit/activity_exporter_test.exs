defmodule TamanduaServer.Audit.ActivityExporterTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Audit.{ActivityExporter, ActivityLogger, AuditExport}

  setup do
    org = insert(:organization)
    user = insert(:user, organization: org)

    # Create some audit logs
    for i <- 1..10 do
      ActivityLogger.log(%{
        action: "test.action_#{i}",
        resource_type: "test",
        user_id: user.id,
        organization_id: org.id,
        ip_address: "192.168.1.#{rem(i, 255)}"
      })
    end

    {:ok, organization: org, user: user}
  end

  describe "create_export/1" do
    test "creates export job", %{organization: org, user: user} do
      {:ok, export} = ActivityExporter.create_export(%{
        organization_id: org.id,
        user_id: user.id,
        export_type: "csv",
        filters: %{}
      })

      assert export.status == "pending"
      assert export.export_type == "csv"
      assert export.organization_id == org.id
    end

    test "starts async export process", %{organization: org, user: user} do
      {:ok, export} = ActivityExporter.create_export(%{
        organization_id: org.id,
        user_id: user.id,
        export_type: "csv",
        filters: %{}
      })

      # Wait for async processing
      Process.sleep(500)

      export = Repo.get!(AuditExport, export.id)
      assert export.status in ["processing", "completed"]
    end
  end

  describe "export_to_csv/3" do
    test "exports audit logs to CSV format", %{organization: org} do
      output_path = "/tmp/test_export_#{:rand.uniform(10000)}.csv"

      {:ok, file_size} = ActivityExporter.export_to_csv(
        org.id,
        %{},
        output_path
      )

      assert file_size > 0
      assert File.exists?(output_path)

      # Verify CSV content
      content = File.read!(output_path)
      assert content =~ "Timestamp,User,Action"
      assert content =~ "test.action"

      # Cleanup
      File.rm!(output_path)
    end

    test "applies filters to export", %{organization: org, user: user} do
      ActivityLogger.log(%{
        action: "alert.created",
        resource_type: "alert",
        user_id: user.id,
        organization_id: org.id
      })

      output_path = "/tmp/test_filtered_#{:rand.uniform(10000)}.csv"

      {:ok, _} = ActivityExporter.export_to_csv(
        org.id,
        %{"action" => "alert.created"},
        output_path
      )

      content = File.read!(output_path)
      assert content =~ "alert.created"
      refute content =~ "test.action"

      File.rm!(output_path)
    end
  end

  describe "export_to_json/3" do
    test "exports audit logs to JSON format", %{organization: org} do
      output_path = "/tmp/test_export_#{:rand.uniform(10000)}.json"

      {:ok, file_size} = ActivityExporter.export_to_json(
        org.id,
        %{},
        output_path
      )

      assert file_size > 0
      assert File.exists?(output_path)

      # Verify JSON content
      content = File.read!(output_path)
      {:ok, data} = Jason.decode(content)
      assert is_list(data)
      assert length(data) > 0

      File.rm!(output_path)
    end
  end

  describe "process_export/1" do
    test "processes export job successfully", %{organization: org, user: user} do
      {:ok, export} = %AuditExport{}
      |> AuditExport.changeset(%{
        organization_id: org.id,
        user_id: user.id,
        export_type: "csv",
        filters: %{}
      })
      |> Repo.insert()

      ActivityExporter.process_export(export.id)

      export = Repo.get!(AuditExport, export.id)
      assert export.status == "completed"
      assert export.progress == 100
      assert export.file_path != nil
      assert export.file_size > 0
    end

    test "handles export errors gracefully", %{organization: org, user: user} do
      {:ok, export} = %AuditExport{}
      |> AuditExport.changeset(%{
        organization_id: org.id,
        user_id: user.id,
        export_type: "invalid_format",
        filters: %{}
      })
      |> Repo.insert()

      ActivityExporter.process_export(export.id)

      export = Repo.get!(AuditExport, export.id)
      assert export.status == "failed"
      assert export.error_message != nil
    end
  end
end
