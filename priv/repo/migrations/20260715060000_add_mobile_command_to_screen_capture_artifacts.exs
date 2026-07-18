defmodule TamanduaServer.Repo.Migrations.AddMobileCommandToScreenCaptureArtifacts do
  use Ecto.Migration

  def change do
    alter table(:screen_capture_artifacts) do
      add(
        :mobile_command_id,
        references(:mdm_commands, type: :binary_id, on_delete: :nilify_all)
      )
    end

    create(unique_index(:screen_capture_artifacts, [:mobile_command_id]))

    create(
      constraint(:screen_capture_artifacts, :screen_capture_artifacts_single_command_check,
        check: "num_nonnulls(command_id, mobile_command_id) <= 1"
      )
    )
  end
end
