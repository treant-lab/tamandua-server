defmodule TamanduaServer.LiveResponse.ScreenCaptureArtifact do
  @moduledoc "Persistent, tenant-scoped storage for bounded screen snapshots."

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.{Agent, AgentCommand}
  alias TamanduaServer.Mobile.MDMCommand

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "screen_capture_artifacts" do
    field(:status, :string, default: "pending")
    field(:mime, :string)
    field(:size, :integer)
    field(:sha256, :string)
    field(:display, :string, default: "all")
    field(:captured_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:uploaded_at, :utc_datetime_usec)
    field(:upload_token_hash, :binary)
    field(:upload_token_used_at, :utc_datetime_usec)
    field(:failure_reason, :string)
    field(:content, :binary, redact: true)
    field(:frame_index, :integer)

    belongs_to(:organization, Organization)
    belongs_to(:agent, Agent)
    belongs_to(:command, AgentCommand)
    belongs_to(:mobile_command, MDMCommand)
    belongs_to(:evidence_session, TamanduaServer.LiveResponse.EvidenceSession)

    timestamps(type: :utc_datetime_usec)
  end

  def create_changeset(artifact, attrs) do
    artifact
    |> cast(attrs, [
      :organization_id,
      :agent_id,
      :status,
      :display,
      :expires_at,
      :upload_token_hash,
      :evidence_session_id,
      :frame_index
    ])
    |> validate_required([
      :organization_id,
      :agent_id,
      :status,
      :display,
      :expires_at,
      :upload_token_hash
    ])
    |> validate_inclusion(:status, ~w(pending ready expired failed))
    |> validate_inclusion(:display, ["all"])
    |> validate_number(:frame_index, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:evidence_session_id)
    |> unique_constraint([:evidence_session_id, :frame_index])
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id)
  end

  def attach_command_changeset(artifact, command_id) do
    artifact
    |> change(command_id: command_id)
    |> foreign_key_constraint(:command_id)
    |> unique_constraint(:command_id)
  end

  def attach_mobile_command_changeset(artifact, mobile_command_id) do
    artifact
    |> change(mobile_command_id: mobile_command_id)
    |> foreign_key_constraint(:mobile_command_id)
    |> unique_constraint(:mobile_command_id)
  end

  def ready_changeset(artifact, attrs) do
    artifact
    |> cast(attrs, [:mime, :size, :sha256, :captured_at, :content])
    |> validate_required([:mime, :size, :sha256, :content])
    |> validate_inclusion(:mime, ["image/png"])
    |> validate_number(:size, greater_than: 0, less_than_or_equal_to: 8_388_608)
    |> validate_format(:sha256, ~r/\A[0-9a-f]{64}\z/)
    |> change(%{
      status: "ready",
      uploaded_at: DateTime.utc_now(),
      upload_token_hash: nil,
      upload_token_used_at: DateTime.utc_now()
    })
  end

  def terminal_changeset(artifact, status, reason) when status in ["expired", "failed"] do
    change(artifact,
      status: status,
      failure_reason: reason,
      upload_token_hash: nil,
      content: nil
    )
  end

  def for_tenant_agent(query \\ __MODULE__, organization_id, agent_id) do
    from(artifact in query,
      where: artifact.organization_id == ^organization_id and artifact.agent_id == ^agent_id
    )
  end
end
