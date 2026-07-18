defmodule TamanduaServer.LiveResponse.EvidenceSession do
  @moduledoc "Tenant-scoped, bounded sequence of independently audited screen snapshots."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "screen_capture_evidence_sessions" do
    field(:status, :string, default: "scheduled")
    field(:reason, :string)
    field(:capture_request, :map)
    field(:frame_count, :integer)
    field(:interval_seconds, :integer)
    field(:next_frame_index, :integer, default: 0)
    field(:requested_by_id, :binary_id)
    field(:requested_by_email, :string)
    field(:started_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)
    field(:cancelled_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:failure_reason, :string)
    field(:approval_status, :string, default: "not_required")
    field(:approval_expires_at, :utc_datetime_usec)
    field(:approved_by_id, :binary_id)
    field(:approved_at, :utc_datetime_usec)
    field(:alert_id, :binary_id)
    field(:investigation_id, :binary_id)
    field(:case_id, :binary_id)
    belongs_to(:mobile_command, TamanduaServer.Mobile.MDMCommand)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:agent, TamanduaServer.Agents.Agent)
    has_many(:artifacts, TamanduaServer.LiveResponse.ScreenCaptureArtifact)
    timestamps(type: :utc_datetime_usec)
  end

  def create_changeset(session, attrs) do
    session
    |> cast(attrs, [
      :organization_id,
      :agent_id,
      :status,
      :reason,
      :capture_request,
      :frame_count,
      :interval_seconds,
      :next_frame_index,
      :requested_by_id,
      :requested_by_email,
      :expires_at,
      :approval_status,
      :approval_expires_at,
      :alert_id,
      :investigation_id,
      :case_id
    ])
    |> validate_required([
      :organization_id,
      :agent_id,
      :status,
      :reason,
      :capture_request,
      :frame_count,
      :interval_seconds,
      :expires_at
    ])
    |> validate_length(:reason, min: 1, max: 500)
    |> validate_number(:frame_count, greater_than_or_equal_to: 2, less_than_or_equal_to: 30)
    |> validate_number(:interval_seconds, greater_than_or_equal_to: 5, less_than_or_equal_to: 60)
    |> validate_inclusion(
      :status,
      ~w(pending_approval scheduled running completed partial cancelled failed expired)
    )
    |> validate_inclusion(:approval_status, ~w(not_required pending approved expired))
    |> validate_session_class()
    |> validate_approval_coherence()
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:investigation_id)
    |> foreign_key_constraint(:case_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id)
  end

  defp validate_session_class(changeset) do
    frames = get_field(changeset, :frame_count)
    interval = get_field(changeset, :interval_seconds)
    approval = get_field(changeset, :approval_status)

    cond do
      is_integer(frames) and approval == "not_required" and frames > 10 ->
        add_error(changeset, :frame_count, "requires long-session approval above 10 frames")

      is_integer(frames) and is_integer(interval) and (frames - 1) * interval > 1_800 ->
        add_error(changeset, :frame_count, "session duration exceeds 1800 seconds")

      true ->
        changeset
    end
  end

  defp validate_approval_coherence(changeset) do
    status = get_field(changeset, :status)
    approval = get_field(changeset, :approval_status)
    approval_expires_at = get_field(changeset, :approval_expires_at)

    cond do
      approval == "pending" and (status != "pending_approval" or is_nil(approval_expires_at)) ->
        add_error(changeset, :approval_status, "pending approval requires status and expiry")

      approval == "not_required" and status == "pending_approval" ->
        add_error(changeset, :approval_status, "pending session must require approval")

      true ->
        changeset
    end
  end
end
