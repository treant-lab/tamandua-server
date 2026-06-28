defmodule TamanduaServer.Mobile.AppGuardResearchSubmission do
  @moduledoc """
  App Guard research submission queued for reviewer triage.

  Mirrors `tamandua.app_guard.research_submission/v1` and links evidence back
  to App Guard events and scoped build manifests without storing raw secrets.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.AppGuardResearchProgram

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @severities ~w(info low medium high critical)
  @statuses ~w(submitted triaging needs_more_info accepted duplicate not_applicable resolved paid closed)
  @decisions ~w(accepted duplicate not_applicable needs_more_info)

  schema "app_guard_research_submissions" do
    field(:submission_id, :string)
    field(:program_id, :string)
    field(:researcher_id, :string)
    field(:title, :string)
    field(:description, :string)
    field(:severity, :string)
    field(:status, :string)
    field(:cvss, :map, default: %{})
    field(:technical_details, :map, default: %{})
    field(:evidence_links, :map, default: %{})
    field(:attachments, {:array, :map}, default: [])
    field(:validation, :map, default: %{})
    field(:reward, :map, default: %{})
    field(:submitted_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    belongs_to(:research_program, AppGuardResearchProgram)

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(
    organization_id research_program_id submission_id program_id researcher_id title
    severity status technical_details submitted_at
  )a

  def changeset(submission, attrs) do
    attrs = normalize_attrs(attrs)

    submission
    |> cast(
      attrs,
      @required_fields ++
        [:description, :cvss, :evidence_links, :attachments, :validation, :reward]
    )
    |> validate_required(@required_fields)
    |> validate_format(:submission_id, ~r/^agsub_[a-zA-Z0-9_-]+$/)
    |> validate_length(:title, min: 1, max: 220)
    |> validate_length(:description, max: 8000)
    |> validate_inclusion(:severity, @severities)
    |> validate_inclusion(:status, @statuses)
    |> validate_technical_details()
    |> validate_evidence_links()
    |> validate_attachments()
    |> validate_review()
    |> unique_constraint([:organization_id, :submission_id])
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:research_program_id)
  end

  def validation_changeset(submission, attrs) do
    attrs = normalize_validation_attrs(attrs)

    submission
    |> cast(attrs, [:status, :validation, :reward])
    |> validate_required([:status, :validation])
    |> validate_inclusion(:status, @statuses)
    |> validate_review()
  end

  def by_organization(query \\ __MODULE__, organization_id) do
    from(submission in query, where: submission.organization_id == ^organization_id)
  end

  def by_submission_id(query \\ __MODULE__, submission_id) do
    from(submission in query, where: submission.submission_id == ^submission_id)
  end

  def by_program_id(query \\ __MODULE__, program_id) do
    from(submission in query, where: submission.program_id == ^program_id)
  end

  def by_status(query \\ __MODULE__, status) do
    from(submission in query, where: submission.status == ^status)
  end

  def latest_first(query \\ __MODULE__) do
    from(submission in query, order_by: [desc: submission.submitted_at])
  end

  defp normalize_attrs(attrs) do
    attrs
    |> Map.put_new("submitted_at", attrs["submitted_at"] || attrs[:submitted_at])
    |> Map.put_new("attachments", attrs["attachments"] || attrs[:attachments] || [])
    |> Map.put_new("status", attrs["status"] || attrs[:status] || "submitted")
  end

  defp normalize_validation_attrs(attrs) do
    status = attrs["status"] || attrs[:status] || attrs["decision"] || attrs[:decision]
    validation = attrs["validation"] || attrs[:validation] || attrs

    %{
      "status" => status,
      "validation" => validation,
      "reward" => attrs["reward"] || attrs[:reward] || %{}
    }
  end

  defp validate_technical_details(changeset) do
    details = get_field(changeset, :technical_details) || %{}

    changeset
    |> validate_nested_string(details, :technical_details, "proof_of_concept")
    |> validate_nested_list(details, :technical_details, "reproduction_steps")
    |> validate_nested_string(details, :technical_details, "impact")
  end

  defp validate_evidence_links(changeset) do
    links = get_field(changeset, :evidence_links) || %{}

    changeset
    |> validate_nested_list(links, :evidence_links, "app_guard_event_ids")
    |> validate_nested_list(links, :evidence_links, "fixed_build_manifest_ids")
  end

  defp validate_attachments(changeset) do
    attachments = get_field(changeset, :attachments) || []

    Enum.reduce(attachments, changeset, fn attachment, acc ->
      sha256 = nested_value(attachment, "sha256")

      if is_binary(sha256) and Regex.match?(~r/^[a-fA-F0-9]{64}$/, sha256) do
        acc
      else
        add_error(acc, :attachments, "sha256 must be a 64-character SHA256")
      end
    end)
  end

  defp validate_review(changeset) do
    validation = get_field(changeset, :validation) || %{}
    decision = nested_value(validation, "decision")

    if is_nil(decision) or decision in @decisions do
      changeset
    else
      add_error(changeset, :validation, "decision must be one of: #{Enum.join(@decisions, ", ")}")
    end
  end

  defp validate_nested_string(changeset, source, parent, field) do
    value = nested_value(source, field)

    if is_binary(value) and String.trim(value) != "" do
      changeset
    else
      add_error(changeset, parent, "#{field} is required")
    end
  end

  defp validate_nested_list(changeset, source, parent, field) do
    value = nested_value(source, field)

    if is_list(value) and value != [] do
      changeset
    else
      add_error(changeset, parent, "#{field} must be a non-empty list")
    end
  end

  defp nested_value(source, field) do
    field
    |> String.split(".")
    |> Enum.reduce(source, fn key, current ->
      if is_map(current),
        do: Map.get(current, key) || Map.get(current, String.to_atom(key)),
        else: nil
    end)
  end
end
