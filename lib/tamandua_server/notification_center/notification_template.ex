defmodule TamanduaServer.NotificationCenter.NotificationTemplate do
  @moduledoc """
  Schema for notification templates using EEx templating.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @channels ["in_app", "email", "sms", "slack", "teams", "pagerduty", "webhook", "discord"]

  schema "notification_templates" do
    field :type, :string
    field :channel, :string
    field :name, :string
    field :description, :string

    field :subject_template, :string
    field :body_template, :string

    field :is_default, :boolean, default: false

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  def changeset(template, attrs) do
    template
    |> cast(attrs, [
      :organization_id,
      :type,
      :channel,
      :name,
      :description,
      :subject_template,
      :body_template,
      :is_default
    ])
    |> validate_required([:type, :channel, :name, :body_template])
    |> validate_inclusion(:channel, @channels)
    |> validate_inclusion(:type, TamanduaServer.NotificationCenter.Notification.notification_types())
    |> validate_template(:subject_template)
    |> validate_template(:body_template)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_template(changeset, field) do
    case get_field(changeset, field) do
      nil ->
        changeset

      template when is_binary(template) ->
        # Try to compile the template
        case EEx.compile_string(template) do
          {:ok, _} ->
            changeset

          {:error, reason} ->
            add_error(changeset, field, "invalid EEx template: #{inspect(reason)}")
        end

      _ ->
        changeset
    end
  rescue
    _ ->
      add_error(changeset, field, "invalid EEx template")
  end

  def channels, do: @channels
end
