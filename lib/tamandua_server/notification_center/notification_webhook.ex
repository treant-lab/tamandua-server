defmodule TamanduaServer.NotificationCenter.NotificationWebhook do
  @moduledoc """
  Schema for webhook notification configurations.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @methods ["GET", "POST", "PUT", "PATCH"]
  @auth_types ["none", "basic", "bearer", "api_key"]

  schema "notification_webhooks" do
    field :name, :string
    field :url, :string
    field :method, :string, default: "POST"

    field :headers, :map, default: %{}
    field :auth_type, :string
    field :auth_config, :map, default: %{}

    field :notification_types, {:array, :string}, default: []
    field :enabled, :boolean, default: true

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  def changeset(webhook, attrs) do
    webhook
    |> cast(attrs, [
      :organization_id,
      :name,
      :url,
      :method,
      :headers,
      :auth_type,
      :auth_config,
      :notification_types,
      :enabled
    ])
    |> validate_required([:organization_id, :name, :url])
    |> validate_inclusion(:method, @methods)
    |> validate_inclusion(:auth_type, @auth_types)
    |> validate_url(:url)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_url(changeset, field) do
    case get_field(changeset, field) do
      nil ->
        changeset

      url when is_binary(url) ->
        uri = URI.parse(url)

        if uri.scheme in ["http", "https"] and uri.host do
          changeset
        else
          add_error(changeset, field, "must be a valid HTTP/HTTPS URL")
        end

      _ ->
        add_error(changeset, field, "must be a string")
    end
  end

  def methods, do: @methods
  def auth_types, do: @auth_types
end
