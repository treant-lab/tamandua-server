defmodule TamanduaServer.Reports.ReportTemplate do
  @moduledoc """
  Schema for custom report templates created via the designer.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "report_templates" do
    field :name, :string
    field :description, :string
    field :category, :string
    field :is_public, :boolean, default: false
    field :is_system, :boolean, default: false

    # Layout configuration
    field :layout, :map, default: %{
      "orientation" => "portrait",
      "page_size" => "A4",
      "columns" => 12,
      "row_height" => 50
    }

    # Widget configurations
    field :widgets, {:array, :map}, default: []

    # Branding
    field :branding, :map, default: %{
      "logo_url" => nil,
      "primary_color" => "#0066cc",
      "company_name" => "Tamandua EDR"
    }

    # Metadata
    field :created_by, :string
    field :last_modified_by, :string
    field :version, :integer, default: 1
    field :tags, {:array, :string}, default: []

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :user, TamanduaServer.Accounts.User

    timestamps()
  end

  def changeset(template, attrs) do
    template
    |> cast(attrs, [
      :name,
      :description,
      :category,
      :is_public,
      :is_system,
      :layout,
      :widgets,
      :branding,
      :created_by,
      :last_modified_by,
      :version,
      :tags,
      :organization_id,
      :user_id
    ])
    |> validate_required([:name, :category])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:description, max: 1000)
    |> validate_inclusion(:category, ["security", "compliance", "operations", "executive", "custom"])
    |> validate_layout()
    |> validate_widgets()
    |> maybe_increment_version()
  end

  defp validate_layout(changeset) do
    case get_change(changeset, :layout) do
      nil -> changeset
      layout ->
        required_keys = ["orientation", "page_size", "columns", "row_height"]
        if Enum.all?(required_keys, &Map.has_key?(layout, &1)) do
          changeset
        else
          add_error(changeset, :layout, "missing required layout keys")
        end
    end
  end

  defp validate_widgets(changeset) do
    case get_change(changeset, :widgets) do
      nil -> changeset
      widgets when is_list(widgets) ->
        # Validate each widget has required fields
        valid? = Enum.all?(widgets, fn widget ->
          Map.has_key?(widget, "type") &&
          Map.has_key?(widget, "id") &&
          Map.has_key?(widget, "position") &&
          Map.has_key?(widget, "size")
        end)

        if valid? do
          changeset
        else
          add_error(changeset, :widgets, "invalid widget configuration")
        end

      _ ->
        add_error(changeset, :widgets, "must be a list")
    end
  end

  defp maybe_increment_version(changeset) do
    if get_change(changeset, :widgets) || get_change(changeset, :layout) do
      current_version = get_field(changeset, :version, 1)
      put_change(changeset, :version, current_version + 1)
    else
      changeset
    end
  end
end
