defmodule TamanduaServer.Dashboards.Layout do
  @moduledoc """
  Schema for dashboard layouts.
  A layout represents a user's custom dashboard configuration with multiple widgets.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @template_types ~w(soc_analyst executive incident_responder threat_hunter compliance custom)

  schema "dashboard_layouts" do
    field :name, :string
    field :description, :string
    field :is_default, :boolean, default: false
    field :is_template, :boolean, default: false
    field :template_type, :string
    field :layout_config, :map, default: %{}
    field :shared_with_users, {:array, :binary_id}, default: []

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization

    has_many :widgets, TamanduaServer.Dashboards.Widget, foreign_key: :dashboard_layout_id, on_delete: :delete_all

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name user_id)a
  @optional_fields ~w(description is_default is_template template_type layout_config shared_with_users organization_id)a

  def changeset(layout, attrs) do
    layout
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:template_type, @template_types, message: "must be a valid template type")
    |> validate_layout_config()
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_layout_config(changeset) do
    case get_change(changeset, :layout_config) do
      nil ->
        changeset

      config when is_map(config) ->
        # Validate grid configuration structure
        if valid_layout_config?(config) do
          changeset
        else
          add_error(changeset, :layout_config, "invalid layout configuration structure")
        end

      _ ->
        add_error(changeset, :layout_config, "must be a map")
    end
  end

  defp valid_layout_config?(config) do
    # Basic validation - can be expanded
    is_map(config)
  end

  @doc """
  Returns the list of available template types.
  """
  def template_types, do: @template_types

  @doc """
  Returns the default layout configuration for a template type.
  """
  def default_template_config("soc_analyst") do
    %{
      "cols" => 12,
      "rowHeight" => 80,
      "widgets" => [
        %{"type" => "threat_level_gauge", "x" => 0, "y" => 0, "w" => 3, "h" => 2},
        %{"type" => "agent_status_overview", "x" => 3, "y" => 0, "w" => 3, "h" => 2},
        %{"type" => "recent_alerts", "x" => 6, "y" => 0, "w" => 6, "h" => 4},
        %{"type" => "top_detections", "x" => 0, "y" => 2, "w" => 6, "h" => 3},
        %{"type" => "timeline", "x" => 0, "y" => 5, "w" => 12, "h" => 3}
      ]
    }
  end

  def default_template_config("executive") do
    %{
      "cols" => 12,
      "rowHeight" => 80,
      "widgets" => [
        %{"type" => "threat_level_gauge", "x" => 0, "y" => 0, "w" => 4, "h" => 2},
        %{"type" => "top_threats", "x" => 4, "y" => 0, "w" => 4, "h" => 2},
        %{"type" => "detection_performance", "x" => 8, "y" => 0, "w" => 4, "h" => 2},
        %{"type" => "geo_map", "x" => 0, "y" => 2, "w" => 12, "h" => 4}
      ]
    }
  end

  def default_template_config("incident_responder") do
    %{
      "cols" => 12,
      "rowHeight" => 80,
      "widgets" => [
        %{"type" => "recent_alerts", "x" => 0, "y" => 0, "w" => 8, "h" => 4},
        %{"type" => "response_actions", "x" => 8, "y" => 0, "w" => 4, "h" => 4},
        %{"type" => "timeline", "x" => 0, "y" => 4, "w" => 12, "h" => 3},
        %{"type" => "top_detections", "x" => 0, "y" => 7, "w" => 6, "h" => 3}
      ]
    }
  end

  def default_template_config("threat_hunter") do
    %{
      "cols" => 12,
      "rowHeight" => 80,
      "widgets" => [
        %{"type" => "top_detections", "x" => 0, "y" => 0, "w" => 6, "h" => 3},
        %{"type" => "top_threats", "x" => 6, "y" => 0, "w" => 6, "h" => 3},
        %{"type" => "geo_map", "x" => 0, "y" => 3, "w" => 12, "h" => 4},
        %{"type" => "timeline", "x" => 0, "y" => 7, "w" => 12, "h" => 3}
      ]
    }
  end

  def default_template_config("compliance") do
    %{
      "cols" => 12,
      "rowHeight" => 80,
      "widgets" => [
        %{"type" => "detection_performance", "x" => 0, "y" => 0, "w" => 6, "h" => 3},
        %{"type" => "system_health", "x" => 6, "y" => 0, "w" => 6, "h" => 3},
        %{"type" => "agent_status_overview", "x" => 0, "y" => 3, "w" => 12, "h" => 2}
      ]
    }
  end

  def default_template_config(_), do: %{"cols" => 12, "rowHeight" => 80, "widgets" => []}
end
