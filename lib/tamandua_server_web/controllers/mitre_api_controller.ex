defmodule TamanduaServerWeb.MitreAPIController do
  @moduledoc """
  REST API for MITRE ATT&CK Navigator integration.

  Provides endpoints for:
  - Navigator layer generation
  - Coverage data
  - Technique lookups
  - Threat actor mapping
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Mitre.{Navigator, AttackFramework, TechniqueMapper}
  alias TamanduaServer.Detection.Mitre

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  GET /api/mitre/coverage

  Get detection coverage summary.

  Query params:
  - time_range: Number of days (default: 30)
  """
  def coverage(conn, params) do
    org_id = get_org_id(conn)
    time_range = bounded_days(Map.get(params, "time_range"), 30)

    coverage_data = Mitre.get_coverage(
      organization_id: org_id,
      days: time_range
    )

    json(conn, coverage_data)
  end

  @doc """
  GET /api/mitre/techniques

  List all techniques or search.

  Query params:
  - q: Search query
  - tactic: Filter by tactic ID
  - platform: Filter by platform
  """
  def list_techniques(conn, params) do
    techniques = cond do
      query = Map.get(params, "q") ->
        AttackFramework.search_techniques(query)

      tactic_id = Map.get(params, "tactic") ->
        AttackFramework.get_techniques_for_tactic(tactic_id)

      true ->
        AttackFramework.list_techniques()
    end

    # Filter by platform if specified
    techniques = if platform = Map.get(params, "platform") do
      Enum.filter(techniques, fn tech -> platform in (tech.platforms || []) end)
    else
      techniques
    end

    json(conn, %{techniques: techniques})
  end

  @doc """
  GET /api/mitre/techniques/:technique_id

  Get detailed information about a specific technique.
  """
  def get_technique(conn, %{"technique_id" => technique_id}) do
    case AttackFramework.get_technique(technique_id) do
      nil ->
        {:error, :not_found}

      technique ->
        # Enrich with coverage data
        coverage = TechniqueMapper.get_technique_coverage(technique_id)

        technique_data = Map.merge(technique, %{
          coverage: coverage
        })

        json(conn, technique_data)
    end
  end

  @doc """
  GET /api/mitre/navigator/coverage

  Generate a Navigator layer JSON for detection coverage.
  """
  def navigator_coverage(conn, params) do
    org_id = get_org_id(conn)
    include_disabled = Map.get(params, "include_disabled", "false") == "true"

    layer = Navigator.generate_coverage_layer(
      organization_id: org_id,
      include_disabled: include_disabled
    )

    json(conn, layer)
  end

  @doc """
  GET /api/mitre/navigator/frequency

  Generate a Navigator layer JSON for alert frequency.

  Query params:
  - time_range: Number of days (default: 30)
  - severity_weight: Weight by severity (default: true)
  - agent_id: Filter by specific agent
  """
  def navigator_frequency(conn, params) do
    org_id = get_org_id(conn)
    time_range = bounded_days(Map.get(params, "time_range"), 30)
    severity_weight = Map.get(params, "severity_weight", "true") == "true"
    agent_id = Map.get(params, "agent_id")

    layer = Navigator.generate_frequency_layer(
      organization_id: org_id,
      time_range: time_range,
      severity_weight: severity_weight,
      agent_id: agent_id
    )

    json(conn, layer)
  end

  @doc """
  GET /api/mitre/navigator/gaps

  Generate a Navigator layer JSON showing coverage gaps.
  """
  def navigator_gaps(conn, _params) do
    org_id = get_org_id(conn)

    layer = Navigator.generate_gap_layer(organization_id: org_id)

    json(conn, layer)
  end

  @doc """
  POST /api/mitre/navigator/custom

  Generate a custom Navigator layer.

  Body:
  {
    "name": "Custom Layer",
    "description": "My custom visualization",
    "techniques": [
      {"technique_id": "T1059", "score": 75, "color": "#ff0000"},
      ...
    ]
  }
  """
  def navigator_custom(conn, params) do
    name = Map.get(params, "name", "Custom Layer")
    description = Map.get(params, "description", "")
    techniques = Map.get(params, "techniques", [])

    layer = Navigator.generate_custom_layer(name, description, techniques)

    json(conn, layer)
  end

  @doc """
  POST /api/mitre/navigator/save

  Save a Navigator layer.

  Body:
  {
    "name": "My Layer",
    "layer_data": {...},
    "layer_type": "coverage",
    "is_public": false
  }
  """
  def save_layer(conn, params) do
    org_id = get_org_id(conn)
    user_id = conn.assigns.current_user.id

    case Navigator.save_layer(
      params["layer_data"],
      params["name"],
      description: params["description"],
      layer_type: params["layer_type"],
      is_public: params["is_public"] || false,
      organization_id: org_id,
      created_by_id: user_id
    ) do
      {:ok, layer} ->
        json(conn, %{id: layer.id, message: "Layer saved successfully"})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  GET /api/mitre/navigator/layers

  List saved Navigator layers.
  """
  def list_layers(conn, _params) do
    org_id = get_org_id(conn)
    layers = Navigator.list_layers(org_id)

    json(conn, %{layers: layers})
  end

  @doc """
  GET /api/mitre/navigator/layers/:layer_id

  Get a saved Navigator layer.
  """
  def get_layer(conn, %{"layer_id" => layer_id}) do
    case Navigator.get_layer(layer_id) do
      nil ->
        {:error, :not_found}

      layer ->
        # Check permission
        org_id = get_org_id(conn)
        if layer.organization_id == org_id or layer.is_public do
          json(conn, layer)
        else
          {:error, :forbidden}
        end
    end
  end

  @doc """
  DELETE /api/mitre/navigator/layers/:layer_id

  Delete a saved Navigator layer.
  """
  def delete_layer(conn, %{"layer_id" => layer_id}) do
    case Navigator.get_layer(layer_id) do
      nil ->
        {:error, :not_found}

      layer ->
        org_id = get_org_id(conn)
        user_id = conn.assigns.current_user.id

        # Only allow deletion if user owns it or is admin
        if layer.organization_id == org_id and layer.created_by_id == user_id do
          case Navigator.delete_layer(layer_id) do
            {:ok, _} ->
              json(conn, %{message: "Layer deleted successfully"})

            {:error, _} ->
              {:error, :internal_server_error}
          end
        else
          {:error, :forbidden}
        end
    end
  end

  @doc """
  GET /api/mitre/actors

  List threat actors.

  Query params:
  - technique: Filter by technique usage
  - country: Filter by country
  """
  def list_threat_actors(conn, params) do
    actors = cond do
      technique_id = Map.get(params, "technique") ->
        AttackFramework.get_actors_for_technique(technique_id)

      true ->
        AttackFramework.list_threat_actors()
    end

    # Filter by country if specified
    actors = if country = Map.get(params, "country") do
      Enum.filter(actors, fn actor -> actor.country == country end)
    else
      actors
    end

    json(conn, %{actors: actors})
  end

  @doc """
  GET /api/mitre/actors/:actor_id

  Get detailed information about a threat actor.
  """
  def get_threat_actor(conn, %{"actor_id" => actor_id}) do
    case AttackFramework.get_threat_actor(actor_id) do
      nil ->
        {:error, :not_found}

      actor ->
        json(conn, actor)
    end
  end

  @doc """
  POST /api/mitre/sync

  Sync technique mappings from detection rules.
  """
  def sync_mappings(conn, _params) do
    org_id = get_org_id(conn)

    case TechniqueMapper.sync_all_mappings(org_id) do
      {:ok, counts} ->
        json(conn, %{
          message: "Mappings synced successfully",
          sigma_rules: counts.sigma,
          yara_rules: counts.yara
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  POST /api/mitre/import

  Import MITRE ATT&CK data from STIX bundle.

  Body:
  {
    "source": "url or file path",
    "force": true/false
  }
  """
  def import_attack_data(conn, params) do
    # Import mutates the shared ATT&CK dataset — admin only. The previous
    # `unless ... do {:error, :forbidden} end` discarded its result, so the
    # check never gated anything (and `.is_admin` does not exist on the User
    # schema — the real field is `role`). Fail closed: unknown/missing user
    # shapes are forbidden, and `{:error, :forbidden}` is rendered as 403 by
    # the FallbackController wired via `action_fallback` above.
    if admin?(conn.assigns[:current_user]) do
      source = Map.get(params, "source")
      force = Map.get(params, "force", false)

      case AttackFramework.import_attack_data(source: source, force: force) do
        # The specific atom result must be matched before the generic
        # {:ok, stats} clause, otherwise `stats.techniques` raises on
        # `:already_imported`.
        {:ok, :already_imported} ->
          json(conn, %{message: "Data already imported, use force=true to re-import"})

        {:ok, stats} ->
          json(conn, %{
            message: "Import completed successfully",
            techniques: stats.techniques,
            actors: stats.actors
          })

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :forbidden}
    end
  end

  # Private helpers

  # Same fail-closed shape as VulnerabilityController.vulnerability_sync_admin?/1:
  # accept both %User{role: ...} structs and plain claim maps; anything else
  # (nil, string-keyed maps, missing role) is not admin.
  defp admin?(%{is_admin: true}), do: true
  defp admin?(%{role: role}) when role in ["admin", :admin], do: true
  defp admin?(_), do: false

  # `conn.assigns[:current_user]` is a %User{} struct on authenticated
  # pipelines; Access syntax (`user[:organization_id]`) raises on structs, so
  # pattern match instead. Nil/unknown shapes yield nil (org-unscoped).
  defp get_org_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      _ -> nil
    end
  end

  defp bounded_days(value, default), do: value |> parse_int(default) |> max(1) |> min(365)

  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default
end
