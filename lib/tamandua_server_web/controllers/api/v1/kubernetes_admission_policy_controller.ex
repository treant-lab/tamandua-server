defmodule TamanduaServerWeb.API.V1.KubernetesAdmissionPolicyController do
  @moduledoc """
  REST API controller for managing Kubernetes admission control policies.

  All endpoints require authentication (`:api_auth` pipeline).

  ## Endpoints

  - `GET    /api/v1/kubernetes/admission-policies`           - List all policies
  - `GET    /api/v1/kubernetes/admission-policies/:id`        - Show a single policy
  - `POST   /api/v1/kubernetes/admission-policies`            - Create a policy
  - `PUT    /api/v1/kubernetes/admission-policies/:id`        - Update a policy
  - `DELETE /api/v1/kubernetes/admission-policies/:id`        - Delete a policy
  - `GET    /api/v1/kubernetes/admission-logs`                - Audit log of decisions
  - `GET    /api/v1/kubernetes/admission-stats`               - Webhook engine stats
  - `GET    /api/v1/kubernetes/admission-policies/:id/versions` - Policy version history
  - `POST   /api/v1/kubernetes/admission-policies/:id/dry-run`  - Toggle dry-run mode
  - `POST   /api/v1/kubernetes/admission-policies/reload`     - Reload policies from DB
  - `POST   /api/v1/kubernetes/admission-simulate`            - Simulate an AdmissionReview
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Kubernetes.AdmissionLog
  alias TamanduaServer.Kubernetes.AdmissionPolicies
  alias TamanduaServer.Kubernetes.AdmissionWebhook

  # -------------------------------------------------------------------
  # CRUD for Policies
  # -------------------------------------------------------------------

  @doc "List all admission policies."
  def index(conn, params) do
    opts = [
      organization_id: params["organization_id"],
      enabled: parse_boolean(params["enabled"]),
      action: params["action"]
    ]

    policies = AdmissionPolicies.list(opts)

    json(conn, %{
      data: Enum.map(policies, &serialize_policy/1),
      total: length(policies)
    })
  end

  @doc "Show a single admission policy."
  def show(conn, %{"id" => id}) do
    case AdmissionPolicies.get(id) do
      {:ok, policy} ->
        json(conn, %{data: serialize_policy(policy)})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Policy not found"})
    end
  end

  @doc "Create a new admission policy (via webhook engine with versioning)."
  def create(conn, %{"policy" => policy_params}) do
    case AdmissionWebhook.add_policy(normalize_params(policy_params)) do
      {:ok, policy} ->
        conn
        |> put_status(201)
        |> json(%{data: serialize_policy(policy)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{errors: format_changeset_errors(changeset)})
    end
  rescue
    # Fallback if webhook engine is not running -- use context module
    _ ->
      case AdmissionPolicies.create(normalize_params(policy_params)) do
        {:ok, policy} ->
          conn
          |> put_status(201)
          |> json(%{data: serialize_policy(policy)})

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
          |> put_status(422)
          |> json(%{errors: format_changeset_errors(changeset)})
      end
  end

  # Also accept params without the "policy" wrapper
  def create(conn, params) when is_map(params) do
    if Map.has_key?(params, "name") do
      create(conn, %{"policy" => params})
    else
      conn
      |> put_status(400)
      |> json(%{error: "Missing policy parameters"})
    end
  end

  @doc "Update an existing admission policy (via webhook engine with versioning)."
  def update(conn, %{"id" => id} = params) do
    policy_params = params["policy"] || Map.drop(params, ["id"])

    case AdmissionWebhook.update_policy(id, normalize_params(policy_params)) do
      {:ok, updated} ->
        json(conn, %{data: serialize_policy(updated)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{errors: format_changeset_errors(changeset)})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Policy not found"})
    end
  rescue
    # Fallback to direct DB update via context module
    _ ->
      policy_params = params["policy"] || Map.drop(params, ["id"])

      case AdmissionPolicies.get(id) do
        {:ok, policy} ->
          case AdmissionPolicies.update(policy, normalize_params(policy_params)) do
            {:ok, updated} ->
              try do
                :ets.insert(:k8s_admission_policies, {updated.id, updated})
              rescue
                _ -> :ok
              end

              json(conn, %{data: serialize_policy(updated)})

            {:error, %Ecto.Changeset{} = changeset} ->
              conn
              |> put_status(422)
              |> json(%{errors: format_changeset_errors(changeset)})
          end

        {:error, :not_found} ->
          conn
          |> put_status(404)
          |> json(%{error: "Policy not found"})
      end
  end

  @doc "Delete an admission policy (via webhook engine)."
  def delete(conn, %{"id" => id}) do
    case AdmissionWebhook.remove_policy(id) do
      :ok ->
        json(conn, %{status: "deleted"})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Policy not found"})
    end
  rescue
    _ ->
      case AdmissionPolicies.delete_by_id(id) do
        :ok ->
          json(conn, %{status: "deleted"})

        {:error, :not_found} ->
          conn
          |> put_status(404)
          |> json(%{error: "Policy not found"})
      end
  end

  # -------------------------------------------------------------------
  # Admission Logs
  # -------------------------------------------------------------------

  @doc "List admission decision audit logs with optional filters."
  def logs(conn, params) do
    filters = %{
      "namespace" => params["namespace"],
      "decision" => params["decision"],
      "resource_kind" => params["resource_kind"],
      "since" => params["since"]
    }

    limit = parse_int(params["limit"], 100)
    offset = parse_int(params["offset"], 0)

    logs = AdmissionLog.list_logs(filters, limit: limit, offset: offset)
    counts = AdmissionLog.decision_counts()

    json(conn, %{
      data: Enum.map(logs, &serialize_log/1),
      total: length(logs),
      counts: counts
    })
  end

  # -------------------------------------------------------------------
  # Webhook Engine Stats
  # -------------------------------------------------------------------

  @doc "Return admission webhook engine statistics."
  def admission_stats(conn, _params) do
    engine_stats = AdmissionWebhook.stats()

    json(conn, %{
      data: engine_stats,
      engine: "admission_webhook",
      policy_count: length(AdmissionWebhook.list_policies())
    })
  rescue
    _ ->
      json(conn, %{data: %{error: "Webhook engine not running"}, engine: "unavailable"})
  end

  # -------------------------------------------------------------------
  # Policy Version History
  # -------------------------------------------------------------------

  @doc "Return version history for a specific policy."
  def versions(conn, %{"id" => id}) do
    versions = AdmissionWebhook.policy_versions(id)

    serialized =
      Enum.map(versions, fn v ->
        %{
          version: v.version,
          action: v.action,
          timestamp: v.timestamp,
          snapshot: serialize_policy_map(v.snapshot)
        }
      end)

    json(conn, %{data: serialized, total: length(serialized)})
  rescue
    _ ->
      json(conn, %{data: [], total: 0})
  end

  # -------------------------------------------------------------------
  # Dry-Run Toggle
  # -------------------------------------------------------------------

  @doc "Toggle dry-run mode for a policy."
  def toggle_dry_run(conn, %{"id" => id} = params) do
    dry_run = params["dry_run"] || params["dryRun"] || false

    case AdmissionWebhook.set_dry_run(id, dry_run) do
      {:ok, policy} ->
        json(conn, %{data: serialize_policy(policy), dry_run: dry_run})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "Policy not found"})
    end
  rescue
    _ ->
      conn
      |> put_status(503)
      |> json(%{error: "Webhook engine not running"})
  end

  # -------------------------------------------------------------------
  # Reload Policies
  # -------------------------------------------------------------------

  @doc "Reload all policies from the database into the webhook engine."
  def reload_policies(conn, _params) do
    {:ok, count} = AdmissionWebhook.reload_policies()

    json(conn, %{status: "reloaded", policy_count: count})
  rescue
    _ ->
      conn
      |> put_status(503)
      |> json(%{error: "Webhook engine not running"})
  end

  # -------------------------------------------------------------------
  # Simulate Admission
  # -------------------------------------------------------------------

  @doc "Simulate an AdmissionReview against current policies (dry-run, no side-effects)."
  def simulate(conn, params) do
    review = params["admission_review"] || params

    response = AdmissionWebhook.evaluate(review, dry_run: true)
    json(conn, %{data: response})
  rescue
    _ ->
      conn
      |> put_status(503)
      |> json(%{error: "Webhook engine not running"})
  end

  # -------------------------------------------------------------------
  # Serializers
  # -------------------------------------------------------------------

  defp serialize_policy(policy) do
    base = %{
      id: policy_field(policy, :id),
      name: policy_field(policy, :name),
      description: policy_field(policy, :description),
      action: policy_field(policy, :action),
      target: policy_field(policy, :target),
      conditions: policy_field(policy, :conditions),
      mutation: policy_field(policy, :mutation),
      enabled: policy_field(policy, :enabled),
      priority: policy_field(policy, :priority),
      namespaces: policy_field(policy, :namespaces),
      namespace_selector: policy_field(policy, :namespace_selector),
      rules: policy_field(policy, :rules),
      labels: policy_field(policy, :labels),
      organization_id: policy_field(policy, :organization_id),
      inserted_at: policy_field(policy, :inserted_at),
      updated_at: policy_field(policy, :updated_at)
    }

    # Add dry_run if present (from webhook engine enrichment)
    dry_run = policy_field(policy, :dry_run)
    if dry_run != nil, do: Map.put(base, :dry_run, dry_run), else: base
  end

  defp serialize_policy_map(policy) when is_map(policy) do
    serialize_policy(policy)
  end

  defp serialize_log(log) do
    %{
      id: log.id,
      uid: log.uid,
      namespace: log.namespace,
      name: log.name,
      resource_kind: log.resource_kind,
      operation: log.operation,
      decision: log.decision,
      reason: log.reason,
      warnings: log.warnings,
      policy_names: log.policy_names,
      patches_applied: log.patches_applied,
      requesting_user: log.requesting_user,
      requesting_groups: log.requesting_groups,
      dry_run: log.dry_run,
      duration_us: log.duration_us,
      metadata: log.metadata,
      timestamp: log.inserted_at
    }
  end

  # Helper to access fields from both struct and plain map
  defp policy_field(policy, key) when is_struct(policy), do: Map.get(policy, key)

  defp policy_field(policy, key) when is_map(policy) do
    Map.get(policy, key) || Map.get(policy, Atom.to_string(key))
  end

  # -------------------------------------------------------------------
  # Helpers
  # -------------------------------------------------------------------

  defp normalize_params(params) when is_map(params) do
    params
    |> maybe_atomize_key("action")
    |> maybe_atomize_key("target")
  end

  defp maybe_atomize_key(params, key) do
    case Map.get(params, key) do
      val when is_binary(val) ->
        try do
          Map.put(params, key, String.to_existing_atom(val))
        rescue
          ArgumentError -> params
        end

      _ ->
        params
    end
  end

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp parse_int(nil, default), do: default

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> default
    end
  end

  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp parse_boolean(nil), do: nil
  defp parse_boolean("true"), do: true
  defp parse_boolean("false"), do: false
  defp parse_boolean(val) when is_boolean(val), do: val
  defp parse_boolean(_), do: nil
end
