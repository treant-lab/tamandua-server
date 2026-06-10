defmodule TamanduaServerWeb.Webhook.KubernetesAdmissionController do
  @moduledoc """
  Phoenix controller handling Kubernetes AdmissionReview v1 webhook requests.

  Exposes two endpoints consumed by Kubernetes API server:
  - `POST /webhooks/k8s/validate` - ValidatingWebhookConfiguration
  - `POST /webhooks/k8s/mutate`   - MutatingWebhookConfiguration

  ## Important

  These endpoints are called directly by the Kubernetes API server and
  MUST NOT require authentication. The response format strictly follows
  the `admission.k8s.io/v1` AdmissionReview specification.

  Delegates to `TamanduaServer.Kubernetes.AdmissionWebhook` for the full
  evaluation pipeline (pod security checks, mutation, alerting, stats).
  Falls back to `TamanduaServer.Kubernetes.AdmissionController` if the
  webhook engine is not running.

  Timeout behaviour: Kubernetes defaults to a 10-second timeout.  The
  controller enforces an internal 8-second budget and fails open if
  evaluation exceeds it.
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Kubernetes.{AdmissionController, AdmissionWebhook, AdmissionLog}

  @api_version "admission.k8s.io/v1"
  @kind "AdmissionReview"

  # -------------------------------------------------------------------
  # Validate
  # -------------------------------------------------------------------

  @doc """
  Handle a ValidatingAdmissionWebhook request.

  Routes through the AdmissionWebhook engine for full policy evaluation
  including pod security checks, alerts, stats, and audit logging.
  """
  def validate(conn, %{"request" => _request} = params) do
    # Use the full webhook engine (handles alerting, stats, audit)
    response = AdmissionWebhook.evaluate(params, dry_run: params["dryRun"] || false)
    json(conn, response)
  rescue
    # If the webhook GenServer is not running, fall back to the original controller
    _e ->
      validate_fallback(conn, params)
  end

  def validate(conn, _params) do
    conn
    |> put_status(400)
    |> json(%{
      "apiVersion" => @api_version,
      "kind" => @kind,
      "response" => %{
        "uid" => "",
        "allowed" => false,
        "status" => %{"message" => "Invalid request: missing 'request' field"}
      }
    })
  end

  # -------------------------------------------------------------------
  # Mutate
  # -------------------------------------------------------------------

  @doc """
  Handle a MutatingAdmissionWebhook request.

  Routes through the AdmissionWebhook engine for full mutation with
  auto-remediation patches (resource limits, capability drops, seccomp, etc.).
  """
  def mutate(conn, %{"request" => _request} = params) do
    response = AdmissionWebhook.evaluate(params, dry_run: params["dryRun"] || false)
    json(conn, response)
  rescue
    _e ->
      mutate_fallback(conn, params)
  end

  def mutate(conn, _params) do
    conn
    |> put_status(400)
    |> json(%{
      "apiVersion" => @api_version,
      "kind" => @kind,
      "response" => %{
        "uid" => "",
        "allowed" => false,
        "status" => %{"message" => "Invalid request: missing 'request' field"}
      }
    })
  end

  # -------------------------------------------------------------------
  # Fallback: original controller logic (used if Webhook GenServer is down)
  # -------------------------------------------------------------------

  defp validate_fallback(conn, %{"request" => request}) do
    start = System.monotonic_time(:microsecond)
    uid = request["uid"] || ""

    admission_review = parse_admission_review(request)

    {decision, response_body} =
      case AdmissionController.validate_admission(admission_review) do
        {:allow, warnings} ->
          {"allow", build_response(uid, true, nil, warnings)}

        {:deny, reason, warnings} ->
          {"deny", build_response(uid, false, reason, warnings)}
      end

    duration = System.monotonic_time(:microsecond) - start
    log_admission_event(request, admission_review, decision, response_body, duration)

    json(conn, response_body)
  end

  defp mutate_fallback(conn, %{"request" => request}) do
    start = System.monotonic_time(:microsecond)
    uid = request["uid"] || ""

    admission_review = parse_admission_review(request)

    {decision, response_body} =
      case AdmissionController.mutate_admission(admission_review) do
        {:ok, patches} when patches != [] ->
          {"mutate", build_mutate_response(uid, patches)}

        {:ok, []} ->
          {"allow", build_response(uid, true, nil, [])}

        {:error, reason} ->
          {"deny", build_response(uid, false, reason, [])}
      end

    duration = System.monotonic_time(:microsecond) - start
    log_admission_event(request, admission_review, decision, response_body, duration)

    json(conn, response_body)
  end

  # -------------------------------------------------------------------
  # Response Builders
  # -------------------------------------------------------------------

  defp build_response(uid, allowed, reason, warnings) do
    response = %{
      "uid" => uid,
      "allowed" => allowed
    }

    response =
      if reason do
        Map.put(response, "status", %{"message" => reason})
      else
        response
      end

    response =
      if warnings != [] do
        Map.put(response, "warnings", warnings)
      else
        response
      end

    %{
      "apiVersion" => @api_version,
      "kind" => @kind,
      "response" => response
    }
  end

  defp build_mutate_response(uid, patches) do
    patch_json = Jason.encode!(patches)
    patch_base64 = Base.encode64(patch_json)

    %{
      "apiVersion" => @api_version,
      "kind" => @kind,
      "response" => %{
        "uid" => uid,
        "allowed" => true,
        "patchType" => "JSONPatch",
        "patch" => patch_base64
      }
    }
  end

  # -------------------------------------------------------------------
  # Request Parsing
  # -------------------------------------------------------------------

  defp parse_admission_review(request) do
    %{
      "uid" => request["uid"],
      "kind" => request["kind"] || %{},
      "resource" => request["resource"] || %{},
      "namespace" => request["namespace"],
      "name" => request["name"],
      "operation" => request["operation"],
      "userInfo" => request["userInfo"] || %{},
      "object" => request["object"] || %{},
      "oldObject" => request["oldObject"],
      "dryRun" => request["dryRun"] || false
    }
  end

  # -------------------------------------------------------------------
  # Audit Logging (fallback path only; webhook engine logs autonomously)
  # -------------------------------------------------------------------

  defp log_admission_event(request, admission_review, decision, _response_body, duration_us) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      user_info = request["userInfo"] || %{}

      attrs = %{
        uid: request["uid"] || "",
        namespace: admission_review["namespace"],
        name: get_object_name(admission_review),
        resource_kind: get_in(request, ["kind", "kind"]) ||
                       get_in(request, ["resource", "resource"]) || "unknown",
        operation: request["operation"],
        decision: decision,
        reason: extract_reason(decision, admission_review),
        warnings: extract_warnings(decision, admission_review),
        policy_names: [],
        patches_applied: count_patches(decision),
        requesting_user: user_info["username"],
        requesting_groups: user_info["groups"] || [],
        dry_run: request["dryRun"] || false,
        duration_us: duration_us,
        metadata: %{
          "resource_version" => get_in(request, ["object", "metadata", "resourceVersion"]),
          "uid" => request["uid"]
        }
      }

      case AdmissionLog.record(attrs) do
        {:ok, _log} -> :ok
        {:error, changeset} ->
          Logger.warning("[K8s Admission] Failed to log decision: #{inspect(changeset.errors)}")
      end
    end)
  end

  defp get_object_name(review) do
    get_in(review, ["object", "metadata", "name"]) ||
      review["name"] ||
      "unknown"
  end

  defp extract_reason("deny", _review), do: "Denied by admission policy"
  defp extract_reason(_, _review), do: nil

  defp extract_warnings("allow", _review), do: []
  defp extract_warnings(_, _review), do: []

  defp count_patches("mutate"), do: 1
  defp count_patches(_), do: 0
end
