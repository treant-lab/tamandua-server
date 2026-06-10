defmodule TamanduaServer.Audit.ActivityLogger do
  @moduledoc """
  Central activity logging service.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Audit.AuditLog
  alias TamanduaServer.Audit.SuspiciousActivityDetector

  @pubsub TamanduaServer.PubSub

  def log(attrs) do
    changeset = AuditLog.changeset(%AuditLog{}, normalize_attrs(attrs))
    
    case Repo.insert(changeset) do
      {:ok, audit_log} ->
        audit_log = check_suspicious_activity(audit_log)
        broadcast_activity(audit_log)
        forward_to_external_systems(audit_log)
        {:ok, audit_log}
        
      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def log_login(user_id, organization_id, ip_address, user_agent) do
    log(%{
      action: "auth.login_success",
      resource_type: "user",
      resource_id: user_id,
      user_id: user_id,
      organization_id: organization_id,
      ip_address: ip_address,
      user_agent: user_agent,
      severity: "info",
      category: "authentication",
      success: true
    })
  end

  def log_login_failure(email, organization_id, ip_address, reason) do
    log(%{
      action: "auth.login_failed",
      resource_type: "user",
      organization_id: organization_id,
      ip_address: ip_address,
      metadata: %{email: email, reason: reason},
      severity: "medium",
      category: "authentication",
      success: false,
      error_message: reason
    })
  end

  def search_paginated(organization_id, filters \\ %{}, page \\ 1, per_page \\ 50) do
    offset = (page - 1) * per_page

    query = from a in AuditLog,
      where: a.organization_id == ^organization_id,
      order_by: [desc: a.inserted_at],
      preload: [:user],
      limit: ^per_page,
      offset: ^offset

    query = apply_filters(query, filters)
    total = Repo.aggregate(query, :count)
    entries = Repo.all(query)

    %{
      entries: entries,
      page: page,
      per_page: per_page,
      total: total,
      total_pages: ceil(total / per_page)
    }
  end

  defp normalize_attrs(attrs) do
    attrs
    |> Map.put_new(:success, true)
    |> Map.put_new(:severity, "info")
    |> Map.put_new(:metadata, %{})
    |> Map.put_new(:changes, %{})
  end

  defp check_suspicious_activity(audit_log) do
    case SuspiciousActivityDetector.analyze(audit_log) do
      {:suspicious, reason, risk_score} ->
        audit_log
        |> Ecto.Changeset.change(%{
          suspicious: true,
          suspicious_reason: reason,
          risk_score: risk_score
        })
        |> Repo.update!()

      :ok ->
        audit_log
    end
  end

  defp broadcast_activity(audit_log) do
    Phoenix.PubSub.broadcast(
      @pubsub,
      "activity:org:#{audit_log.organization_id}",
      {:new_activity, audit_log}
    )

    if audit_log.suspicious do
      Phoenix.PubSub.broadcast(
        @pubsub,
        "suspicious_activity:org:#{audit_log.organization_id}",
        {:suspicious_activity, audit_log}
      )
    end
  end

  defp forward_to_external_systems(audit_log) do
    Task.start(fn ->
      TamanduaServer.Audit.Forwarder.forward_async(audit_log)
    end)
  end

  defp apply_filters(query, filters) do
    Enum.reduce(filters, query, fn
      {:user_id, user_id}, query when not is_nil(user_id) ->
        where(query, [a], a.user_id == ^user_id)
      {:action, action}, query when not is_nil(action) ->
        where(query, [a], a.action == ^action)
      {:category, category}, query when not is_nil(category) ->
        where(query, [a], a.category == ^category)
      {:suspicious, suspicious}, query when not is_nil(suspicious) ->
        where(query, [a], a.suspicious == ^suspicious)
      {:from_date, from_date}, query when not is_nil(from_date) ->
        where(query, [a], a.inserted_at >= ^from_date)
      {:to_date, to_date}, query when not is_nil(to_date) ->
        where(query, [a], a.inserted_at <= ^to_date)
      _, query ->
        query
    end)
  end
end
