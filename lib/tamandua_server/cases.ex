defmodule TamanduaServer.Cases do
  @moduledoc """
  Canonical case view over the legacy case-investigation store.

  The facade keeps `case_investigations` as the source of truth and projects
  linked alert evidence without copying it. Capabilities that do not yet have
  durable storage are returned as explicitly degraded instead of being
  represented as empty, working features.
  """

  import Ecto.Query, warn: false

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Investigations
  alias TamanduaServer.Investigations.CaseInvestigation
  alias TamanduaServer.Repo

  @type canonical_case :: map()

  @spec create(String.t(), map()) :: {:ok, canonical_case()} | {:error, Ecto.Changeset.t()}
  def create(organization_id, attrs) when is_binary(organization_id) and is_map(attrs) do
    attrs =
      attrs
      |> Map.new(fn {key, value} -> {normalize_key(key), value} end)
      |> Map.put(:organization_id, organization_id)

    with {:ok, investigation} <- Investigations.create_investigation(attrs) do
      {:ok, build_view(investigation, [])}
    end
  end

  @spec list(String.t(), keyword()) :: [canonical_case()]
  def list(organization_id, opts \\ []) when is_binary(organization_id) do
    opts = Keyword.put(opts, :organization_id, organization_id)

    opts
    |> Investigations.list_investigations()
    |> attach_alerts(organization_id)
  end

  @spec get(String.t(), String.t()) :: {:ok, canonical_case()} | {:error, :not_found}
  def get(organization_id, id) when is_binary(organization_id) and is_binary(id) do
    investigation =
      CaseInvestigation
      |> where(
        [case_record],
        case_record.id == ^id and case_record.organization_id == ^organization_id
      )
      |> preload([:assigned_user, :creator])
      |> Repo.one()

    case investigation do
      nil ->
        {:error, :not_found}

      investigation ->
        alerts = alerts_for([investigation], organization_id)
        {:ok, build_view(investigation, Map.get(alerts, investigation.id, []))}
    end
  end

  @doc "Builds the stable API projection and is public to keep the contract unit-testable."
  @spec build_view(CaseInvestigation.t(), [Alert.t()]) :: canonical_case()
  def build_view(%CaseInvestigation{} = investigation, alerts) when is_list(alerts) do
    %{
      id: investigation.id,
      kind: "security_case",
      title: investigation.title,
      description: investigation.description,
      status: investigation.status,
      severity: investigation.severity,
      owner: user_ref(investigation.assigned_user, investigation.assigned_to),
      created_by: user_ref(investigation.creator, investigation.created_by),
      sla: sla_view(investigation, alerts),
      alerts: Enum.map(alerts, &alert_ref/1),
      evidence: Enum.map(alerts, &evidence_ref/1),
      event_ids: investigation.event_ids || [],
      tasks: unavailable("case_tasks_not_persisted"),
      timeline: timeline_view(investigation, alerts),
      audit: unavailable("case_audit_journal_not_persisted"),
      findings: investigation.findings,
      notes: investigation.notes,
      tags: investigation.tags || [],
      mitre: %{
        tactics: investigation.mitre_tactics || [],
        techniques: investigation.mitre_techniques || []
      },
      inserted_at: investigation.inserted_at,
      updated_at: investigation.updated_at
    }
  end

  defp attach_alerts(investigations, organization_id) do
    alerts = alerts_for(investigations, organization_id)
    Enum.map(investigations, &build_view(&1, Map.get(alerts, &1.id, [])))
  end

  defp alerts_for(investigations, organization_id) do
    ids = investigations |> Enum.flat_map(&(&1.alert_ids || [])) |> Enum.uniq()

    alerts =
      if ids == [] do
        []
      else
        Alert
        |> where([a], a.organization_id == ^organization_id and a.id in ^ids)
        |> Repo.all()
      end

    by_id = Map.new(alerts, &{&1.id, &1})

    Map.new(investigations, fn investigation ->
      ordered = Enum.flat_map(investigation.alert_ids || [], &List.wrap(by_id[&1]))
      {investigation.id, ordered}
    end)
  end

  defp alert_ref(alert) do
    %{
      id: alert.id,
      title: alert.title,
      status: alert.status,
      severity: alert.severity,
      agent_id: alert.agent_id,
      threat_score: alert.threat_score,
      inserted_at: alert.inserted_at
    }
  end

  defp evidence_ref(alert) do
    %{
      source_type: "alert",
      source_id: alert.id,
      evidence: alert.evidence || %{},
      process_chain: alert.process_chain || [],
      event_ids: alert.event_ids || []
    }
  end

  defp timeline_view(investigation, alerts) do
    alert_events =
      Enum.map(alerts, fn alert ->
        %{
          type: "alert_linked",
          entity_type: "alert",
          entity_id: alert.id,
          occurred_at: alert.inserted_at,
          summary: alert.title
        }
      end)

    %{
      state: "available",
      legacy: investigation.timeline || %{},
      events: alert_events
    }
  end

  defp sla_view(_investigation, alerts) do
    deadlines = alerts |> Enum.map(& &1.sla_resolve_deadline) |> Enum.reject(&is_nil/1)
    due_at = Enum.min_by(deadlines, &DateTime.to_unix/1, fn -> nil end)
    breached = Enum.any?(alerts, &(&1.sla_resolve_breached == true))

    %{
      state: if(due_at, do: "derived_from_alerts", else: "unavailable"),
      due_at: due_at,
      breached: breached,
      source: if(due_at, do: "linked_alerts", else: nil)
    }
  end

  defp user_ref(nil, nil), do: nil
  defp user_ref(nil, id), do: %{id: id}
  defp user_ref(user, _id), do: %{id: user.id, name: user.name, email: user.email}

  defp unavailable(reason), do: %{state: "unavailable", reason: reason, items: []}

  defp normalize_key("title"), do: :title
  defp normalize_key("description"), do: :description
  defp normalize_key("status"), do: :status
  defp normalize_key("severity"), do: :severity
  defp normalize_key("assigned_to"), do: :assigned_to
  defp normalize_key("created_by"), do: :created_by
  defp normalize_key("alert_ids"), do: :alert_ids
  defp normalize_key("event_ids"), do: :event_ids
  defp normalize_key("notes"), do: :notes
  defp normalize_key("findings"), do: :findings
  defp normalize_key("timeline"), do: :timeline
  defp normalize_key("tags"), do: :tags
  defp normalize_key("mitre_tactics"), do: :mitre_tactics
  defp normalize_key("mitre_techniques"), do: :mitre_techniques
  defp normalize_key(key), do: key
end
