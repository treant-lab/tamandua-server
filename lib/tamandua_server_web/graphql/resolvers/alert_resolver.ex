defmodule TamanduaServerWeb.GraphQL.Resolvers.AlertResolver do
  @moduledoc """
  GraphQL resolvers for Alert queries and fields.
  """

  require Logger

  alias TamanduaServer.{Alerts, Agents, Repo}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Telemetry.Event
  import Ecto.Query

  # Query resolvers

  def list_alerts(_parent, args, %{context: context}) do
    org_id = context[:organization_id]
    filter = Map.get(args, :filter, %{})
    pagination = Map.get(args, :pagination, %{})

    limit = pagination[:limit] || 50
    offset = pagination[:offset] || 0

    query =
      Alert
      |> maybe_scope_org(org_id)
      |> order_by([a], desc: a.inserted_at)
      |> apply_alert_filters(filter)
      |> limit(^limit)
      |> offset(^offset)

    {:ok, Repo.all(query)}
  end

  def get_alert(_parent, %{id: id}, %{context: context}) do
    org_id = context[:organization_id]

    query =
      Alert
      |> maybe_scope_org(org_id)
      |> where([a], a.id == ^id)

    case Repo.one(query) do
      nil -> {:error, "Alert not found"}
      alert -> {:ok, alert}
    end
  end

  def alert_stats(_parent, _args, %{context: context}) do
    org_id = context[:organization_id]

    base_query =
      Alert
      |> maybe_scope_org(org_id)

    total = Repo.aggregate(base_query, :count)

    new_count =
      base_query
      |> where([a], a.status == "new")
      |> Repo.aggregate(:count)

    investigating_count =
      base_query
      |> where([a], a.status == "investigating")
      |> Repo.aggregate(:count)

    resolved_count =
      base_query
      |> where([a], a.status == "resolved")
      |> Repo.aggregate(:count)

    by_severity =
      base_query
      |> group_by([a], a.severity)
      |> select([a], {a.severity, count(a.id)})
      |> Repo.all()
      |> Enum.into(%{})

    by_tactic =
      base_query
      |> where([a], not is_nil(a.mitre_tactics))
      |> select([a], a.mitre_tactics)
      |> Repo.all()
      |> List.flatten()
      |> Enum.frequencies()

    {:ok,
     %{
       total: total,
       new: new_count,
       investigating: investigating_count,
       resolved: resolved_count,
       by_severity: by_severity,
       by_tactic: by_tactic,
       trend: []
     }}
  end

  # Field resolvers

  def agent(alert, _args, %{context: context}) do
    org_id = context[:organization_id]

    if alert.agent_id && alert.organization_id == org_id do
      # Use tenant-scoped lookup to prevent BOLA/IDOR
      # Only return the agent if it belongs to the same organization as the alert
      case Agents.get_agent_for_org(org_id, alert.agent_id) do
        {:ok, agent} -> {:ok, agent}
        {:error, :not_found} -> {:ok, nil}
      end
    else
      {:ok, nil}
    end
  end

  def assigned_to(alert, _args, %{context: context}) do
    org_id = context[:organization_id]

    if alert.assigned_to_id && alert.organization_id == org_id do
      {:ok,
       Repo.get_by(TamanduaServer.Accounts.User,
         id: alert.assigned_to_id,
         organization_id: org_id
       )}
    else
      {:ok, nil}
    end
  end

  def related_events(alert, args, %{context: context}) do
    limit = args[:limit] || 20
    org_id = context[:organization_id]

    event_ids = alert.event_ids || []

    if Enum.empty?(event_ids) || is_nil(org_id) || alert.organization_id != org_id do
      {:ok, []}
    else
      events =
        from(e in Event,
          where: e.id in ^event_ids and e.organization_id == ^org_id,
          order_by: [desc: e.timestamp],
          limit: ^limit
        )
        |> Repo.all()

      {:ok, events}
    end
  rescue
    error ->
      Logger.warning(
        "related_events resolver failed for alert=#{inspect(alert.id)}: #{inspect(error)}"
      )

      {:ok, []}
  end

  def timeline(alert, _args, %{context: context}) do
    org_id = context[:organization_id]

    if is_nil(org_id) || alert.organization_id != org_id do
      {:ok, []}
    else
      # Build timeline from alert and related events
      timeline_events = []

      # Add alert creation
      timeline_events = [
        %{
          timestamp: alert.inserted_at,
          event_type: "alert_created",
          description: "Alert created: #{alert.title}",
          details: %{severity: alert.severity},
          severity: alert.severity,
          agent_id: alert.agent_id,
          event_id: nil
        }
        | timeline_events
      ]

      # Add related events
      event_ids = alert.event_ids || []

      timeline_events =
        if Enum.empty?(event_ids) do
          timeline_events
        else
          events =
            from(e in Event,
              where: e.id in ^event_ids and e.organization_id == ^org_id,
              order_by: [asc: e.timestamp]
            )
            |> Repo.all()

          event_timeline =
            Enum.map(events, fn e ->
              %{
                timestamp: e.timestamp,
                event_type: e.event_type,
                description: "Event: #{e.event_type}",
                details: e.payload,
                severity: e.severity,
                agent_id: e.agent_id,
                event_id: e.id
              }
            end)

          timeline_events ++ event_timeline
        end

      # Sort by timestamp
      timeline_events = Enum.sort_by(timeline_events, & &1.timestamp, {:asc, DateTime})

      {:ok, timeline_events}
    end
  end

  # Mutation resolvers

  def update_alert(_parent, %{id: id, input: input}, %{context: context}) do
    org_id = context[:organization_id]

    with :ok <- ensure_scoped_assignee(input[:assigned_to_id], org_id) do
      query =
        Alert
        |> maybe_scope_org(org_id)
        |> where([a], a.id == ^id)

      case Repo.one(query) do
        nil ->
          {:error, "Alert not found"}

        alert ->
          attrs =
            Map.take(input, [:status, :severity, :resolution_notes, :assigned_to_id])
            |> Map.new(fn {k, v} -> {k, v} end)

          case Alerts.update_alert(alert, attrs) do
            {:ok, updated} -> {:ok, updated}
            {:error, changeset} -> {:error, format_errors(changeset)}
          end
      end
    else
      _ -> {:error, "Assignee not found"}
    end
  end

  def assign_alert(_parent, %{id: id, user_id: user_id}, %{context: context}) do
    org_id = context[:organization_id]

    with :ok <- ensure_scoped_assignee(user_id, org_id) do
      query =
        Alert
        |> maybe_scope_org(org_id)
        |> where([a], a.id == ^id)

      case Repo.one(query) do
        nil ->
          {:error, "Alert not found"}

        alert ->
          case Alerts.update_alert(alert, %{assigned_to_id: user_id, status: "investigating"}) do
            {:ok, updated} -> {:ok, updated}
            {:error, changeset} -> {:error, format_errors(changeset)}
          end
      end
    else
      _ -> {:error, "Assignee not found"}
    end
  end

  def resolve_alert(_parent, %{id: id, resolution_notes: notes}, %{context: context}) do
    org_id = context[:organization_id]

    query =
      Alert
      |> maybe_scope_org(org_id)
      |> where([a], a.id == ^id)

    case Repo.one(query) do
      nil ->
        {:error, "Alert not found"}

      alert ->
        case Alerts.update_alert(alert, %{status: "resolved", resolution_notes: notes}) do
          {:ok, updated} -> {:ok, updated}
          {:error, changeset} -> {:error, format_errors(changeset)}
        end
    end
  end

  def mark_false_positive(_parent, %{id: id, reason: reason}, %{context: context}) do
    org_id = context[:organization_id]

    query =
      Alert
      |> maybe_scope_org(org_id)
      |> where([a], a.id == ^id)

    case Repo.one(query) do
      nil ->
        {:error, "Alert not found"}

      alert ->
        notes = "Marked as false positive: #{reason || "No reason provided"}"

        case Alerts.update_alert(alert, %{status: "false_positive", resolution_notes: notes}) do
          {:ok, updated} -> {:ok, updated}
          {:error, changeset} -> {:error, format_errors(changeset)}
        end
    end
  end

  def bulk_update_alerts(_parent, %{input: input}, %{context: context}) do
    org_id = context[:organization_id]
    alert_ids = input.alert_ids

    with :ok <- ensure_scoped_assignee(input[:assigned_to_id], org_id) do
      updates =
        %{}
        |> maybe_put_update(:status, input[:status])
        |> maybe_put_update(:assigned_to_id, input[:assigned_to_id])

      query =
        Alert
        |> maybe_scope_org(org_id)
        |> where([a], a.id in ^alert_ids)

      {count, _} = Repo.update_all(query, set: Map.to_list(updates))

      {:ok,
       %{
         success: true,
         message: "Updated #{count} alerts"
       }}
    else
      _ -> {:error, "Assignee not found"}
    end
  end

  # Private helpers

  defp maybe_scope_org(query, nil), do: where(query, [a], false)

  defp maybe_scope_org(query, org_id) do
    where(query, [a], a.organization_id == ^org_id)
  end

  defp apply_alert_filters(query, filter) do
    query
    |> maybe_filter(:status, filter[:status])
    |> maybe_filter(:severity, filter[:severity])
    |> maybe_filter(:agent_id, filter[:agent_id])
    |> maybe_filter(:assigned_to_id, filter[:assigned_to_id])
    |> maybe_filter_since(filter[:since])
    |> maybe_filter_until(filter[:until])
    |> maybe_filter_search(filter[:search])
    |> maybe_filter_mitre_tactic(filter[:mitre_tactic])
    |> maybe_filter_threat_score(filter[:threat_score_min])
  end

  defp maybe_filter(query, _field, nil), do: query

  defp maybe_filter(query, field, value) do
    where(query, [a], field(a, ^field) == ^value)
  end

  defp maybe_filter_since(query, nil), do: query

  defp maybe_filter_since(query, since) do
    where(query, [a], a.inserted_at >= ^since)
  end

  defp maybe_filter_until(query, nil), do: query

  defp maybe_filter_until(query, until_time) do
    where(query, [a], a.inserted_at <= ^until_time)
  end

  defp maybe_filter_search(query, nil), do: query

  defp maybe_filter_search(query, search) do
    pattern = "%#{search}%"
    where(query, [a], ilike(a.title, ^pattern) or ilike(a.description, ^pattern))
  end

  defp maybe_filter_mitre_tactic(query, nil), do: query

  defp maybe_filter_mitre_tactic(query, tactic) do
    where(query, [a], ^tactic in a.mitre_tactics)
  end

  defp maybe_filter_threat_score(query, nil), do: query

  defp maybe_filter_threat_score(query, min_score) do
    where(query, [a], a.threat_score >= ^min_score)
  end

  defp maybe_put_update(updates, _key, nil), do: updates
  defp maybe_put_update(updates, key, value), do: Map.put(updates, key, value)

  defp ensure_scoped_assignee(nil, _org_id), do: :ok
  defp ensure_scoped_assignee(_user_id, nil), do: {:error, :not_found}

  defp ensure_scoped_assignee(user_id, org_id) do
    if Repo.exists?(
         from(u in TamanduaServer.Accounts.User,
           where: u.id == ^user_id and u.organization_id == ^org_id
         )
       ),
       do: :ok,
       else: {:error, :not_found}
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
  end
end
