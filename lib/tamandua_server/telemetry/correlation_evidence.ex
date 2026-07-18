defmodule TamanduaServer.Telemetry.CorrelationEvidence do
  @moduledoc """
  Conservative event evidence extraction for investigation timelines.

  This module intentionally does not create alerts or change event severity. It
  extracts normalized entities, scores event-to-event evidence, and explains why
  two events are worth looking at together.
  """

  alias TamanduaServer.Telemetry.CorrelationScoringPolicy

  @default_threshold 40
  @max_events 250

  @type event_like :: map() | struct()

  @doc """
  Extract normalized entities from a telemetry event.
  """
  @spec extract_entities(event_like()) :: map()
  def extract_entities(event) do
    payload = value(event, :payload) || %{}
    enrichment = value(event, :enrichment) || %{}
    process = nested_map(payload, :process)
    file = nested_map(payload, :file)
    network = nested_map(payload, :network)
    dns = nested_map(payload, :dns)
    identity = nested_map(payload, :identity)

    %{
      identity:
        compact(%{
          baseline_key:
            first_present(payload, identity, [
              :baseline_key,
              :subject,
              :target,
              :subject_account,
              :target_account,
              :user,
              :username,
              :account_name
            ]),
          subject:
            first_present(payload, identity, [
              :subject,
              :subject_account,
              :account_name,
              :user,
              :username
            ]),
          target:
            first_present(payload, identity, [
              :target,
              :target_account,
              :destination_user,
              :dst_user
            ]),
          source_event_id: first_present(payload, identity, [:source_event_id, :event_id]),
          logon_type: first_present(payload, identity, [:logon_type]),
          auth_package: first_present(payload, identity, [:auth_package, :authentication_package])
        }),
      process:
        compact(%{
          pid: first_present(payload, process, [:pid, :process_id]),
          ppid: first_present(payload, process, [:ppid, :parent_pid, :parent_process_id]),
          name: first_present(payload, process, [:name, :process_name, :image_name]),
          path:
            first_present(payload, process, [:path, :process_path, :image_path, :executable_path]),
          command_line: first_present(payload, process, [:command_line, :cmdline, :command]),
          user: first_present(payload, process, [:user, :username, :account_name]),
          process_guid:
            first_present(payload, process, [:process_guid, :process_uuid, :entity_id])
        }),
      file:
        compact(%{
          path:
            first_present(payload, file, [
              :file_path,
              :target_path,
              :path,
              :destination_path,
              :source_path
            ]),
          sha256: first_present(payload, file, [:sha256, :hash_sha256, :file_sha256]),
          md5: first_present(payload, file, [:md5, :hash_md5, :file_md5])
        }),
      network:
        compact(%{
          local_ip: first_present(payload, network, [:local_ip, :src_ip, :source_ip]),
          local_port: first_present(payload, network, [:local_port, :src_port, :source_port]),
          remote_ip:
            first_present(payload, network, [:remote_ip, :dest_ip, :destination_ip, :dst_ip]),
          remote_port:
            first_present(payload, network, [
              :remote_port,
              :dest_port,
              :destination_port,
              :dst_port
            ]),
          protocol: first_present(payload, network, [:protocol, :ip_protocol]),
          direction: first_present([first(payload, [:direction]), first(network, [:direction])]),
          bytes_sent:
            first_present([
              first(payload, [:bytes_sent, :tx_bytes]),
              first(network, [:bytes_sent, :tx_bytes])
            ]),
          bytes_received:
            first_present([
              first(payload, [:bytes_received, :rx_bytes]),
              first(network, [:bytes_received, :rx_bytes])
            ])
        }),
      dns:
        compact(%{
          domain: first_present(payload, dns, [:domain, :query, :query_name, :hostname]),
          sni:
            first_present([first(payload, [:sni, :server_name]), first(dns, [:sni, :server_name])]),
          ja3:
            first_present([
              first(payload, [:ja3, :ja3_hash]),
              first(dns, [:ja3, :ja3_hash]),
              first(network, [:ja3, :ja3_hash])
            ])
        }),
      detection:
        compact(%{
          mitre_techniques: mitre_techniques(payload, enrichment),
          rule_names: rule_names(payload, value(event, :detections) || [])
        })
    }
  end

  @doc """
  Describe whether an event has enough fields to support good correlation.
  """
  @spec telemetry_quality(event_like()) :: map()
  def telemetry_quality(event) do
    event_type = value(event, :event_type) |> to_string()
    entities = extract_entities(event)
    expected = expected_fields(event_type)

    present =
      expected
      |> Enum.filter(fn path -> present_path?(entities, path) end)
      |> Enum.map(&Enum.join(&1, "."))

    missing =
      expected
      |> Enum.reject(fn path -> present_path?(entities, path) end)
      |> Enum.map(&Enum.join(&1, "."))

    score =
      case expected do
        [] -> 100
        _ -> round(length(present) / length(expected) * 100)
      end

    %{
      score: score,
      level: quality_level(score),
      present: present,
      missing: missing
    }
  end

  @doc """
  Score a pair of events and return explainable relationship evidence.
  """
  @spec score_pair(event_like(), event_like()) :: map()
  def score_pair(left, right) do
    left_entities = extract_entities(left)
    right_entities = extract_entities(right)
    same_agent? = string_value(value(left, :agent_id)) == string_value(value(right, :agent_id))
    minutes = abs(time_diff_minutes(value(left, :timestamp), value(right, :timestamp)))

    evidence =
      []
      |> maybe_add(
        same_process_guid?(left_entities, right_entities, same_agent?),
        60,
        "same process guid",
        "process_guid"
      )
      |> maybe_add(
        parent_child?(left_entities, right_entities, same_agent?, minutes),
        45,
        "parent/child process relationship",
        "process_tree"
      )
      |> maybe_add(
        same_pid?(left_entities, right_entities, same_agent?, minutes),
        35,
        "same pid on same agent within 10 minutes",
        "pid"
      )
      |> maybe_add(same_hash?(left_entities, right_entities), 50, "same sha256", "file_hash")
      |> maybe_add(
        same_file_path?(left_entities, right_entities, same_agent?),
        file_path_weight(left_entities, right_entities),
        "same file path on same agent",
        "file_path"
      )
      |> maybe_add(
        same_public_remote_ip?(left_entities, right_entities),
        35,
        "same public remote ip",
        "remote_ip"
      )
      |> maybe_add(
        same_private_remote_ip?(left_entities, right_entities, same_agent?),
        15,
        "same private remote ip on same agent",
        "remote_ip_private"
      )
      |> maybe_add(
        same_domain?(left_entities, right_entities),
        35,
        "same domain or sni",
        "domain"
      )
      |> maybe_add(
        same_identity?(left_entities, right_entities),
        45,
        "same identity baseline key",
        "identity"
      )
      |> maybe_add(
        same_supported_mitre?(left_entities, right_entities),
        15,
        "same MITRE technique with supporting entity evidence",
        "mitre"
      )
      |> maybe_add(minutes <= 5, 10, "within 5 minutes", "temporal")

    scoring = CorrelationScoringPolicy.score(evidence, threshold: @default_threshold)

    strong_types =
      evidence
      |> Enum.map(& &1.type)
      |> Enum.reject(&CorrelationScoringPolicy.context_only_type?/1)

    %{
      scoringVersion: CorrelationScoringPolicy.version(),
      score: scoring.score,
      reasons: Enum.map(evidence, & &1.reason),
      relationTypes: Enum.uniq(Enum.map(evidence, & &1.type)),
      sharedEntities: Enum.uniq(strong_types),
      timeDeltaMinutes: minutes,
      scoring: scoring
    }
  end

  @doc """
  Correlate a bounded set of events for timeline visualization.
  """
  @spec correlate_events([event_like()], keyword()) :: map()
  def correlate_events(events, opts \\ []) when is_list(events) do
    threshold = Keyword.get(opts, :threshold, @default_threshold)
    max_events = Keyword.get(opts, :max_events, @max_events)
    analyzed_events = Enum.take(events, max_events)

    links =
      analyzed_events
      |> pairs()
      |> Enum.map(fn {left, right} ->
        evidence = score_pair(left, right)

        %{
          source: string_value(value(left, :id)),
          target: string_value(value(right, :id)),
          score: evidence.score,
          reasons: evidence.reasons,
          relationTypes: evidence.relationTypes,
          sharedEntities: evidence.sharedEntities,
          timeDeltaMinutes: evidence.timeDeltaMinutes,
          scoring: evidence.scoring
        }
      end)
      |> Enum.filter(&(&1.score >= threshold))
      |> Enum.sort_by(& &1.score, :desc)

    %{
      scoring_version: CorrelationScoringPolicy.version(),
      scoring_policy: %{
        version: CorrelationScoringPolicy.version(),
        threshold: threshold,
        mode: "conservative_multi_signal",
        requirements: [
          "requires at least one strong shared entity",
          "temporal, MITRE and private IP overlap are context only"
        ]
      },
      correlations: links,
      event_links: event_links(links),
      entity_graph: entity_graph(analyzed_events, links),
      incident_candidates: incident_candidates(analyzed_events, links),
      campaign_candidates: campaign_candidates(analyzed_events, links),
      risk_score: risk_score(analyzed_events, links),
      attack_chain: attack_chain(analyzed_events),
      evidence_summary: evidence_summary(links),
      telemetry_gaps: telemetry_gaps(analyzed_events),
      analyzed_event_count: length(analyzed_events),
      partial: length(events) > length(analyzed_events)
    }
  end

  defp pairs(events) do
    events
    |> Enum.with_index()
    |> Enum.flat_map(fn {left, index} ->
      events
      |> Enum.drop(index + 1)
      |> Enum.map(fn right -> {left, right} end)
    end)
  end

  defp event_links(links) do
    Enum.reduce(links, %{}, fn link, acc ->
      acc
      |> Map.update(
        link.source,
        [related_link(link.target, link)],
        &[related_link(link.target, link) | &1]
      )
      |> Map.update(
        link.target,
        [related_link(link.source, link)],
        &[related_link(link.source, link) | &1]
      )
    end)
    |> Enum.into(%{}, fn {event_id, related} ->
      {event_id, Enum.sort_by(related, & &1.score, :desc)}
    end)
  end

  defp entity_graph(events, links) do
    linked_event_ids =
      links
      |> Enum.flat_map(&[&1.source, &1.target])
      |> MapSet.new()

    event_nodes =
      events
      |> Enum.filter(fn event ->
        MapSet.member?(linked_event_ids, string_value(value(event, :id)))
      end)
      |> Enum.map(fn event ->
        event_id = string_value(value(event, :id))

        %{
          id: event_id,
          type: "event",
          label: value(event, :event_type) |> to_string(),
          severity: value(event, :severity) |> to_string()
        }
      end)

    {entity_nodes, entity_edges} =
      events
      |> Enum.filter(fn event ->
        MapSet.member?(linked_event_ids, string_value(value(event, :id)))
      end)
      |> Enum.flat_map(fn event ->
        event_id = string_value(value(event, :id))

        event
        |> extract_entities()
        |> graph_entities()
        |> Enum.map(fn entity ->
          entity_id = entity_node_id(entity.type, entity.value)

          {
            Map.put(entity, :id, entity_id),
            %{
              source: event_id,
              target: entity_id,
              type: "observed_entity",
              entityType: entity.type
            }
          }
        end)
      end)
      |> Enum.reduce({%{}, []}, fn {node, edge}, {nodes, edges} ->
        {Map.put(nodes, node.id, node), [edge | edges]}
      end)

    %{
      scoringVersion: CorrelationScoringPolicy.version(),
      nodes: event_nodes ++ Map.values(entity_nodes),
      edges: Enum.reverse(entity_edges)
    }
  end

  defp related_link(event_id, link) do
    %{
      id: event_id,
      score: link.score,
      reasons: link.reasons,
      relationTypes: link.relationTypes
    }
  end

  defp incident_candidates(events, links) do
    events_by_id = Map.new(events, fn event -> {string_value(value(event, :id)), event} end)

    links
    |> connected_components()
    |> Enum.map(fn event_ids ->
      component_links = links_for_component(links, event_ids)
      relation_types = component_relation_types(component_links)
      shared_entities = component_shared_entities(component_links)
      score = component_score(component_links)

      %{
        id: candidate_id("incident", event_ids),
        scoringVersion: CorrelationScoringPolicy.version(),
        eventIds: event_ids,
        eventCount: length(event_ids),
        score: score,
        severity: component_severity(event_ids, events_by_id),
        relationTypes: relation_types,
        supportingEntities: shared_entities,
        title: incident_title(event_ids, events_by_id, relation_types)
      }
    end)
    |> Enum.filter(&(&1.eventCount >= 2 and &1.supportingEntities != []))
    |> Enum.sort_by(& &1.score, :desc)
  end

  defp campaign_candidates(events, links) do
    events
    |> incident_candidates(links)
    |> Enum.filter(fn candidate ->
      candidate.eventCount >= 3 or length(candidate.supportingEntities) >= 2
    end)
    |> Enum.map(fn candidate ->
      candidate
      |> Map.put(:id, String.replace(candidate.id, "incident:", "campaign:", global: false))
      |> Map.put(:campaignSignals, campaign_signals(candidate))
    end)
  end

  defp risk_score(events, links) do
    severity_score =
      events
      |> Enum.map(fn event -> severity_weight(value(event, :severity)) end)
      |> Enum.max(fn -> 0 end)

    link_score =
      links
      |> Enum.take(5)
      |> Enum.map(& &1.score)
      |> Enum.sum()
      |> div(5)

    min(100, severity_score + link_score)
  end

  defp attack_chain(events) do
    events
    |> Enum.flat_map(fn event ->
      entities = extract_entities(event)
      get_in(entities, [:detection, :mitre_techniques]) || []
    end)
    |> Enum.uniq()
    |> Enum.take(12)
  end

  defp evidence_summary(links) do
    links
    |> Enum.flat_map(& &1.relationTypes)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_type, count} -> count end, :desc)
    |> Enum.map(fn {type, count} -> %{type: type, count: count} end)
  end

  defp telemetry_gaps(events) do
    events
    |> Enum.flat_map(fn event -> telemetry_quality(event).missing end)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_field, count} -> count end, :desc)
    |> Enum.take(10)
    |> Enum.map(fn {field, count} -> %{field: field, count: count} end)
  end

  defp connected_components([]), do: []

  defp connected_components(links) do
    adjacency =
      Enum.reduce(links, %{}, fn link, acc ->
        acc
        |> Map.update(link.source, MapSet.new([link.target]), &MapSet.put(&1, link.target))
        |> Map.update(link.target, MapSet.new([link.source]), &MapSet.put(&1, link.source))
      end)

    adjacency
    |> Map.keys()
    |> Enum.reduce({MapSet.new(), []}, fn event_id, {visited, components} ->
      if MapSet.member?(visited, event_id) do
        {visited, components}
      else
        component =
          walk_component([event_id], adjacency, MapSet.new()) |> MapSet.to_list() |> Enum.sort()

        {MapSet.union(visited, MapSet.new(component)), [component | components]}
      end
    end)
    |> elem(1)
    |> Enum.reverse()
  end

  defp walk_component([], _adjacency, visited), do: visited

  defp walk_component([event_id | rest], adjacency, visited) do
    if MapSet.member?(visited, event_id) do
      walk_component(rest, adjacency, visited)
    else
      neighbors = adjacency |> Map.get(event_id, MapSet.new()) |> MapSet.to_list()
      walk_component(neighbors ++ rest, adjacency, MapSet.put(visited, event_id))
    end
  end

  defp links_for_component(links, event_ids) do
    ids = MapSet.new(event_ids)
    Enum.filter(links, &(MapSet.member?(ids, &1.source) and MapSet.member?(ids, &1.target)))
  end

  defp component_relation_types(links) do
    links
    |> Enum.flat_map(& &1.relationTypes)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp component_shared_entities(links) do
    links
    |> Enum.flat_map(& &1.sharedEntities)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp component_score([]), do: 0

  defp component_score(links) do
    links
    |> Enum.map(& &1.score)
    |> Enum.sum()
    |> Kernel./(length(links))
    |> round()
  end

  defp component_severity(event_ids, events_by_id) do
    event_ids
    |> Enum.map(fn id -> events_by_id |> Map.get(id) |> then(&value(&1, :severity)) end)
    |> Enum.max_by(&severity_weight/1, fn -> "info" end)
    |> to_string()
  end

  defp incident_title(event_ids, events_by_id, relation_types) do
    event_types =
      event_ids
      |> Enum.map(fn id ->
        events_by_id |> Map.get(id) |> then(&value(&1, :event_type)) |> to_string()
      end)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()
      |> Enum.take(3)

    relation = relation_types |> List.first() || "correlation"
    "#{length(event_ids)} related events via #{relation}: #{Enum.join(event_types, ", ")}"
  end

  defp campaign_signals(candidate) do
    []
    |> maybe_add_signal(candidate.eventCount >= 3, "multi_event_cluster")
    |> maybe_add_signal(length(candidate.supportingEntities) >= 2, "multiple_supporting_entities")
  end

  defp maybe_add_signal(signals, true, signal), do: [signal | signals]
  defp maybe_add_signal(signals, _, _), do: signals

  defp candidate_id(prefix, event_ids) do
    digest =
      event_ids
      |> Enum.join(":")
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)
      |> binary_part(0, 12)

    "#{prefix}:#{digest}"
  end

  defp expected_fields(event_type) do
    cond do
      String.starts_with?(event_type, "process") ->
        [
          [:process, :pid],
          [:process, :name],
          [:process, :path],
          [:process, :ppid],
          [:process, :user]
        ]

      String.starts_with?(event_type, "file") ->
        [[:file, :path], [:process, :pid], [:process, :name]]

      String.starts_with?(event_type, "network") ->
        [
          [:network, :remote_ip],
          [:network, :remote_port],
          [:network, :protocol],
          [:process, :pid],
          [:process, :name]
        ]

      String.starts_with?(event_type, "dns") ->
        [[:dns, :domain], [:process, :pid], [:process, :name]]

      String.starts_with?(event_type, "auth") or String.starts_with?(event_type, "identity") ->
        [[:identity, :baseline_key]]

      String.starts_with?(event_type, "registry") ->
        [[:process, :pid], [:process, :name]]

      true ->
        []
    end
  end

  defp same_process_guid?(left, right, true) do
    present_equal?(
      get_in(left, [:process, :process_guid]),
      get_in(right, [:process, :process_guid])
    )
  end

  defp same_process_guid?(_, _, _), do: false

  defp parent_child?(left, right, true, minutes) when minutes <= 10 do
    left_pid = normalize_int(get_in(left, [:process, :pid]))
    left_ppid = normalize_int(get_in(left, [:process, :ppid]))
    right_pid = normalize_int(get_in(right, [:process, :pid]))
    right_ppid = normalize_int(get_in(right, [:process, :ppid]))

    (left_pid && right_ppid && left_pid == right_ppid) ||
      (right_pid && left_ppid && right_pid == left_ppid)
  end

  defp parent_child?(_, _, _, _), do: false

  defp same_pid?(left, right, true, minutes) when minutes <= 10 do
    present_equal?(
      normalize_int(get_in(left, [:process, :pid])),
      normalize_int(get_in(right, [:process, :pid]))
    )
  end

  defp same_pid?(_, _, _, _), do: false

  defp same_hash?(left, right) do
    left_hash = normalized_hash(get_in(left, [:file, :sha256]))
    right_hash = normalized_hash(get_in(right, [:file, :sha256]))
    present_equal?(left_hash, right_hash)
  end

  defp same_file_path?(left, right, true) do
    present_equal?(
      normalize_path(get_in(left, [:file, :path])),
      normalize_path(get_in(right, [:file, :path]))
    )
  end

  defp same_file_path?(_, _, _), do: false

  defp file_path_weight(left, right) do
    path =
      normalize_path(get_in(left, [:file, :path])) ||
        normalize_path(get_in(right, [:file, :path]))

    if noisy_path?(path), do: 15, else: 30
  end

  defp same_public_remote_ip?(left, right) do
    left_ip = string_value(get_in(left, [:network, :remote_ip]))
    right_ip = string_value(get_in(right, [:network, :remote_ip]))
    present_equal?(left_ip, right_ip) && !private_ip?(left_ip)
  end

  defp same_private_remote_ip?(left, right, true) do
    left_ip = string_value(get_in(left, [:network, :remote_ip]))
    right_ip = string_value(get_in(right, [:network, :remote_ip]))
    present_equal?(left_ip, right_ip) && private_ip?(left_ip)
  end

  defp same_private_remote_ip?(_, _, _), do: false

  defp same_domain?(left, right) do
    left_domain = normalize_domain(get_in(left, [:dns, :domain]) || get_in(left, [:dns, :sni]))
    right_domain = normalize_domain(get_in(right, [:dns, :domain]) || get_in(right, [:dns, :sni]))

    present_equal?(left_domain, right_domain) and not common_domain?(left_domain)
  end

  defp same_identity?(left, right) do
    present_equal?(
      normalize_identity(get_in(left, [:identity, :baseline_key])),
      normalize_identity(get_in(right, [:identity, :baseline_key]))
    )
  end

  defp same_supported_mitre?(left, right) do
    left_techniques = MapSet.new(get_in(left, [:detection, :mitre_techniques]) || [])
    right_techniques = MapSet.new(get_in(right, [:detection, :mitre_techniques]) || [])
    MapSet.size(MapSet.intersection(left_techniques, right_techniques)) > 0
  end

  defp graph_entities(entities) do
    [
      graph_entity("process_guid", get_in(entities, [:process, :process_guid])),
      graph_entity("identity", get_in(entities, [:identity, :baseline_key])),
      graph_entity("file_hash", get_in(entities, [:file, :sha256])),
      graph_entity("file_path", get_in(entities, [:file, :path])),
      graph_entity("remote_ip", get_in(entities, [:network, :remote_ip])),
      graph_entity("domain", get_in(entities, [:dns, :domain]) || get_in(entities, [:dns, :sni]))
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp graph_entity("file_hash", value) do
    case normalized_hash(value) do
      nil -> nil
      hash -> %{type: "file_hash", value: hash, label: hash, strength: "strong"}
    end
  end

  defp graph_entity("file_path", value) do
    path = normalize_path(value)

    if present?(path) and not noisy_path?(path) do
      %{type: "file_path", value: path, label: path, strength: "strong"}
    end
  end

  defp graph_entity("remote_ip", value) do
    ip = string_value(value)

    if present?(ip) and not private_ip?(ip) do
      %{type: "remote_ip", value: ip, label: ip, strength: "strong"}
    end
  end

  defp graph_entity("domain", value) do
    domain = normalize_domain(value)

    if present?(domain) and not common_domain?(domain) do
      %{type: "domain", value: domain, label: domain, strength: "strong"}
    end
  end

  defp graph_entity("identity", value) do
    identity = normalize_identity(value)

    if present?(identity) do
      %{type: "identity", value: identity, label: identity, strength: "strong"}
    end
  end

  defp graph_entity(type, value) do
    if present?(value) do
      normalized = string_value(value)
      %{type: type, value: normalized, label: normalized, strength: "strong"}
    end
  end

  defp entity_node_id(type, value), do: "entity:#{type}:#{value}"

  defp maybe_add(evidence, true, score, reason, type),
    do: [%{score: score, reason: reason, type: type} | evidence]

  defp maybe_add(evidence, _, _, _, _), do: evidence

  defp present_path?(map, path), do: present?(get_in(map, path))

  defp present_equal?(left, right), do: present?(left) && present?(right) && left == right

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(value) when is_list(value), do: value != []
  defp present?(nil), do: false
  defp present?(_), do: true

  defp compact(map) do
    map
    |> Enum.reject(fn {_key, value} -> !present?(value) end)
    |> Map.new()
  end

  defp first(map, keys) do
    Enum.find_value(keys, fn key -> value(map, key) end)
  end

  defp first_present(primary, nested, keys) do
    first_present([first(primary, keys), first(nested, keys)])
  end

  defp first_present(values) do
    Enum.find(values, &present?/1)
  end

  defp nested_map(map, key) do
    case value(map, key) do
      nested when is_map(nested) -> nested
      _ -> %{}
    end
  end

  defp value(%{} = map, key) when is_atom(key),
    do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp value(map, key) when is_map(map), do: Map.get(map, key)
  defp value(_, _), do: nil

  defp mitre_techniques(payload, enrichment) do
    [
      value(payload, :mitre_techniques),
      value(payload, :techniques),
      value(payload, :mitre_technique),
      value(enrichment, :mitre_techniques)
    ]
    |> Enum.flat_map(&List.wrap/1)
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp rule_names(payload, detections) do
    payload_rules = List.wrap(value(payload, :rule_name) || value(payload, :rule_names))

    detection_rules =
      detections
      |> List.wrap()
      |> Enum.filter(&is_map/1)
      |> Enum.map(fn detection -> value(detection, :rule_name) || value(detection, :name) end)

    (payload_rules ++ detection_rules)
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp quality_level(score) when score >= 75, do: "good"
  defp quality_level(score) when score >= 40, do: "partial"
  defp quality_level(_), do: "poor"

  defp severity_weight("critical"), do: 70
  defp severity_weight("high"), do: 50
  defp severity_weight("medium"), do: 30
  defp severity_weight("low"), do: 15
  defp severity_weight(_), do: 5

  defp time_diff_minutes(nil, _), do: 999_999
  defp time_diff_minutes(_, nil), do: 999_999

  defp time_diff_minutes(%DateTime{} = left, %DateTime{} = right),
    do: DateTime.diff(left, right, :minute)

  defp time_diff_minutes(%NaiveDateTime{} = left, %NaiveDateTime{} = right),
    do: NaiveDateTime.diff(left, right, :minute)

  defp time_diff_minutes(left, right) when is_binary(left) and is_binary(right) do
    with {:ok, left_dt, _} <- DateTime.from_iso8601(left),
         {:ok, right_dt, _} <- DateTime.from_iso8601(right) do
      DateTime.diff(left_dt, right_dt, :minute)
    else
      _ -> 999_999
    end
  end

  defp time_diff_minutes(_, _), do: 999_999

  defp string_value(nil), do: nil
  defp string_value(value), do: value |> to_string() |> String.trim()

  defp normalize_int(value) when is_integer(value), do: value

  defp normalize_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} -> int
      _ -> nil
    end
  end

  defp normalize_int(_), do: nil

  defp normalized_hash(value) when is_binary(value) do
    value = value |> String.trim() |> String.downcase()
    if String.length(value) >= 32, do: value, else: nil
  end

  defp normalized_hash(_), do: nil

  defp normalize_path(value) when is_binary(value) do
    value
    |> String.replace("\\", "/")
    |> String.downcase()
    |> String.trim()
  end

  defp normalize_path(_), do: nil

  defp normalize_domain(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.trim_trailing(".")
    |> String.downcase()
  end

  defp normalize_domain(_), do: nil

  defp normalize_identity(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_identity(_), do: nil

  defp noisy_path?(nil), do: false

  defp noisy_path?(path) do
    String.contains?(path, "/cache/") ||
      String.contains?(path, "/caches/") ||
      String.contains?(path, "/appdata/local/temp/") ||
      String.contains?(path, "/appdata/local/microsoft/") ||
      String.contains?(path, "/appdata/local/google/") ||
      String.contains?(path, "/appdata/local/packages/") ||
      String.contains?(path, "/windows/temp/") ||
      String.contains?(path, "/tmp/") ||
      String.contains?(path, "/temp/")
  end

  defp common_domain?(nil), do: false

  defp common_domain?(domain) do
    domain in [
      "apple.com",
      "icloud.com",
      "microsoft.com",
      "windows.com",
      "google.com",
      "gstatic.com",
      "googleapis.com",
      "spotify.com",
      "office.com",
      "live.com"
    ] or
      String.ends_with?(domain, ".apple.com") or
      String.ends_with?(domain, ".icloud.com") or
      String.ends_with?(domain, ".microsoft.com") or
      String.ends_with?(domain, ".windows.com") or
      String.ends_with?(domain, ".google.com") or
      String.ends_with?(domain, ".gstatic.com") or
      String.ends_with?(domain, ".googleapis.com") or
      String.ends_with?(domain, ".spotify.com") or
      String.ends_with?(domain, ".office.com") or
      String.ends_with?(domain, ".live.com")
  end

  defp private_ip?(nil), do: false

  defp private_ip?(ip) do
    String.starts_with?(ip, "10.") ||
      String.starts_with?(ip, "192.168.") ||
      String.starts_with?(ip, "172.16.") ||
      String.starts_with?(ip, "172.17.") ||
      String.starts_with?(ip, "172.18.") ||
      String.starts_with?(ip, "172.19.") ||
      String.starts_with?(ip, "172.2") ||
      String.starts_with?(ip, "172.30.") ||
      String.starts_with?(ip, "172.31.") ||
      String.starts_with?(ip, "127.") ||
      ip == "::1"
  end
end
