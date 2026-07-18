defmodule TamanduaServer.Alerts.EvidenceGraph do
  @moduledoc """
  Builds a canonical, read-only investigation graph from persisted alert data.

  Nodes never infer entities that are absent from the alert. The graph embeds
  `EvidenceQuality` so consumers can distinguish direct evidence from partial
  or synthetic context before presenting pivots as claimable facts.
  """

  alias TamanduaServer.Alerts.EvidenceQuality

  @schema "tamandua.alert.evidence_graph/v1"

  @spec build(map() | struct()) :: map()
  def build(alert) do
    evidence = map_value(alert, :evidence)
    raw_event = map_value(alert, :raw_event)
    source_event_id = value(alert, :source_event_id)
    alert_id = value(alert, :id) || source_event_id || "unknown"

    alert_node =
      node("alert", alert_id, %{title: value(alert, :title), severity: value(alert, :severity)})

    {nodes, edges} =
      {[alert_node], []}
      |> add_entity(
        alert_node,
        "event",
        source_event_id,
        %{event_id: source_event_id},
        "derived_from"
      )
      |> add_entity(
        alert_node,
        "asset",
        value(alert, :agent_id),
        %{agent_id: value(alert, :agent_id)},
        "affects"
      )
      |> add_detection(alert_node, alert)
      |> add_user(alert_node, evidence, raw_event)
      |> add_processes(alert_node, alert, evidence, raw_event)
      |> add_file(alert_node, evidence, raw_event)
      |> add_network(alert_node, evidence, raw_event)

    nodes = Enum.uniq_by(nodes, & &1.id)
    edges = Enum.uniq_by(edges, &{&1.from, &1.to, &1.relationship})
    quality = EvidenceQuality.classify(alert)

    %{
      schema: @schema,
      alert_id: to_string(alert_id),
      evidence_quality: quality,
      claimable: quality.claimable,
      nodes: nodes,
      edges: edges,
      pivots: pivots(nodes),
      gaps: quality.missing
    }
  end

  defp add_detection({nodes, edges}, alert_node, alert) do
    detection = map_value(alert, :detection_metadata)
    rule = value(detection, :rule_id) || value(detection, :rule_name) || value(alert, :rule_id)
    add_entity({nodes, edges}, alert_node, "detection", rule, detection, "triggered_by")
  end

  defp add_user({nodes, edges}, alert_node, evidence, raw_event) do
    user = map_value(evidence, :user)

    user_name =
      value(user, :name) || value(user, :username) || value(raw_event, :username) ||
        value(raw_event, :user)

    attrs = if map_size(user) > 0, do: user, else: %{name: user_name}
    add_entity({nodes, edges}, alert_node, "user", user_name, attrs, "observed_user")
  end

  defp add_processes({nodes, edges}, alert_node, alert, evidence, raw_event) do
    primary = map_value(evidence, :process)
    chain = list_value(alert, :process_chain)

    processes =
      [primary | chain]
      |> Enum.filter(&(is_map(&1) and map_size(&1) > 0))
      |> case do
        [] ->
          fallback = %{
            pid: value(raw_event, :pid),
            name: value(raw_event, :process_name),
            command_line: value(raw_event, :command_line)
          }

          if Enum.any?(Map.values(fallback), &present?/1), do: [fallback], else: []

        values ->
          values
      end

    {nodes, edges, process_nodes} =
      Enum.reduce(processes, {nodes, edges, []}, fn process, {node_acc, edge_acc, process_acc} ->
        identity =
          value(process, :pid) || value(process, :process_guid) || value(process, :path) ||
            value(process, :name)

        if present?(identity) do
          process_node = node("process", identity, process)

          {[process_node | node_acc], [edge(alert_node, process_node, "involves") | edge_acc],
           [process_node | process_acc]}
        else
          {node_acc, edge_acc, process_acc}
        end
      end)

    process_edges =
      for child <- process_nodes,
          parent <- process_nodes,
          child.id != parent.id,
          present?(value(child.attributes, :ppid)),
          to_string(value(child.attributes, :ppid)) == to_string(value(parent.attributes, :pid)) do
        edge(parent, child, "spawned")
      end

    {nodes, process_edges ++ edges}
  end

  defp add_file({nodes, edges}, alert_node, evidence, raw_event) do
    file = map_value(evidence, :file)

    identity =
      value(file, :sha256) || value(file, :hash) || value(file, :path) ||
        value(raw_event, :file_path)

    attrs = if map_size(file) > 0, do: file, else: %{path: value(raw_event, :file_path)}
    add_entity({nodes, edges}, alert_node, "file", identity, attrs, "references")
  end

  defp add_network({nodes, edges}, alert_node, evidence, raw_event) do
    candidates = network_candidates(value(evidence, :network))

    candidates =
      if candidates == [] do
        [%{remote_ip: value(raw_event, :remote_ip), domain: value(raw_event, :domain)}]
      else
        candidates
      end

    Enum.reduce(candidates, {nodes, edges}, fn network, acc ->
      identity =
        value(network, :remote_ip) || value(network, :dst_ip) || value(network, :domain) ||
          value(network, :host) || value(network, :tls_sni)

      add_entity(acc, alert_node, "network", identity, network, "communicates_with")
    end)
  end

  defp add_entity({nodes, edges}, _root, _type, identity, _attrs, _relationship)
       when identity in [nil, ""],
       do: {nodes, edges}

  defp add_entity({nodes, edges}, root, type, identity, attrs, relationship) do
    entity = node(type, identity, attrs)
    {[entity | nodes], [edge(root, entity, relationship) | edges]}
  end

  defp node(type, identity, attributes) do
    %{
      id: "#{type}:#{identity}",
      type: type,
      label: label(type, identity, attributes),
      attributes: attributes || %{}
    }
  end

  defp edge(from, to, relationship), do: %{from: from.id, to: to.id, relationship: relationship}

  defp label("process", identity, attributes),
    do: value(attributes, :name) || value(attributes, :path) || to_string(identity)

  defp label("detection", identity, attributes),
    do: value(attributes, :rule_name) || to_string(identity)

  defp label("user", identity, _attributes), do: to_string(identity)
  defp label(_type, identity, _attributes), do: to_string(identity)

  defp pivots(nodes) do
    nodes
    |> Enum.flat_map(fn node -> pivot_for(node.type, node.attributes) end)
    |> Enum.reject(fn pivot -> not present?(pivot.value) end)
    |> Enum.uniq_by(&{&1.field, &1.value})
  end

  defp pivot_for("event", attrs), do: pivot(attrs, event_id: :event_id)
  defp pivot_for("asset", attrs), do: pivot(attrs, agent_id: :agent_id)

  defp pivot_for("user", attrs),
    do: pivot(attrs, username: :username, name: :username, sid: :user_sid)

  defp pivot_for("process", attrs),
    do:
      pivot(attrs,
        pid: :process_pid,
        process_guid: :process_guid,
        name: :process_name,
        path: :process_path,
        sha256: :file_sha256
      )

  defp pivot_for("file", attrs),
    do: pivot(attrs, sha256: :file_sha256, hash: :file_hash, path: :file_path)

  defp pivot_for("network", attrs),
    do:
      pivot(attrs,
        remote_ip: :remote_ip,
        dst_ip: :remote_ip,
        domain: :domain,
        host: :domain,
        tls_sni: :domain
      )

  defp pivot_for("detection", attrs), do: pivot(attrs, rule_id: :rule_id, rule_name: :rule_name)
  defp pivot_for(_type, _attrs), do: []

  defp pivot(attrs, mappings) do
    Enum.map(mappings, fn {source, field} ->
      %{
        field: Atom.to_string(field),
        value: value(attrs, source),
        query: %{field: Atom.to_string(field), operator: "equals", value: value(attrs, source)}
      }
    end)
  end

  defp network_candidates(value) when is_list(value), do: Enum.filter(value, &is_map/1)
  defp network_candidates(value) when is_map(value) and map_size(value) > 0, do: [value]
  defp network_candidates(_value), do: []

  defp map_value(source, key) do
    case value(source, key) do
      candidate when is_map(candidate) -> candidate
      _candidate -> %{}
    end
  end

  defp list_value(source, key) do
    case value(source, key) do
      candidate when is_list(candidate) -> candidate
      _candidate -> []
    end
  end

  defp value(source, key) when is_map(source),
    do: Map.get(source, key) || Map.get(source, Atom.to_string(key))

  defp value(_source, _key), do: nil

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(_value), do: true
end
