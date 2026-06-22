defmodule TamanduaServerWeb.API.V1.YaraRuleController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AuditLog
  alias TamanduaServer.Detection.Rules
  alias TamanduaServer.Detection.YaraScanner
  alias TamanduaServer.Detection.YaraGenerator

  # Pagination defaults for /yara-rules. The merged response combines DB
  # rules + builtin file-backed rules so clamping happens at the controller
  # level (the DB query alone cannot bound the response). Mirrors
  # AgentController / SigmaRuleController / AlertController.
  @default_per_page 50
  @max_per_page 200

  action_fallback TamanduaServerWeb.FallbackController

  def index(conn, params) do
    {limit, offset} = pagination_params(params)

    base_filters = %{
      enabled: params["enabled"],
      category: params["category"]
    }

    # YARA rules come from two sources (Postgres + builtin .yar files on disk).
    # We materialize both, concatenate DB-first to preserve existing ordering,
    # then page in memory. Total rule counts are O(hundreds), so in-memory
    # pagination is acceptable here.
    database_rules = Rules.list_yara_rules(base_filters) |> Enum.map(&serialize/1)
    builtin_rules = list_builtin_file_rules(base_filters)

    all_rules = database_rules ++ builtin_rules
    total = length(all_rules)
    page = all_rules |> Enum.drop(offset) |> Enum.take(limit)

    json(conn, %{
      data: page,
      meta: %{total: total, limit: limit, offset: offset}
    })
  end

  def show(conn, %{"id" => id}) do
    rule = Rules.get_yara_rule!(id)
    json(conn, %{data: serialize(rule)})
  end

  def create(conn, params) do
    attrs = normalize_rule_params(params)

    case Rules.create_yara_rule(attrs) do
      {:ok, rule} ->
        user = conn.assigns[:current_user]
        AuditLog.log_rule_change(user, "yara", "created", rule.id, %{
          rule_name: rule.name,
          category: rule.category
        }, request_metadata(conn))

        conn
        |> put_status(:created)
        |> json(%{data: serialize(rule)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def update(conn, %{"id" => id} = params) do
    rule = Rules.get_yara_rule!(id)
    attrs = params |> Map.delete("id") |> normalize_rule_params()

    case Rules.update_yara_rule(rule, attrs) do
      {:ok, rule} ->
        user = conn.assigns[:current_user]
        AuditLog.log_rule_change(user, "yara", "updated", id, %{
          rule_name: rule.name,
          changes: attrs
        }, request_metadata(conn))

        json(conn, %{data: serialize(rule)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def delete(conn, %{"id" => id}) do
    rule = Rules.get_yara_rule!(id)

    case Rules.delete_yara_rule(rule) do
      {:ok, _} ->
        user = conn.assigns[:current_user]
        AuditLog.log_rule_change(user, "yara", "deleted", id, %{
          rule_name: rule.name
        }, request_metadata(conn))

        send_resp(conn, :no_content, "")

      {:error, _} ->
        conn
        |> put_status(400)
        |> json(%{error: "Failed to delete rule"})
    end
  end

  defp serialize(rule) do
    %{
      id: rule.id,
      name: rule.name,
      description: rule.description,
      content: rule.source,
      source: rule.source,
      enabled: rule.enabled,
      author: rule.author,
      category: rule.category,
      tags: rule.tags || [],
      severity: rule.severity,
      mitre_techniques: rule.mitre_techniques || [],
      inserted_at: iso8601_or_nil(rule.inserted_at),
      updated_at: iso8601_or_nil(rule.updated_at),
      created_at: iso8601_or_nil(rule.inserted_at),
      updated_at_legacy: iso8601_or_nil(rule.updated_at)
    }
  end

  defp list_builtin_file_rules(filters) do
    filters = Map.new(filters, fn {key, value} -> {to_string(key), value} end)

    YaraScanner.get_rule_files()
    |> Enum.map(&serialize_builtin_rule_file/1)
    |> Enum.filter(&builtin_rule_matches_filters?(&1, filters))
  end

  defp serialize_builtin_rule_file(path) do
    source =
      case File.read(path) do
        {:ok, content} -> content
        {:error, reason} -> "rule unavailable_#{System.unique_integer([:positive])} { meta: description = \"Failed to read #{Path.basename(path)}: #{inspect(reason)}\" condition: false }"
      end
    filename = Path.basename(path)
    name = Path.rootname(filename)
    rule_names = extract_yara_rule_names(source)
    mitre_techniques = extract_mitre_techniques(source)
    tags = extract_yara_tags(source)
    severity = extract_highest_severity(source)
    description = extract_first_meta(source, "description") ||
      "Built-in YARA rule file with #{length(rule_names)} rule definitions."

    %{
      id: "builtin:#{filename}",
      name: name,
      description: description,
      content: source,
      source: source,
      enabled: true,
      readonly: true,
      source_type: "builtin_file",
      file_name: filename,
      file_path: path,
      author: extract_first_meta(source, "author") || "Tamandua",
      category: name |> String.replace("_", " "),
      tags: tags,
      severity: severity,
      mitre_techniques: mitre_techniques,
      rule_count: length(rule_names),
      meta: %{
        "source" => "priv/yara_rules",
        "file" => filename,
        "rule_count" => Integer.to_string(length(rule_names))
      }
    }
  end

  defp builtin_rule_matches_filters?(rule, %{"enabled" => enabled}) when enabled in ["false", false] do
    false
  end
  defp builtin_rule_matches_filters?(rule, filters) do
    category = filters["category"]
    is_nil(category) or category == "" or rule.category == category
  end

  defp extract_yara_rule_names(source) do
    ~r/\brule\s+([A-Za-z_][A-Za-z0-9_]*)/m
    |> Regex.scan(source)
    |> Enum.map(fn [_, name] -> name end)
    |> Enum.uniq()
  end

  defp extract_yara_tags(source) do
    ~r/\brule\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*([^{\r\n]+)\{/m
    |> Regex.scan(source)
    |> Enum.flat_map(fn [_, tags] -> String.split(tags, ~r/\s+/, trim: true) end)
    |> Enum.uniq()
  end

  defp extract_mitre_techniques(source) do
    ~r/\bT\d{4}(?:\.\d{3})?\b/
    |> Regex.scan(source)
    |> Enum.map(&List.first/1)
    |> Enum.uniq()
  end

  defp extract_first_meta(source, key) do
    pattern = Regex.compile!("\\b#{Regex.escape(key)}\\s*=\\s*\"([^\"]+)\"", "m")

    case Regex.run(pattern, source) do
      [_, value] -> value
      _ -> nil
    end
  end

  defp extract_highest_severity(source) do
    order = %{"informational" => 0, "low" => 1, "medium" => 2, "high" => 3, "critical" => 4}

    severities =
      ~r/\bseverity\s*=\s*"([^"]+)"/m
      |> Regex.scan(source)
      |> Enum.map(fn [_, severity] -> String.downcase(severity) end)
      |> Enum.filter(&Map.has_key?(order, &1))

    Enum.max_by(severities, &Map.fetch!(order, &1), fn -> "medium" end)
  end

  defp iso8601_or_nil(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp iso8601_or_nil(%NaiveDateTime{} = value), do: NaiveDateTime.to_iso8601(value)
  defp iso8601_or_nil(value) when is_binary(value), do: value
  defp iso8601_or_nil(_), do: nil

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  @doc """
  GET /api/v1/rules/yara/status
  Returns YARA scanner status including availability and cache stats.
  """
  def status(conn, _params) do
    available = YaraScanner.available?()
    rule_files = YaraScanner.get_rule_files()
    cache_stats = YaraScanner.cache_stats()
    total_rule_definitions =
      rule_files
      |> Enum.map(fn path ->
        case File.read(path) do
          {:ok, source} -> length(extract_yara_rule_names(source))
          {:error, _} -> 0
        end
      end)
      |> Enum.sum()

    payload = %{
      loaded_rules: length(rule_files),
      loaded_files: length(rule_files),
      total_rules: total_rule_definitions,
      last_compiled: nil,
      scan_count: cache_stats[:entries] || cache_stats["entries"] || 0,
      available: available,
      yara_executable: YaraScanner.yara_executable(),
      rule_files: Enum.map(rule_files, &Path.basename/1),
      rule_count: length(rule_files),
      cache: cache_stats
    }

    json(conn, Map.put(payload, :data, payload))
  end

  @doc """
  POST /api/v1/rules/yara/scan
  Scan a file or binary content with YARA rules.

  Params:
  - file_path: Path to a file on the server (for local files)
  - content: Base64-encoded binary content to scan
  - hash: Optional SHA256 hash for caching
  """
  def scan(conn, params) do
    unless YaraScanner.available?() do
      conn
      |> put_status(:service_unavailable)
      |> json(%{error: "YARA scanner not available. Ensure yara CLI is installed."})
    else
      result = cond do
        # Scan base64-encoded content
        params["content"] ->
          with {:ok, content} <- decode_scan_content(params["content"]),
               do: YaraScanner.scan_bytes(content, hash: params["hash"])

        # Scan a file path
        params["file_path"] ->
          YaraScanner.scan_file(params["file_path"])

        true ->
          {:error, :missing_params}
      end

      case result do
        {:ok, matches} ->
          json(conn, %{
            data: %{
              matches: Enum.map(matches, &serialize_match/1),
              match_count: length(matches),
              detections: YaraScanner.matches_to_detections(matches)
            }
          })

        {:error, :missing_params} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Either 'file_path' or 'content' (base64) is required"})

        {:error, :invalid_content} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Invalid YARA scan content"})

        {:error, :file_not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "File not found"})

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{error: "Scan failed: #{inspect(reason)}"})
      end
    end
  end

  @doc """
  POST /api/v1/rules/yara/clear_cache
  Clear the YARA scan results cache.
  """
  def clear_cache(conn, _params) do
    YaraScanner.clear_cache()
    json(conn, %{data: %{message: "Cache cleared successfully"}})
  end

  defp serialize_match(match) do
    %{
      rule: match[:rule],
      file: match[:file],
      rule_file: match[:rule_file],
      tags: match[:tags] || [],
      meta: match[:meta] || %{},
      matched_strings: length(match[:strings] || [])
    }
  end

  defp request_metadata(conn) do
    [
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    ]
  end

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] -> forwarded |> String.split(",") |> List.first() |> String.trim()
      [] -> conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end

  defp normalize_rule_params(%{"yara_rule" => attrs}) when is_map(attrs), do: normalize_rule_params(attrs)

  defp normalize_rule_params(params) when is_map(params) do
    params
    |> maybe_put_source_from_content()
  end

  defp maybe_put_source_from_content(%{"source" => _} = params), do: params
  defp maybe_put_source_from_content(%{"content" => content} = params), do: Map.put(params, "source", content)
  defp maybe_put_source_from_content(params), do: params

  defp decode_scan_content(content) when is_binary(content) do
    case Base.decode64(content) do
      {:ok, decoded} -> {:ok, decoded}
      :error ->
        if String.contains?(content, "rule ") do
          {:ok, content}
        else
          {:error, :invalid_content}
        end
    end
  end

  # --- Auto-Generated YARA Rule Endpoints ---

  @doc """
  GET /api/v1/rules/yara/generated
  List auto-generated YARA rules with optional filters.

  Query params:
  - status: Filter by lifecycle status (staged, reviewed, active, expired, rejected)
  - family: Filter by malware family
  - limit: Maximum results (default: 100)
  """
  def list_generated(conn, params) do
    opts = [
      status: params["status"],
      family: params["family"],
      limit: parse_limit(params["limit"])
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    rules = YaraGenerator.list_staged_rules(opts)
    json(conn, %{data: Enum.map(rules, &serialize_generated/1)})
  end

  @doc """
  GET /api/v1/rules/yara/generated/:id
  Show a single auto-generated YARA rule.
  """
  def show_generated(conn, %{"id" => id}) do
    case TamanduaServer.Repo.get(TamanduaServer.Detection.GeneratedYaraRule, id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Generated rule not found"})

      rule ->
        json(conn, %{data: serialize_generated(rule)})
    end
  end

  @doc """
  POST /api/v1/rules/yara/generated/:id/promote
  Promote a staged or reviewed rule to active status.
  """
  def promote_generated(conn, %{"id" => id}) do
    user = conn.assigns[:current_user]
    reviewer_id = if user, do: user.id, else: nil

    case YaraGenerator.promote_rule(id, reviewer_id) do
      {:ok, rule} ->
        if user do
          AuditLog.log_rule_change(user, "yara_generated", "promoted", id, %{
            rule_name: rule.name,
            malware_family: rule.malware_family
          }, request_metadata(conn))
        end

        json(conn, %{data: serialize_generated(rule)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Generated rule not found"})

      {:error, {:invalid_status, status}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Cannot promote rule with status '#{status}'"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to promote rule: #{inspect(reason)}"})
    end
  end

  @doc """
  POST /api/v1/rules/yara/generated/:id/reject
  Reject a staged or reviewed rule. Its source hash will not trigger regeneration.
  """
  def reject_generated(conn, %{"id" => id}) do
    user = conn.assigns[:current_user]
    reviewer_id = if user, do: user.id, else: nil

    case YaraGenerator.reject_rule(id, reviewer_id) do
      {:ok, rule} ->
        if user do
          AuditLog.log_rule_change(user, "yara_generated", "rejected", id, %{
            rule_name: rule.name,
            malware_family: rule.malware_family
          }, request_metadata(conn))
        end

        json(conn, %{data: serialize_generated(rule)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Generated rule not found"})

      {:error, :cannot_reject_active} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Cannot reject an active rule"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to reject rule: #{inspect(reason)}"})
    end
  end

  @doc """
  POST /api/v1/rules/yara/generated/cleanup
  Manually trigger cleanup of expired staged rules.
  """
  def cleanup_generated(conn, _params) do
    case YaraGenerator.cleanup_expired() do
      {:ok, count} ->
        json(conn, %{data: %{expired_count: count, message: "Cleanup completed"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Cleanup failed: #{inspect(reason)}"})
    end
  end

  @doc """
  GET /api/v1/rules/yara/generated/stats
  Get auto-generation statistics.
  """
  def generated_stats(conn, _params) do
    stats = YaraGenerator.stats()
    json(conn, %{data: stats})
  end

  defp serialize_generated(rule) do
    %{
      id: rule.id,
      name: rule.name,
      rule_content: rule.rule_content,
      source_hash: rule.source_hash,
      malware_family: rule.malware_family,
      ml_confidence: rule.ml_confidence,
      status: rule.status,
      expires_at: rule.expires_at && DateTime.to_iso8601(rule.expires_at),
      reviewed_at: rule.reviewed_at && DateTime.to_iso8601(rule.reviewed_at),
      reviewed_by_id: rule.reviewed_by_id,
      metadata: rule.metadata,
      created_at: DateTime.to_iso8601(rule.inserted_at),
      updated_at: DateTime.to_iso8601(rule.updated_at)
    }
  end

  defp parse_limit(nil), do: 100
  defp parse_limit(str) when is_binary(str) do
    case Integer.parse(str) do
      {n, _} when n > 0 and n <= 500 -> n
      _ -> 100
    end
  end
  defp parse_limit(_), do: 100

  # Clamps client-supplied limit/offset on /yara-rules. Distinct from
  # `parse_limit/1` above (which serves list_generated/2 with its own ceiling
  # of 500) so the public list endpoint gets its own conservative cap.
  defp pagination_params(params) do
    limit =
      params["limit"]
      |> parse_int(@default_per_page)
      |> max(1)
      |> min(@max_per_page)

    offset = params["offset"] |> parse_int(0) |> max(0)
    {limit, offset}
  end

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default
end
