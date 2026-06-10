defmodule TamanduaServer.Detection.IOCs do
  @moduledoc """
  Context module for Indicators of Compromise (IOCs) management.

  Provides functions for managing IOCs including:
  - CRUD operations (create, read, update, delete)
  - Lookup by type and value
  - Search and filtering
  - Bulk import/export
  - Statistics and counting

  IOC Types:
  - ip: IP addresses (IPv4/IPv6)
  - domain: Domain names
  - hash_md5, hash_sha1, hash_sha256: File hashes
  - url: Full URLs
  - email: Email addresses
  - filename: File names or paths

  Metadata:
  - source: Origin of the IOC (manual, threat feed, etc.)
  - severity: low, medium, high, critical
  - tags: Array of classification tags
  - enabled: Whether the IOC is active for detection
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.IOC

  @valid_types ~w(hash_md5 hash_sha256 hash_sha1 ip domain url email filename)

  # ============================================================================
  # Lookup Functions
  # ============================================================================

  @doc """
  Lookup an IOC by type and value.

  Returns `{:ok, ioc}` if found, `{:error, :not_found}` otherwise.

  ## Examples

      iex> lookup("ip", "192.168.1.1")
      {:ok, %IOC{type: "ip", value: "192.168.1.1", ...}}

      iex> lookup("domain", "unknown.com")
      {:error, :not_found}
  """
  @spec lookup(String.t(), String.t()) :: {:ok, IOC.t()} | {:error, :not_found}
  def lookup(indicator_type, indicator_value) when is_binary(indicator_type) and is_binary(indicator_value) do
    normalized_value = normalize_value(indicator_type, indicator_value)

    query =
      from(i in IOC,
        where: i.type == ^indicator_type and i.value == ^normalized_value and i.enabled == true,
        limit: 1
      )

    case Repo.one(query) do
      nil -> {:error, :not_found}
      ioc -> {:ok, ioc}
    end
  end

  def lookup(indicator_type, indicator_value) do
    lookup(to_string(indicator_type), to_string(indicator_value))
  end

  @doc """
  Lookup an IOC by type and value, returning the IOC or nil.
  """
  @spec lookup!(String.t(), String.t()) :: IOC.t() | nil
  def lookup!(indicator_type, indicator_value) do
    case lookup(indicator_type, indicator_value) do
      {:ok, ioc} -> ioc
      {:error, :not_found} -> nil
    end
  end

  # ============================================================================
  # Count Functions
  # ============================================================================

  @doc """
  Returns the total count of IOCs in the database.

  ## Options
    - `:enabled` - Count only enabled (true) or disabled (false) IOCs
    - `:type` - Count only IOCs of a specific type

  ## Examples

      iex> count()
      42

      iex> count(enabled: true)
      35

      iex> count(type: "ip")
      10
  """
  @spec count(keyword()) :: non_neg_integer()
  def count(opts \\ []) do
    base_query = from(i in IOC, select: count(i.id))

    base_query
    |> apply_count_filters(opts)
    |> Repo.one()
  end

  defp apply_count_filters(query, []), do: query

  defp apply_count_filters(query, [{:enabled, enabled} | rest]) when is_boolean(enabled) do
    query
    |> where([i], i.enabled == ^enabled)
    |> apply_count_filters(rest)
  end

  defp apply_count_filters(query, [{:type, type} | rest]) when is_binary(type) do
    query
    |> where([i], i.type == ^type)
    |> apply_count_filters(rest)
  end

  defp apply_count_filters(query, [_ | rest]), do: apply_count_filters(query, rest)

  @doc """
  Returns counts grouped by IOC type.

  ## Examples

      iex> count_by_type()
      %{"ip" => 10, "domain" => 15, "hash_sha256" => 17}
  """
  @spec count_by_type() :: map()
  def count_by_type do
    from(i in IOC,
      where: i.enabled == true,
      group_by: i.type,
      select: {i.type, count(i.id)}
    )
    |> Repo.all()
    |> Map.new()
  end

  @doc """
  Returns counts grouped by IOC source.

  ## Examples

      iex> count_by_source()
      %{"urlhaus_urls" => 1000, "feodo_ip_blocklist" => 500, "manual" => 10}
  """
  @spec count_by_source() :: map()
  def count_by_source do
    from(i in IOC,
      where: i.enabled == true and not is_nil(i.source),
      group_by: i.source,
      select: {i.source, count(i.id)}
    )
    |> Repo.all()
    |> Map.new()
  end

  @doc """
  List the most recently added IOCs.

  ## Examples

      iex> list_recent(10)
      [%IOC{}, ...]
  """
  @spec list_recent(non_neg_integer()) :: [IOC.t()]
  def list_recent(limit \\ 10) do
    from(i in IOC,
      where: i.enabled == true,
      order_by: [desc: i.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  # ============================================================================
  # List Functions
  # ============================================================================

  @doc """
  List IOCs with optional filtering and pagination.

  ## Options
    - `:type` - Filter by IOC type
    - `:enabled` - Filter by enabled status (boolean)
    - `:source` - Filter by source
    - `:severity` - Filter by severity level
    - `:tags` - Filter by tags (must contain all specified tags)
    - `:limit` - Maximum number of results (default: 100)
    - `:offset` - Number of results to skip (default: 0)
    - `:order_by` - Field to sort by (default: :inserted_at)
    - `:order_dir` - Sort direction :asc or :desc (default: :desc)

  ## Examples

      iex> list()
      [%IOC{}, ...]

      iex> list(type: "ip", enabled: true, limit: 10)
      [%IOC{type: "ip", enabled: true}, ...]
  """
  @spec list(keyword()) :: [IOC.t()]
  def list(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    order_by = Keyword.get(opts, :order_by, :inserted_at)
    order_dir = Keyword.get(opts, :order_dir, :desc)

    base_query =
      from(i in IOC,
        limit: ^limit,
        offset: ^offset,
        order_by: [{^order_dir, ^order_by}]
      )

    base_query
    |> apply_list_filters(opts)
    |> Repo.all()
  end

  defp apply_list_filters(query, []), do: query

  defp apply_list_filters(query, [{:type, type} | rest]) when is_binary(type) do
    query
    |> where([i], i.type == ^type)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:enabled, enabled} | rest]) when is_boolean(enabled) do
    query
    |> where([i], i.enabled == ^enabled)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:source, source} | rest]) when is_binary(source) do
    query
    |> where([i], i.source == ^source)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:severity, severity} | rest]) when is_binary(severity) do
    query
    |> where([i], i.severity == ^severity)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:tags, tags} | rest]) when is_list(tags) do
    query
    |> where([i], fragment("? @> ?", i.tags, ^tags))
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [_ | rest]), do: apply_list_filters(query, rest)

  @doc """
  List all IOCs with optional filters (legacy function, kept for compatibility).
  """
  def list_iocs(filters \\ %{}) do
    opts =
      filters
      |> Enum.map(fn
        {:enabled, val} -> {:enabled, parse_boolean(val)}
        {k, v} -> {k, v}
      end)
      |> Keyword.new()

    list(opts)
  end

  # ============================================================================
  # CRUD Functions
  # ============================================================================

  @doc """
  Get a single IOC by ID.
  """
  def get_ioc!(id), do: Repo.get!(IOC, id)

  @doc """
  Get a single IOC by ID, returning nil if not found.
  """
  def get_ioc(id), do: Repo.get(IOC, id)

  @doc """
  Add a new IOC.

  ## Examples

      iex> add(%{type: "ip", value: "192.168.1.1", source: "manual"})
      {:ok, %IOC{}}

      iex> add(%{type: "invalid", value: "test"})
      {:error, %Ecto.Changeset{}}
  """
  @spec add(map()) :: {:ok, IOC.t()} | {:error, Ecto.Changeset.t()}
  def add(ioc_data) when is_map(ioc_data) do
    attrs = normalize_attrs(ioc_data)

    %IOC{}
    |> IOC.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Create a new IOC (alias for add/1).
  """
  def create_ioc(attrs), do: add(attrs)

  @doc """
  Update an IOC.
  """
  def update_ioc(%IOC{} = ioc, attrs) do
    ioc
    |> IOC.changeset(normalize_attrs(attrs))
    |> Repo.update()
  end

  @doc """
  Remove an IOC by ID.

  ## Examples

      iex> remove("550e8400-e29b-41d4-a716-446655440000")
      {:ok, %IOC{}}

      iex> remove("nonexistent-id")
      {:error, :not_found}
  """
  @spec remove(String.t()) :: {:ok, IOC.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def remove(ioc_id) when is_binary(ioc_id) do
    case get_ioc(ioc_id) do
      nil -> {:error, :not_found}
      ioc -> Repo.delete(ioc)
    end
  end

  @doc """
  Delete an IOC struct.
  """
  def delete_ioc(%IOC{} = ioc) do
    Repo.delete(ioc)
  end

  # ============================================================================
  # Bulk Operations
  # ============================================================================

  @doc """
  Bulk add multiple IOCs.

  Returns a tuple with counts of successful and failed inserts.
  Failed inserts are returned with their changeset errors.

  ## Options
    - `:on_conflict` - What to do on conflict (:nothing, :replace_all, default: :nothing)
    - `:conflict_target` - Fields to check for conflicts (default: [:type, :value])

  ## Examples

      iex> bulk_add([
      ...>   %{type: "ip", value: "1.1.1.1"},
      ...>   %{type: "ip", value: "2.2.2.2"}
      ...> ])
      {:ok, %{successful: 2, failed: 0, errors: []}}

      iex> bulk_add([%{type: "invalid", value: "test"}])
      {:ok, %{successful: 0, failed: 1, errors: [...]}}
  """
  @spec bulk_add([map()], keyword()) :: {:ok, map()}
  def bulk_add(iocs, opts \\ []) when is_list(iocs) do
    raw_on_conflict = Keyword.get(opts, :on_conflict, :nothing)
    conflict_target = Keyword.get(opts, :conflict_target, [:type, :value])

    # Ecto doesn't accept :update as on_conflict value; translate it to
    # {:replace, updatable_fields} which replaces the listed columns on conflict.
    on_conflict =
      case raw_on_conflict do
        :update ->
          {:replace, [
            :description, :severity, :confidence, :tags, :metadata,
            :source, :source_ref, :first_seen, :last_seen, :expires_at,
            :malware_family, :threat_actor, :campaign,
            :mitre_tactics, :mitre_techniques, :enabled, :updated_at
          ]}
        :replace_all -> :replace_all
        other -> other
      end

    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    {valid, invalid} =
      iocs
      |> Enum.map(&normalize_attrs/1)
      |> Enum.split_with(&valid_ioc_attrs?/1)

    # Prepare entries for insert_all
    entries =
      valid
      |> Enum.map(fn attrs ->
        attrs
        |> Map.put(:id, Ecto.UUID.generate())
        |> Map.put(:inserted_at, now)
        |> Map.put(:updated_at, now)
        |> Map.put_new(:enabled, true)
        |> Map.put_new(:severity, "medium")
        |> Map.put_new(:tags, [])
        |> Map.put_new(:metadata, %{})
        |> maybe_coerce_confidence()
        |> normalize_map_for_insert()
        |> Map.take(ioc_schema_fields())
      end)

    # Deduplicate within the batch to avoid "ON CONFLICT DO UPDATE cannot
    # affect row a second time" errors.  Keep the last occurrence per key.
    entries =
      entries
      |> Enum.reverse()
      |> Enum.uniq_by(fn e -> {Map.get(e, :type), Map.get(e, :value)} end)
      |> Enum.reverse()

    # PostgreSQL protocol supports max 65 535 parameters per query.
    # Each IOC row has ~20 columns, so cap batches at 2 000 rows.
    batch_size = 2_000

    {inserted_count, _} =
      if length(entries) > 0 do
        entries
        |> Enum.chunk_every(batch_size)
        |> Enum.reduce({0, nil}, fn chunk, {acc, _} ->
          {n, result} =
            Repo.insert_all(IOC, chunk,
              on_conflict: on_conflict,
              conflict_target: conflict_target
            )
          {acc + n, result}
        end)
      else
        {0, nil}
      end

    errors =
      invalid
      |> Enum.map(fn attrs ->
        changeset = IOC.changeset(%IOC{}, attrs)
        %{attrs: attrs, errors: changeset.errors}
      end)

    {:ok, %{
      successful: inserted_count,
      failed: length(invalid),
      errors: errors
    }}
  end

  defp valid_ioc_attrs?(attrs) do
    type = Map.get(attrs, :type) || Map.get(attrs, "type")
    value = Map.get(attrs, :value) || Map.get(attrs, "value")

    type in @valid_types && is_binary(value) && String.length(value) > 0
  end

  defp normalize_map_for_insert(attrs) do
    attrs
    |> Enum.map(fn
      {k, v} when is_atom(k) -> {k, v}
      {k, v} when is_binary(k) -> {String.to_existing_atom(k), v}
    end)
    |> Map.new()
  end

  # Coerce confidence to a float value in 0.0..1.0 range.
  # The Aggregator and STIX converter pass floats (0.0-1.0),
  # while some legacy code may pass integers (0-100).
  defp maybe_coerce_confidence(attrs) do
    case Map.get(attrs, :confidence) || Map.get(attrs, "confidence") do
      nil -> attrs
      c when is_integer(c) and c > 1 -> Map.put(attrs, :confidence, c / 100.0)
      c when is_integer(c) -> Map.put(attrs, :confidence, c / 1.0)
      c when is_float(c) and c > 1.0 -> Map.put(attrs, :confidence, min(c / 100.0, 1.0))
      c when is_float(c) -> Map.put(attrs, :confidence, c)
      _ -> Map.delete(attrs, :confidence)
    end
  end

  # Returns the list of atom keys that correspond to IOC schema fields,
  # ensuring insert_all never receives unknown columns.
  defp ioc_schema_fields do
    [
      :id, :type, :value, :description, :enabled, :source, :source_ref,
      :severity, :confidence, :tags, :metadata,
      :first_seen, :last_seen, :expires_at,
      :malware_family, :threat_actor, :campaign,
      :mitre_tactics, :mitre_techniques,
      :organization_id, :inserted_at, :updated_at
    ]
  end

  @doc """
  Bulk remove IOCs by IDs.

  ## Examples

      iex> bulk_remove(["id1", "id2", "id3"])
      {:ok, 3}
  """
  @spec bulk_remove([String.t()]) :: {:ok, non_neg_integer()}
  def bulk_remove(ioc_ids) when is_list(ioc_ids) do
    {count, _} =
      from(i in IOC, where: i.id in ^ioc_ids)
      |> Repo.delete_all()

    {:ok, count}
  end

  # ============================================================================
  # Search Functions
  # ============================================================================

  @doc """
  Search IOCs by query string.

  Searches across value, description, source, and tags fields.

  ## Options
    - `:type` - Filter by IOC type
    - `:enabled` - Filter by enabled status
    - `:limit` - Maximum results (default: 50)

  ## Examples

      iex> search("malware")
      [%IOC{description: "known malware hash", ...}, ...]

      iex> search("192.168", type: "ip")
      [%IOC{type: "ip", value: "192.168.1.1"}, ...]
  """
  @spec search(String.t(), keyword()) :: [IOC.t()]
  def search(query, opts \\ []) when is_binary(query) do
    limit = Keyword.get(opts, :limit, 50)
    search_pattern = "%#{String.replace(query, "%", "\\%")}%"

    base_query =
      from(i in IOC,
        where:
          ilike(i.value, ^search_pattern) or
          ilike(i.description, ^search_pattern) or
          ilike(i.source, ^search_pattern) or
          fragment("array_to_string(?, ',') ILIKE ?", i.tags, ^search_pattern),
        order_by: [desc: i.inserted_at],
        limit: ^limit
      )

    base_query
    |> apply_search_filters(opts)
    |> Repo.all()
  end

  defp apply_search_filters(query, []), do: query

  defp apply_search_filters(query, [{:type, type} | rest]) when is_binary(type) do
    query
    |> where([i], i.type == ^type)
    |> apply_search_filters(rest)
  end

  defp apply_search_filters(query, [{:enabled, enabled} | rest]) when is_boolean(enabled) do
    query
    |> where([i], i.enabled == ^enabled)
    |> apply_search_filters(rest)
  end

  defp apply_search_filters(query, [_ | rest]), do: apply_search_filters(query, rest)

  @doc """
  Search IOCs by value (legacy function).

  Uses ILIKE for partial matching with proper escaping to avoid full table scans
  on the unindexed value column. For exact matches, use `lookup/2` instead.
  """
  def search_by_value(value) when is_binary(value) do
    escaped = value |> String.replace("\\", "\\\\") |> String.replace("%", "\\%") |> String.replace("_", "\\_")
    pattern = "%#{escaped}%"

    from(i in IOC,
      where: ilike(i.value, ^pattern) and i.enabled == true,
      order_by: [desc: i.inserted_at],
      limit: 100
    )
    |> Repo.all()
  end

  # ============================================================================
  # Match Functions
  # ============================================================================

  @doc """
  Check if a value matches any enabled IOC.
  Returns the matching IOC or nil.
  """
  def match?(value, type) do
    normalized_value = normalize_value(type, value)

    from(i in IOC,
      where: i.value == ^normalized_value and i.type == ^type and i.enabled == true,
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  Check multiple values against IOCs and return all matches.

  ## Examples

      iex> match_batch([{"ip", "1.1.1.1"}, {"domain", "evil.com"}])
      [%IOC{type: "ip", value: "1.1.1.1"}, %IOC{type: "domain", value: "evil.com"}]
  """
  @spec match_batch([{String.t(), String.t()}]) :: [IOC.t()]
  def match_batch(indicators) when is_list(indicators) do
    # Group by type for efficient querying
    grouped =
      indicators
      |> Enum.map(fn {type, value} -> {type, normalize_value(type, value)} end)
      |> Enum.group_by(fn {type, _} -> type end, fn {_, value} -> value end)

    grouped
    |> Enum.flat_map(fn {type, values} ->
      from(i in IOC,
        where: i.type == ^type and i.value in ^values and i.enabled == true
      )
      |> Repo.all()
    end)
  end

  # ============================================================================
  # Statistics Functions
  # ============================================================================

  @doc """
  Get IOC statistics.

  Returns a map with:
  - total: Total count of IOCs
  - active: Count of enabled IOCs
  - by_type: Counts grouped by type
  - by_severity: Counts grouped by severity
  - by_source: Counts grouped by source
  """
  @spec get_stats() :: map()
  def get_stats do
    %{
      total: count(),
      active: count(enabled: true),
      by_type: count_by_type(),
      by_severity: count_by_severity(),
      by_source: count_by_source()
    }
  end

  defp count_by_severity do
    from(i in IOC,
      where: i.enabled == true,
      group_by: i.severity,
      select: {i.severity, count(i.id)}
    )
    |> Repo.all()
    |> Map.new()
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp normalize_attrs(attrs) when is_map(attrs) do
    attrs
    |> atomize_keys()
    |> then(fn a ->
      type = Map.get(a, :type, "")
      value = Map.get(a, :value, "")

      Map.put(a, :value, normalize_value(type, value))
    end)
  end

  defp atomize_keys(map) do
    map
    |> Enum.map(fn
      {k, v} when is_binary(k) ->
        key = try do
          String.to_existing_atom(k)
        rescue
          ArgumentError -> k
        end
        {key, v}
      {k, v} -> {k, v}
    end)
    |> Map.new()
  end

  defp normalize_value(type, value) when type in ["ip", :ip] do
    value
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_value(type, value) when type in ["domain", :domain] do
    normalized =
      value
      |> String.trim()
      |> String.downcase()
      |> String.trim_leading("www.")

    # Apply IDNA/punycode normalization for internationalized domain names
    try do
      case :idna.encode(String.to_charlist(normalized)) do
        encoded when is_list(encoded) -> List.to_string(encoded)
        _ -> normalized
      end
    rescue
      _ -> normalized
    catch
      _, _ -> normalized
    end
  end

  defp normalize_value(type, value) when type in ["hash_md5", "hash_sha1", "hash_sha256", :hash_md5, :hash_sha1, :hash_sha256] do
    value
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_value(type, value) when type in ["email", :email] do
    value
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_value(type, value) when type in ["url", :url] do
    value
    |> String.trim()
  end

  defp normalize_value(_type, value), do: String.trim(to_string(value))

  defp parse_boolean("true"), do: true
  defp parse_boolean("false"), do: false
  defp parse_boolean(true), do: true
  defp parse_boolean(false), do: false
  defp parse_boolean(_), do: nil
end
