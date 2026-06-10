defmodule TamanduaServer.AISecurity.KnownGood do
  @moduledoc """
  Context for managing known-good model hashes.

  Provides functions to add, remove, and query verified model file hashes.
  When a model's SHA-256 hash matches an entry in this database, the scanner
  can skip expensive deep analysis and return "verified" status immediately.

  ## Features

    * Fast hash lookup (indexed PostgreSQL query < 10ms)
    * Multi-tenant support via organization_id
    * Bulk import/export for administrator workflows
    * Statistics for monitoring and dashboards

  ## Example Usage

      # Check if a model hash is known-good
      case KnownGood.is_known_good?("abc123...") do
        {:ok, entry} -> # Skip deep scan, return verified
        {:error, :not_found} -> # Proceed with full scan
      end

      # Add a new trusted hash
      {:ok, entry} = KnownGood.add_hash(%{
        sha256: "abc123...",
        source: "custom",
        name: "llama-7b-v2",
        model_type: "gguf"
      })

      # Bulk import from JSON/CSV
      {:ok, result} = KnownGood.import_hashes([
        %{"sha256" => "...", "name" => "model1"},
        %{"sha256" => "...", "name" => "model2"}
      ])
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.AISecurity.KnownGood.HashEntry

  @max_import_size 1000
  @sha256_regex ~r/^[a-fA-F0-9]{64}$/

  # ===========================================================================
  # Lookup Functions
  # ===========================================================================

  @doc """
  Check if a SHA-256 hash is in the known-good database.

  Returns `{:ok, %HashEntry{}}` if the hash is found, or `{:error, :not_found}`
  if not. This is the primary function for fast-path scanning.

  ## Options

    * `:organization_id` - Filter by organization (also includes global entries with nil org_id)

  ## Examples

      iex> is_known_good?("abc123..." |> String.duplicate(2))
      {:ok, %HashEntry{sha256: "abc123..."}}

      iex> is_known_good?("unknown_hash")
      {:error, :not_found}
  """
  @spec is_known_good?(String.t(), keyword()) :: {:ok, HashEntry.t()} | {:error, :not_found}
  def is_known_good?(sha256, opts \\ []) do
    sha256 = String.downcase(sha256)
    org_id = Keyword.get(opts, :organization_id)

    query =
      from h in HashEntry,
        where: h.sha256 == ^sha256,
        where: is_nil(h.organization_id) or h.organization_id == ^org_id,
        limit: 1

    case Repo.one(query) do
      nil -> {:error, :not_found}
      entry -> {:ok, entry}
    end
  end

  @doc """
  Get a single hash entry by SHA-256.

  Unlike `is_known_good?/2`, this does not check organization scope.
  Returns `nil` if not found.

  ## Options

    * `:organization_id` - Filter by organization

  ## Examples

      iex> get_hash("abc123...")
      %HashEntry{}

      iex> get_hash("unknown")
      nil
  """
  @spec get_hash(String.t(), keyword()) :: HashEntry.t() | nil
  def get_hash(sha256, opts \\ []) do
    sha256 = String.downcase(sha256)
    org_id = Keyword.get(opts, :organization_id)

    query =
      from h in HashEntry,
        where: h.sha256 == ^sha256

    query =
      if org_id do
        from h in query, where: h.organization_id == ^org_id
      else
        query
      end

    Repo.one(query)
  end

  # ===========================================================================
  # CRUD Functions
  # ===========================================================================

  @doc """
  Add a new known-good hash entry.

  Handles duplicate hashes gracefully using `on_conflict: :nothing`.
  When a duplicate is detected, returns the existing entry.

  ## Required Attributes

    * `:sha256` - The SHA-256 hash (64 hex characters)
    * `:source` - One of "custom", "import", "verified_scan"

  ## Optional Attributes

    * `:name` - Human-readable name
    * `:model_type` - "pickle", "gguf", "safetensors", or "onnx"
    * `:notes` - Administrator notes
    * `:created_by` - User ID who added the entry
    * `:organization_id` - Tenant ID

  ## Examples

      iex> add_hash(%{sha256: "abc...", source: "custom", name: "my-model"})
      {:ok, %HashEntry{}}

      iex> add_hash(%{sha256: "invalid", source: "custom"})
      {:error, %Ecto.Changeset{}}
  """
  @spec add_hash(map()) :: {:ok, HashEntry.t()} | {:error, Ecto.Changeset.t()}
  def add_hash(attrs) do
    changeset = HashEntry.changeset(%HashEntry{}, attrs)

    case Repo.insert(changeset, on_conflict: :nothing, returning: true) do
      {:ok, %HashEntry{id: nil} = _entry} ->
        # on_conflict: :nothing returns struct with nil id when skipped
        # Fetch the existing entry
        sha256 = String.downcase(attrs[:sha256] || attrs["sha256"] || "")
        org_id = attrs[:organization_id] || attrs["organization_id"]

        case get_existing_entry(sha256, org_id) do
          nil -> {:error, Ecto.Changeset.add_error(changeset, :sha256, "already exists")}
          entry -> {:ok, entry}
        end

      {:ok, entry} ->
        {:ok, entry}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  defp get_existing_entry(sha256, org_id) do
    query =
      from h in HashEntry,
        where: h.sha256 == ^sha256

    query =
      if org_id do
        from h in query, where: h.organization_id == ^org_id
      else
        from h in query, where: is_nil(h.organization_id)
      end

    Repo.one(query)
  end

  @doc """
  Remove a known-good hash entry.

  Returns `{:ok, %HashEntry{}}` if the entry was deleted, or
  `{:error, :not_found}` if no matching entry exists.

  ## Options

    * `:organization_id` - Required to match the entry's organization

  ## Examples

      iex> remove_hash("abc123...")
      {:ok, %HashEntry{}}

      iex> remove_hash("nonexistent")
      {:error, :not_found}
  """
  @spec remove_hash(String.t(), keyword()) :: {:ok, HashEntry.t()} | {:error, :not_found}
  def remove_hash(sha256, opts \\ []) do
    sha256 = String.downcase(sha256)
    org_id = Keyword.get(opts, :organization_id)

    query =
      from h in HashEntry,
        where: h.sha256 == ^sha256

    query =
      if org_id do
        from h in query, where: h.organization_id == ^org_id
      else
        from h in query, where: is_nil(h.organization_id)
      end

    case Repo.one(query) do
      nil ->
        {:error, :not_found}

      entry ->
        Repo.delete(entry)
    end
  end

  # ===========================================================================
  # List and Stats Functions
  # ===========================================================================

  @doc """
  List known-good hash entries with pagination and filtering.

  ## Options

    * `:limit` - Maximum entries to return (default: 50)
    * `:offset` - Number of entries to skip (default: 0)
    * `:source` - Filter by source type
    * `:model_type` - Filter by model type
    * `:organization_id` - Filter by organization

  ## Examples

      iex> list_hashes()
      [%HashEntry{}, ...]

      iex> list_hashes(source: "custom", limit: 10)
      [%HashEntry{}, ...]
  """
  @spec list_hashes(keyword()) :: [HashEntry.t()]
  def list_hashes(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)
    source = Keyword.get(opts, :source)
    model_type = Keyword.get(opts, :model_type)
    org_id = Keyword.get(opts, :organization_id)

    HashEntry
    |> maybe_filter_source(source)
    |> maybe_filter_model_type(model_type)
    |> maybe_filter_organization(org_id)
    |> order_by([h], desc: h.inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Count total entries matching filters.

  ## Options

    * `:source` - Filter by source type
    * `:model_type` - Filter by model type
    * `:organization_id` - Filter by organization

  ## Examples

      iex> count_hashes()
      42

      iex> count_hashes(source: "import")
      15
  """
  @spec count_hashes(keyword()) :: non_neg_integer()
  def count_hashes(opts \\ []) do
    source = Keyword.get(opts, :source)
    model_type = Keyword.get(opts, :model_type)
    org_id = Keyword.get(opts, :organization_id)

    HashEntry
    |> maybe_filter_source(source)
    |> maybe_filter_model_type(model_type)
    |> maybe_filter_organization(org_id)
    |> Repo.aggregate(:count)
  end

  @doc """
  Get aggregate statistics for known-good hashes.

  Returns a map with total counts, breakdowns by source and model type.

  ## Options

    * `:organization_id` - Filter by organization

  ## Examples

      iex> stats()
      %{
        total_count: 100,
        by_source: %{"custom" => 50, "import" => 45, "verified_scan" => 5},
        by_model_type: %{"gguf" => 40, "safetensors" => 35, "pickle" => 15, "onnx" => 10}
      }
  """
  @spec stats(keyword()) :: map()
  def stats(opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)

    base_query =
      HashEntry
      |> maybe_filter_organization(org_id)

    total_count = Repo.aggregate(base_query, :count)

    by_source =
      base_query
      |> group_by([h], h.source)
      |> select([h], {h.source, count(h.id)})
      |> Repo.all()
      |> Enum.into(%{})

    by_model_type =
      base_query
      |> where([h], not is_nil(h.model_type))
      |> group_by([h], h.model_type)
      |> select([h], {h.model_type, count(h.id)})
      |> Repo.all()
      |> Enum.into(%{})

    %{
      total_count: total_count,
      by_source: by_source,
      by_model_type: by_model_type
    }
  end

  # ===========================================================================
  # Bulk Import/Export Functions
  # ===========================================================================

  @doc """
  Bulk import hash entries.

  Efficiently imports up to #{@max_import_size} entries in a single operation.
  Uses `INSERT ... ON CONFLICT DO NOTHING` for duplicate handling.

  ## Parameters

    * `entries` - List of maps with at least `:sha256` key
    * `opts` - Options including `:created_by` and `:organization_id`

  ## Returns

    * `{:ok, %{imported: N, skipped: N, invalid: N, errors: [...]}}` on success
    * `{:error, message}` if entry count exceeds limit

  ## Examples

      iex> import_hashes([%{"sha256" => "abc...", "name" => "model1"}])
      {:ok, %{imported: 1, skipped: 0, invalid: 0, errors: []}}

      iex> import_hashes([%{"sha256" => "invalid"}])
      {:ok, %{imported: 0, skipped: 0, invalid: 1, errors: ["Invalid SHA-256: invalid"]}}
  """
  @spec import_hashes([map()], keyword()) :: {:ok, map()} | {:error, String.t()}
  def import_hashes(entries, opts \\ []) when is_list(entries) do
    if length(entries) > @max_import_size do
      {:error, "Maximum #{@max_import_size} entries per import"}
    else
      created_by = Keyword.get(opts, :created_by)
      organization_id = Keyword.get(opts, :organization_id)
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      {valid, invalid} = Enum.split_with(entries, &valid_sha256?(&1["sha256"] || &1[:sha256]))

      rows =
        Enum.map(valid, fn entry ->
          sha256 = entry["sha256"] || entry[:sha256]

          %{
            id: Ecto.UUID.generate(),
            sha256: String.downcase(sha256),
            name: entry["name"] || entry[:name],
            source: "import",
            model_type: normalize_model_type(entry["model_type"] || entry[:model_type]),
            notes: entry["notes"] || entry[:notes],
            created_by: created_by,
            organization_id: organization_id,
            inserted_at: now,
            updated_at: now
          }
        end)

      {imported, _} = Repo.insert_all(HashEntry, rows, on_conflict: :nothing)

      {:ok,
       %{
         imported: imported,
         skipped: length(valid) - imported,
         invalid: length(invalid),
         errors: Enum.map(invalid, &"Invalid SHA-256: #{&1["sha256"] || &1[:sha256]}")
       }}
    end
  end

  @doc """
  Export hash entries to a list of maps suitable for JSON serialization.

  ## Options

    * `:organization_id` - Filter by organization
    * `:model_type` - Filter by model type
    * `:source` - Filter by source

  ## Examples

      iex> export_hashes()
      [%{sha256: "abc...", name: "model1", ...}, ...]
  """
  @spec export_hashes(keyword()) :: [map()]
  def export_hashes(opts \\ []) do
    list_hashes(opts ++ [limit: 10_000])
    |> Enum.map(fn entry ->
      %{
        sha256: entry.sha256,
        name: entry.name,
        model_type: entry.model_type,
        source: entry.source,
        notes: entry.notes
      }
    end)
  end

  @doc """
  Parse a CSV string into a list of hash entry maps.

  Expected CSV format:
  ```
  sha256,name,model_type,notes
  abc123...,model-name,gguf,Optional notes
  ```

  ## Examples

      iex> parse_csv("sha256,name,model_type,notes\\nabc...,test,gguf,")
      {:ok, [%{"sha256" => "abc...", "name" => "test", "model_type" => "gguf", "notes" => nil}]}
  """
  @spec parse_csv(String.t()) :: {:ok, [map()]} | {:error, String.t()}
  def parse_csv(csv_string) do
    lines = String.split(csv_string, ~r/\r?\n/, trim: true)

    case lines do
      [] ->
        {:ok, []}

      [_header | rows] ->
        entries =
          rows
          |> Enum.map(&parse_csv_row/1)
          |> Enum.reject(&is_nil/1)

        {:ok, entries}
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp valid_sha256?(nil), do: false

  defp valid_sha256?(sha256) when is_binary(sha256) do
    Regex.match?(@sha256_regex, sha256)
  end

  defp valid_sha256?(_), do: false

  defp normalize_model_type(nil), do: nil
  defp normalize_model_type(""), do: nil
  defp normalize_model_type(type) when type in ["pickle", "gguf", "safetensors", "onnx"], do: type
  defp normalize_model_type(_), do: nil

  defp parse_csv_row(row) do
    case String.split(row, ",", parts: 4) do
      [sha256 | rest] ->
        %{
          "sha256" => String.trim(sha256),
          "name" => Enum.at(rest, 0, "") |> String.trim(),
          "model_type" => Enum.at(rest, 1, "") |> String.trim() |> nilify_empty(),
          "notes" => Enum.at(rest, 2, "") |> String.trim() |> nilify_empty()
        }

      _ ->
        nil
    end
  end

  defp nilify_empty(""), do: nil
  defp nilify_empty(s), do: s

  defp maybe_filter_source(query, nil), do: query

  defp maybe_filter_source(query, source) do
    from h in query, where: h.source == ^source
  end

  defp maybe_filter_model_type(query, nil), do: query

  defp maybe_filter_model_type(query, model_type) do
    from h in query, where: h.model_type == ^model_type
  end

  defp maybe_filter_organization(query, nil), do: query

  defp maybe_filter_organization(query, org_id) do
    from h in query, where: h.organization_id == ^org_id or is_nil(h.organization_id)
  end
end
