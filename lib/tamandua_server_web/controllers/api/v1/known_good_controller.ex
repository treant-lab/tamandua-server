defmodule TamanduaServerWeb.API.V1.KnownGoodController do
  @moduledoc """
  REST API controller for managing known-good model hashes.

  Provides CRUD operations for the known-good hash database, enabling
  administrators to add/remove trusted model file hashes without server
  restart. When a model's SHA-256 hash matches an entry, the scanner
  can skip expensive deep analysis and return "verified" immediately.

  ## Endpoints

    * `GET /api/v1/ai-security/known-good` - List hashes with pagination
    * `GET /api/v1/ai-security/known-good/:sha256` - Check if hash is known-good
    * `POST /api/v1/ai-security/known-good` - Add a new hash
    * `DELETE /api/v1/ai-security/known-good/:sha256` - Remove a hash
    * `GET /api/v1/ai-security/known-good/stats` - Get aggregate statistics
    * `POST /api/v1/ai-security/known-good/import` - Bulk import from JSON/CSV
    * `GET /api/v1/ai-security/known-good/export` - Export hashes to JSON/CSV

  ## Multi-tenancy

  All operations respect `organization_id` from `conn.assigns` when available.
  Global entries (with `nil` organization_id) are visible to all tenants.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.KnownGood

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List known-good hashes with pagination and filtering.

  ## Query Parameters

    * `limit` - Maximum entries to return (default: 50, max: 1000)
    * `offset` - Number of entries to skip (default: 0)
    * `source` - Filter by source: "custom", "import", "verified_scan"
    * `model_type` - Filter by model type: "pickle", "gguf", "safetensors", "onnx"

  ## Response

      {
        "data": [
          {
            "sha256": "abc123...",
            "name": "llama-7b",
            "source": "custom",
            "model_type": "gguf",
            "notes": "Official release",
            "created_by": "user-123",
            "inserted_at": "2026-03-29T12:00:00Z"
          }
        ],
        "meta": {
          "total": 100,
          "limit": 50,
          "offset": 0
        }
      }
  """
  def index(conn, params) do
    opts = build_list_opts(conn, params)
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)

    entries = KnownGood.list_hashes(opts)
    total = KnownGood.count_hashes(Keyword.delete(opts, :limit) |> Keyword.delete(:offset))

    conn
    |> put_status(:ok)
    |> json(%{
      data: Enum.map(entries, &serialize_entry/1),
      meta: %{
        total: total,
        limit: limit,
        offset: offset
      }
    })
  end

  @doc """
  Check if a specific SHA-256 hash is in the known-good database.

  Returns the full entry if found, or 404 if not found.

  ## Response (200 OK)

      {
        "data": {
          "sha256": "abc123...",
          "name": "llama-7b",
          "source": "custom",
          "model_type": "gguf",
          "notes": "Official release"
        },
        "known_good": true
      }

  ## Response (404 Not Found)

      {
        "error": "not_found",
        "message": "Hash not found in known-good database"
      }
  """
  def show(conn, %{"sha256" => sha256}) do
    opts = build_org_opts(conn)

    case KnownGood.is_known_good?(sha256, opts) do
      {:ok, entry} ->
        conn
        |> put_status(:ok)
        |> json(%{
          data: serialize_entry(entry),
          known_good: true
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{
          error: "not_found",
          message: "Hash not found in known-good database"
        })
    end
  end

  @doc """
  Add a new known-good hash entry.

  ## Request Body

      {
        "sha256": "abc123...",      // Required: 64 hex characters
        "name": "llama-7b",         // Optional: human-readable name
        "source": "custom",         // Optional: defaults to "custom"
        "model_type": "gguf",       // Optional: pickle, gguf, safetensors, onnx
        "notes": "Verified clean"   // Optional: admin notes
      }

  ## Response (201 Created)

      {
        "data": { ... entry fields ... }
      }

  ## Response (422 Unprocessable Entity)

      {
        "error": "validation_failed",
        "errors": {
          "sha256": ["must be exactly 64 hexadecimal characters"]
        }
      }
  """
  def create(conn, params) do
    attrs =
      params
      |> Map.take(["sha256", "name", "source", "model_type", "notes"])
      |> Map.put_new("source", "custom")
      |> add_created_by(conn)
      |> add_organization_id(conn)

    case KnownGood.add_hash(attrs) do
      {:ok, entry} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_entry(entry)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "validation_failed",
          errors: format_changeset_errors(changeset)
        })
    end
  end

  @doc """
  Remove a known-good hash entry.

  ## Response (200 OK)

      {
        "data": { ... deleted entry fields ... },
        "deleted": true
      }

  ## Response (404 Not Found)

      {
        "error": "not_found",
        "message": "Hash not found in known-good database"
      }
  """
  def delete(conn, %{"sha256" => sha256}) do
    opts = build_org_opts(conn)

    case KnownGood.remove_hash(sha256, opts) do
      {:ok, entry} ->
        conn
        |> put_status(:ok)
        |> json(%{
          data: serialize_entry(entry),
          deleted: true
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{
          error: "not_found",
          message: "Hash not found in known-good database"
        })
    end
  end

  @doc """
  Get aggregate statistics for known-good hashes.

  ## Response

      {
        "data": {
          "total_count": 100,
          "by_source": {
            "custom": 50,
            "import": 45,
            "verified_scan": 5
          },
          "by_model_type": {
            "gguf": 40,
            "safetensors": 35,
            "pickle": 15,
            "onnx": 10
          }
        }
      }
  """
  def stats(conn, _params) do
    opts = build_org_opts(conn)
    stats = KnownGood.stats(opts)

    conn
    |> put_status(:ok)
    |> json(%{data: stats})
  end

  @doc """
  Bulk import hash entries from JSON or CSV.

  ## JSON Request Body

      {
        "hashes": [
          {"sha256": "abc123...", "name": "model1", "model_type": "gguf"},
          {"sha256": "def456...", "name": "model2", "model_type": "safetensors"}
        ]
      }

  ## CSV Request Body

      {
        "csv": "sha256,name,model_type,notes\\nabc123...,model1,gguf,\\ndef456...,model2,safetensors,"
      }

  ## Response

      {
        "data": {
          "imported": 2,
          "skipped": 0,
          "invalid": 0,
          "errors": []
        }
      }
  """
  def import_hashes(conn, %{"hashes" => hashes}) when is_list(hashes) do
    opts = build_import_opts(conn)

    case KnownGood.import_hashes(hashes, opts) do
      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(%{data: result})

      {:error, message} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: message})
    end
  end

  def import_hashes(conn, %{"csv" => csv_string}) when is_binary(csv_string) do
    opts = build_import_opts(conn)

    with {:ok, entries} <- KnownGood.parse_csv(csv_string),
         {:ok, result} <- KnownGood.import_hashes(entries, opts) do
      conn
      |> put_status(:ok)
      |> json(%{data: result})
    else
      {:error, message} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: message})
    end
  end

  def import_hashes(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      error: "invalid_request",
      message: "Request must include 'hashes' (JSON array) or 'csv' (string)"
    })
  end

  @doc """
  Export hash entries to JSON or CSV format.

  ## Query Parameters

    * `format` - Output format: "json" (default) or "csv"
    * `model_type` - Filter by model type
    * `source` - Filter by source

  ## JSON Response

      {
        "hashes": [
          {"sha256": "abc123...", "name": "model1", "model_type": "gguf", ...}
        ]
      }

  ## CSV Response (Content-Type: text/csv)

      sha256,name,model_type,notes
      abc123...,model1,gguf,
      def456...,model2,safetensors,
  """
  def export_hashes(conn, params) do
    format = Map.get(params, "format", "json")
    opts = build_export_opts(conn, params)
    entries = KnownGood.export_hashes(opts)

    case format do
      "csv" ->
        csv = build_csv(entries)

        conn
        |> put_resp_content_type("text/csv")
        |> put_resp_header("content-disposition", "attachment; filename=\"known_good_hashes.csv\"")
        |> send_resp(200, csv)

      _ ->
        json(conn, %{hashes: entries})
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp serialize_entry(entry) do
    %{
      sha256: entry.sha256,
      name: entry.name,
      source: entry.source,
      model_type: entry.model_type,
      notes: entry.notes,
      created_by: entry.created_by,
      inserted_at: entry.inserted_at
    }
  end

  defp build_list_opts(conn, params) do
    limit = parse_int(params["limit"], 50) |> min(1000)
    offset = parse_int(params["offset"], 0)

    opts = [limit: limit, offset: offset]
    opts = maybe_add_filter(opts, :source, params["source"])
    opts = maybe_add_filter(opts, :model_type, params["model_type"])
    opts = maybe_add_org_id(opts, conn)
    opts
  end

  defp build_org_opts(conn) do
    maybe_add_org_id([], conn)
  end

  defp build_import_opts(conn) do
    opts = []
    opts = maybe_add_org_id(opts, conn)

    case conn.assigns[:current_user] do
      %{id: user_id} -> [{:created_by, user_id} | opts]
      _ -> opts
    end
  end

  defp build_export_opts(conn, params) do
    opts = []
    opts = maybe_add_filter(opts, :model_type, params["model_type"])
    opts = maybe_add_filter(opts, :source, params["source"])
    opts = maybe_add_org_id(opts, conn)
    opts
  end

  defp add_created_by(attrs, conn) do
    case conn.assigns[:current_user] do
      %{id: user_id} -> Map.put(attrs, "created_by", user_id)
      _ -> attrs
    end
  end

  defp add_organization_id(attrs, conn) do
    case conn.assigns[:organization_id] do
      nil -> attrs
      org_id -> Map.put(attrs, "organization_id", org_id)
    end
  end

  defp maybe_add_filter(opts, _key, nil), do: opts
  defp maybe_add_filter(opts, _key, ""), do: opts
  defp maybe_add_filter(opts, key, value), do: [{key, value} | opts]

  defp maybe_add_org_id(opts, conn) do
    case conn.assigns[:organization_id] do
      nil -> opts
      org_id -> [{:organization_id, org_id} | opts]
    end
  end

  defp parse_int(nil, default), do: default
  defp parse_int("", default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> changeset_error_opt(key) |> to_string()
      end)
    end)
  end

  defp changeset_error_opt(opts, "count"), do: Keyword.get(opts, :count, "count")
  defp changeset_error_opt(opts, "validation"), do: Keyword.get(opts, :validation, "validation")
  defp changeset_error_opt(opts, "kind"), do: Keyword.get(opts, :kind, "kind")
  defp changeset_error_opt(opts, "type"), do: Keyword.get(opts, :type, "type")
  defp changeset_error_opt(_opts, key), do: key

  defp build_csv(entries) do
    header = "sha256,name,model_type,notes\n"

    rows =
      Enum.map_join(entries, "\n", fn e ->
        [e.sha256, e.name || "", e.model_type || "", e.notes || ""]
        |> Enum.map(&escape_csv/1)
        |> Enum.join(",")
      end)

    header <> rows
  end

  defp escape_csv(nil), do: ""

  defp escape_csv(s) when is_binary(s) do
    if String.contains?(s, [",", "\"", "\n"]) do
      "\"" <> String.replace(s, "\"", "\"\"") <> "\""
    else
      s
    end
  end

  defp escape_csv(other), do: to_string(other)
end
