defmodule TamanduaServer.ThreatIntel.StixTaxii do
  @moduledoc """
  STIX/TAXII 2.1 client for bi-directional threat intelligence sharing.

  Supports:
  - TAXII 2.1 server discovery and collection enumeration
  - Polling STIX objects from TAXII collections
  - Publishing STIX bundles to writable TAXII collections
  - Configurable authentication (Basic, API key, certificate)

  TAXII 2.1 endpoints follow the specification:
  - Discovery: GET {server}/taxii2/
  - API Root: GET {api_root}/
  - Collections: GET {api_root}/collections/
  - Objects: GET {api_root}/collections/{id}/objects/
  - Publish:  POST {api_root}/collections/{id}/objects/

  Reference: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
  """

  require Logger

  @finch_name TamanduaServer.Finch
  @default_timeout 30_000
  @taxii_content_type "application/taxii+json;version=2.1"
  @stix_content_type "application/stix+json;version=2.1"

  # ── TAXII 2.1 Discovery ─────────────────────────────────────────────

  @doc """
  Discover available API roots from a TAXII 2.1 server.

  Returns the discovery document which includes:
  - `title` - Server title
  - `description` - Server description
  - `api_roots` - List of API root URLs
  - `default` - Default API root URL

  ## Parameters
    - `server_url` - Base URL of the TAXII server
    - `auth` - Authentication credentials (see auth format below)

  ## Auth format
    - `%{type: :basic, username: "user", password: "pass"}`
    - `%{type: :api_key, key: "key-value", header: "X-API-Key"}`
    - `%{type: :bearer, token: "jwt-token"}`
  """
  @spec discover(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def discover(server_url, auth \\ %{}) do
    url = normalize_url(server_url) <> "/taxii2/"

    case taxii_get(url, auth) do
      {:ok, body} ->
        {:ok, body}

      {:error, reason} ->
        Logger.error("[StixTaxii] Discovery failed for #{server_url}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Get information about a specific API root.

  Returns API root details including title, description, versions, and max content length.
  """
  @spec get_api_root(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def get_api_root(api_root_url, auth \\ %{}) do
    url = normalize_url(api_root_url) <> "/"

    case taxii_get(url, auth) do
      {:ok, body} -> {:ok, body}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── Collections ──────────────────────────────────────────────────────

  @doc """
  List available collections from a TAXII API root.

  Returns a list of collection objects, each containing:
  - `id` - Collection UUID
  - `title` - Human-readable title
  - `description` - Collection description
  - `can_read` - Whether objects can be read
  - `can_write` - Whether objects can be written
  - `media_types` - Supported media types
  """
  @spec list_collections(String.t(), map()) :: {:ok, [map()]} | {:error, term()}
  def list_collections(api_root_url, auth \\ %{}) do
    url = normalize_url(api_root_url) <> "/collections/"

    case taxii_get(url, auth) do
      {:ok, %{"collections" => collections}} ->
        {:ok, collections}

      {:ok, body} when is_map(body) ->
        # Some servers return collections at top level
        {:ok, Map.get(body, "collections", [])}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get details about a specific collection.
  """
  @spec get_collection(String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def get_collection(api_root_url, collection_id, auth \\ %{}) do
    url = normalize_url(api_root_url) <> "/collections/#{collection_id}/"

    case taxii_get(url, auth) do
      {:ok, body} -> {:ok, body}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── Poll Objects ─────────────────────────────────────────────────────

  @doc """
  Poll for STIX objects from a TAXII collection.

  ## Options
    - `:added_after` - Only return objects added after this DateTime
    - `:types` - List of STIX object types to filter (e.g., ["indicator", "malware"])
    - `:ids` - List of specific STIX object IDs to retrieve
    - `:limit` - Maximum number of objects to return
    - `:next` - Pagination cursor from previous response

  ## Returns
    `{:ok, %{objects: [...], more: boolean, next: cursor}}`
  """
  @spec poll_collection(String.t(), String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def poll_collection(api_root_url, collection_id, auth \\ %{}, opts \\ []) do
    base_url = normalize_url(api_root_url) <> "/collections/#{collection_id}/objects/"

    query_params = build_query_params(opts)
    url = if query_params == "", do: base_url, else: "#{base_url}?#{query_params}"

    case taxii_get(url, auth, accept: @stix_content_type) do
      {:ok, %{"objects" => objects} = body} ->
        {:ok, %{
          objects: objects,
          more: Map.get(body, "more", false),
          next: Map.get(body, "next")
        }}

      {:ok, body} when is_map(body) ->
        {:ok, %{
          objects: Map.get(body, "objects", []),
          more: Map.get(body, "more", false),
          next: Map.get(body, "next")
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Poll all pages from a collection, following pagination cursors.

  Warning: This may return a very large number of objects. Use with care.
  """
  @spec poll_all(String.t(), String.t(), map(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def poll_all(api_root_url, collection_id, auth, opts \\ []) do
    do_poll_all(api_root_url, collection_id, auth, opts, [])
  end

  defp do_poll_all(api_root_url, collection_id, auth, opts, acc) do
    case poll_collection(api_root_url, collection_id, auth, opts) do
      {:ok, %{objects: objects, more: true, next: next}} when not is_nil(next) ->
        new_opts = Keyword.put(opts, :next, next)
        do_poll_all(api_root_url, collection_id, auth, new_opts, acc ++ objects)

      {:ok, %{objects: objects}} ->
        {:ok, acc ++ objects}

      {:error, reason} ->
        if length(acc) > 0 do
          Logger.warning("[StixTaxii] Partial poll result: #{length(acc)} objects before error")
          {:ok, acc}
        else
          {:error, reason}
        end
    end
  end

  # ── Publish Objects ──────────────────────────────────────────────────

  @doc """
  Publish a STIX bundle to a writable TAXII collection.

  The bundle should be a map with:
  - `"type"` => `"bundle"`
  - `"id"` => Bundle ID
  - `"objects"` => List of STIX objects

  Returns the TAXII status resource with envelope ID and processing status.
  """
  @spec publish_bundle(String.t(), String.t(), map(), map()) ::
          {:ok, map()} | {:error, term()}
  def publish_bundle(api_root_url, collection_id, bundle, auth) do
    url = normalize_url(api_root_url) <> "/collections/#{collection_id}/objects/"

    case taxii_post(url, bundle, auth) do
      {:ok, body} ->
        Logger.info("[StixTaxii] Published bundle to #{collection_id}: #{inspect(Map.get(body, "id"))}")
        {:ok, body}

      {:error, reason} ->
        Logger.error("[StixTaxii] Failed to publish bundle: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Check the status of a previously published bundle.
  """
  @spec get_publish_status(String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def get_publish_status(api_root_url, status_id, auth) do
    url = normalize_url(api_root_url) <> "/status/#{status_id}/"

    case taxii_get(url, auth) do
      {:ok, body} -> {:ok, body}
      {:error, reason} -> {:error, reason}
    end
  end

  # ── TAXII Feed Integration ──────────────────────────────────────────

  @doc """
  Poll a TAXII collection and convert STIX indicators to internal IOC format.

  This is the main entry point for using TAXII as a feed source.
  Polls for indicators, converts them, and returns IOCs ready for insertion.

  ## Options
    - `:added_after` - Only fetch indicators added after this DateTime
    - `:limit` - Maximum indicators to fetch per poll
  """
  @spec poll_indicators(String.t(), String.t(), map(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def poll_indicators(api_root_url, collection_id, auth, opts \\ []) do
    poll_opts = opts ++ [types: ["indicator"]]

    case poll_collection(api_root_url, collection_id, auth, poll_opts) do
      {:ok, %{objects: objects}} ->
        iocs =
          objects
          |> Enum.filter(&(&1["type"] == "indicator"))
          |> Enum.flat_map(fn indicator ->
            case TamanduaServer.ThreatIntel.StixConverter.from_stix_indicator(indicator) do
              {:ok, ioc} -> [ioc]
              {:error, _} -> []
            end
          end)

        {:ok, iocs}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ── HTTP Helpers ─────────────────────────────────────────────────────

  defp taxii_get(url, auth, opts \\ []) do
    accept = Keyword.get(opts, :accept, @taxii_content_type)
    headers = build_headers(auth, accept)

    request = Finch.build(:get, url, headers)

    case Finch.request(request, @finch_name, receive_timeout: @default_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, parsed} -> {:ok, parsed}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %Finch.Response{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %Finch.Response{status: 403}} ->
        {:error, :forbidden}

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: 406}} ->
        # Not Acceptable - try without TAXII content type
        fallback_headers = build_headers(auth, "application/json")
        fallback_request = Finch.build(:get, url, fallback_headers)
        case Finch.request(fallback_request, @finch_name, receive_timeout: @default_timeout) do
          {:ok, %Finch.Response{status: 200, body: body}} ->
            case Jason.decode(body) do
              {:ok, parsed} -> {:ok, parsed}
              {:error, _} -> {:error, :invalid_json}
            end
          {:ok, %Finch.Response{status: status, body: body}} ->
            {:error, "HTTP #{status}: #{String.slice(body, 0, 500)}"}
          {:error, reason} ->
            {:error, reason}
        end

      {:ok, %Finch.Response{status: status, body: body}} ->
        {:error, "HTTP #{status}: #{String.slice(body, 0, 500)}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp taxii_post(url, body, auth) do
    headers = build_headers(auth, @taxii_content_type) ++
      [{"content-type", @stix_content_type}]

    json_body = Jason.encode!(body)
    request = Finch.build(:post, url, headers, json_body)

    case Finch.request(request, @finch_name, receive_timeout: @default_timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..202 ->
        case Jason.decode(resp_body) do
          {:ok, parsed} -> {:ok, parsed}
          {:error, _} -> {:ok, %{"status" => "accepted"}}
        end

      {:ok, %Finch.Response{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %Finch.Response{status: 403}} ->
        {:error, :forbidden}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:error, "HTTP #{status}: #{String.slice(resp_body, 0, 500)}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_headers(auth, accept) do
    base_headers = [{"accept", accept}]

    case auth do
      %{type: :basic, username: username, password: password} ->
        encoded = Base.encode64("#{username}:#{password}")
        base_headers ++ [{"authorization", "Basic #{encoded}"}]

      %{type: :api_key, key: key, header: header} ->
        base_headers ++ [{header, key}]

      %{type: :api_key, key: key} ->
        base_headers ++ [{"authorization", "Bearer #{key}"}]

      %{type: :bearer, token: token} ->
        base_headers ++ [{"authorization", "Bearer #{token}"}]

      _ ->
        base_headers
    end
  end

  defp build_query_params(opts) do
    params = []

    params = case Keyword.get(opts, :added_after) do
      nil -> params
      %DateTime{} = dt -> params ++ [{"added_after", DateTime.to_iso8601(dt)}]
      str when is_binary(str) -> params ++ [{"added_after", str}]
      _ -> params
    end

    params = case Keyword.get(opts, :types) do
      nil -> params
      types when is_list(types) ->
        Enum.reduce(types, params, fn type, acc ->
          acc ++ [{"match[type]", type}]
        end)
      _ -> params
    end

    params = case Keyword.get(opts, :ids) do
      nil -> params
      ids when is_list(ids) ->
        Enum.reduce(ids, params, fn id, acc ->
          acc ++ [{"match[id]", id}]
        end)
      _ -> params
    end

    params = case Keyword.get(opts, :limit) do
      nil -> params
      limit -> params ++ [{"limit", to_string(limit)}]
    end

    params = case Keyword.get(opts, :next) do
      nil -> params
      next -> params ++ [{"next", next}]
    end

    params
    |> Enum.map(fn {k, v} -> "#{URI.encode_www_form(k)}=#{URI.encode_www_form(v)}" end)
    |> Enum.join("&")
  end

  # ── STIX Bundle Parsing ──────────────────────────────────────────────

  @doc """
  Parse a STIX 2.1 bundle and extract all structured objects.

  Returns a map with objects grouped by type:
  - `:indicators` - IOC indicators
  - `:attack_patterns` - ATT&CK technique descriptions
  - `:malware` - Malware family definitions
  - `:relationships` - STIX relationships linking objects
  - `:identities` - Source/target identities
  - `:campaigns` - Campaign objects
  - `:intrusion_sets` - Threat actor groups
  - `:tools` - Legitimate tools used by attackers
  - `:other` - Any other STIX object types
  """
  @spec parse_bundle(map()) :: {:ok, map()} | {:error, term()}
  def parse_bundle(%{"type" => "bundle", "objects" => objects}) when is_list(objects) do
    grouped = Enum.group_by(objects, fn obj -> obj["type"] end)

    result = %{
      indicators: Map.get(grouped, "indicator", []),
      attack_patterns: Map.get(grouped, "attack-pattern", []),
      malware: Map.get(grouped, "malware", []),
      relationships: Map.get(grouped, "relationship", []),
      identities: Map.get(grouped, "identity", []),
      campaigns: Map.get(grouped, "campaign", []),
      intrusion_sets: Map.get(grouped, "intrusion-set", []),
      tools: Map.get(grouped, "tool", []),
      sightings: Map.get(grouped, "sighting", []),
      other: objects
        |> Enum.reject(fn obj ->
          obj["type"] in [
            "indicator", "attack-pattern", "malware", "relationship",
            "identity", "campaign", "intrusion-set", "tool", "sighting"
          ]
        end),
      total_objects: length(objects)
    }

    {:ok, result}
  end

  def parse_bundle(%{"type" => "bundle"}), do: {:ok, %{indicators: [], total_objects: 0}}
  def parse_bundle(_), do: {:error, :invalid_bundle}

  @doc """
  Extract IOCs from a parsed STIX bundle.

  Converts STIX indicators to internal IOC format and enriches them
  with context from related objects (attack patterns, malware, campaigns).
  """
  @spec extract_iocs_from_bundle(map()) :: {:ok, [map()]} | {:error, term()}
  def extract_iocs_from_bundle(%{"type" => "bundle", "objects" => objects} = bundle) do
    case parse_bundle(bundle) do
      {:ok, parsed} ->
        # Build a lookup map for relationships and context objects
        object_index = build_object_index(objects)
        relationship_map = build_relationship_map(parsed.relationships)

        # Convert indicators to IOCs with enrichment from related objects
        iocs = Enum.flat_map(parsed.indicators, fn indicator ->
          case TamanduaServer.ThreatIntel.StixConverter.from_stix_indicator(indicator) do
            {:ok, ioc} ->
              enriched = enrich_ioc_from_stix(ioc, indicator, relationship_map, object_index)
              [enriched]
            {:error, _} ->
              []
          end
        end)

        {:ok, iocs}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def extract_iocs_from_bundle(_), do: {:error, :invalid_bundle}

  @doc """
  Import STIX objects from a TAXII collection into Tamandua.

  Polls the specified collection, extracts IOCs from indicators,
  stores them in the database, and optionally triggers a retroactive scan.

  ## Options
    - `:added_after` - Only fetch objects added after this DateTime
    - `:retro_scan` - Whether to trigger retroactive scan for new IOCs (default: true)
  """
  @spec import_from_collection(String.t(), String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def import_from_collection(api_root_url, collection_id, auth, opts \\ []) do
    retro_scan = Keyword.get(opts, :retro_scan, true)

    case poll_all(api_root_url, collection_id, auth, opts) do
      {:ok, objects} ->
        # Construct a bundle from the polled objects
        bundle = %{"type" => "bundle", "id" => "bundle--import", "objects" => objects}

        case TamanduaServer.ThreatIntel.StixConverter.import_bundle(bundle) do
          {:ok, result} ->
            # Optionally trigger retroactive scan
            if retro_scan and result.iocs_inserted > 0 do
              try do
                iocs = TamanduaServer.ThreatIntel.StixConverter.from_stix_indicators(
                  Enum.filter(objects, &(&1["type"] == "indicator"))
                )
                TamanduaServer.ThreatIntel.RetroactiveScanner.scan_new_iocs(iocs)
              rescue
                _ -> :ok
              end
            end

            {:ok, Map.put(result, :collection_id, collection_id)}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ── Private Helpers for Bundle Parsing ─────────────────────────────

  defp build_object_index(objects) do
    Enum.reduce(objects, %{}, fn obj, acc ->
      case obj["id"] do
        nil -> acc
        id -> Map.put(acc, id, obj)
      end
    end)
  end

  defp build_relationship_map(relationships) do
    # Build a map from source_ref -> [{relationship_type, target_ref}]
    Enum.reduce(relationships, %{}, fn rel, acc ->
      source = rel["source_ref"]
      target = rel["target_ref"]
      rel_type = rel["relationship_type"]

      if source && target && rel_type do
        entry = %{type: rel_type, target: target, source: source}
        Map.update(acc, source, [entry], fn existing -> [entry | existing] end)
      else
        acc
      end
    end)
  end

  defp enrich_ioc_from_stix(ioc, indicator, relationship_map, object_index) do
    indicator_id = indicator["id"]
    related = Map.get(relationship_map, indicator_id, [])

    # Extract attack patterns (MITRE techniques) from relationships
    mitre_techniques = related
    |> Enum.filter(fn r -> r.type == "indicates" end)
    |> Enum.flat_map(fn r ->
      case Map.get(object_index, r.target) do
        %{"type" => "attack-pattern", "external_references" => refs} ->
          refs
          |> Enum.filter(fn ref -> ref["source_name"] == "mitre-attack" end)
          |> Enum.map(fn ref -> ref["external_id"] end)
          |> Enum.reject(&is_nil/1)
        _ ->
          []
      end
    end)

    # Extract malware names from relationships
    malware_names = related
    |> Enum.filter(fn r -> r.type == "indicates" end)
    |> Enum.flat_map(fn r ->
      case Map.get(object_index, r.target) do
        %{"type" => "malware", "name" => name} -> [name]
        _ -> []
      end
    end)

    # Extract campaign context
    campaign_names = related
    |> Enum.flat_map(fn r ->
      case Map.get(object_index, r.target) do
        %{"type" => "campaign", "name" => name} -> [name]
        _ -> []
      end
    end)

    # Enrich tags
    extra_tags =
      Enum.map(mitre_techniques, fn t -> "mitre:#{t}" end) ++
      Enum.map(malware_names, fn m -> "malware:#{m}" end) ++
      Enum.map(campaign_names, fn c -> "campaign:#{c}" end)

    existing_tags = ioc[:tags] || []

    %{ioc |
      tags: Enum.uniq(existing_tags ++ extra_tags),
      description: enrich_description(ioc[:description], malware_names, campaign_names)
    }
  end

  defp enrich_description(base_desc, malware_names, campaign_names) do
    parts = [base_desc]
    parts = if malware_names != [], do: parts ++ ["Malware: #{Enum.join(malware_names, ", ")}"], else: parts
    parts = if campaign_names != [], do: parts ++ ["Campaign: #{Enum.join(campaign_names, ", ")}"], else: parts
    Enum.join(parts, " | ")
  end

  defp normalize_url(url) do
    url
    |> String.trim()
    |> String.trim_trailing("/")
  end
end
