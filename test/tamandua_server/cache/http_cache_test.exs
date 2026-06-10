defmodule TamanduaServer.Cache.HTTPCacheTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Cache.HTTPCache

  describe "generate_etag/1" do
    test "generates ETag from binary content" do
      etag = HTTPCache.generate_etag("test content")
      assert is_binary(etag)
      assert String.starts_with?(etag, "\"")
      assert String.ends_with?(etag, "\"")
    end

    test "generates consistent ETags for same content" do
      etag1 = HTTPCache.generate_etag("content")
      etag2 = HTTPCache.generate_etag("content")
      assert etag1 == etag2
    end

    test "generates different ETags for different content" do
      etag1 = HTTPCache.generate_etag("content1")
      etag2 = HTTPCache.generate_etag("content2")
      assert etag1 != etag2
    end

    test "generates ETag from map" do
      data = %{id: 1, name: "test"}
      etag = HTTPCache.generate_etag(data)
      assert is_binary(etag)
    end
  end

  describe "generate_weak_etag/1" do
    test "generates weak ETag with W/ prefix" do
      etag = HTTPCache.generate_weak_etag("test content")
      assert String.starts_with?(etag, "W/\"")
    end
  end

  describe "validate_conditional_request/2" do
    test "returns :not_modified when ETags match" do
      conn = build_conn()
      |> put_req_header("if-none-match", "\"abc123\"")

      result = HTTPCache.validate_conditional_request(conn, "\"abc123\"")
      assert result == :not_modified
    end

    test "returns :proceed when ETags don't match" do
      conn = build_conn()
      |> put_req_header("if-none-match", "\"abc123\"")

      result = HTTPCache.validate_conditional_request(conn, "\"def456\"")
      assert result == :proceed
    end

    test "returns :proceed when no If-None-Match header" do
      conn = build_conn()
      result = HTTPCache.validate_conditional_request(conn, "\"abc123\"")
      assert result == :proceed
    end

    test "handles multiple ETags in If-None-Match" do
      conn = build_conn()
      |> put_req_header("if-none-match", "\"abc\", \"def\", \"ghi\"")

      assert :not_modified = HTTPCache.validate_conditional_request(conn, "\"def\"")
      assert :proceed = HTTPCache.validate_conditional_request(conn, "\"xyz\"")
    end
  end

  describe "validate_if_modified_since/2" do
    test "returns :not_modified when resource hasn't been modified" do
      last_modified = ~U[2024-01-01 12:00:00Z]
      client_date = "Mon, 01 Jan 2024 12:00:00 GMT"

      conn = build_conn()
      |> put_req_header("if-modified-since", client_date)

      result = HTTPCache.validate_if_modified_since(conn, last_modified)
      assert result == :not_modified
    end

    test "returns :proceed when resource has been modified" do
      last_modified = ~U[2024-01-02 12:00:00Z]
      client_date = "Mon, 01 Jan 2024 12:00:00 GMT"

      conn = build_conn()
      |> put_req_header("if-modified-since", client_date)

      result = HTTPCache.validate_if_modified_since(conn, last_modified)
      assert result == :proceed
    end

    test "returns :proceed when no If-Modified-Since header" do
      conn = build_conn()
      last_modified = ~U[2024-01-01 12:00:00Z]

      result = HTTPCache.validate_if_modified_since(conn, last_modified)
      assert result == :proceed
    end
  end

  describe "format_http_date/1" do
    test "formats DateTime as HTTP date" do
      dt = ~U[2024-01-01 12:00:00Z]
      formatted = HTTPCache.format_http_date(dt)
      assert formatted == "Mon, 01 Jan 2024 12:00:00 GMT"
    end
  end

  describe "put_cache_control/3" do
    test "adds public cache control header" do
      conn = build_conn()
      |> HTTPCache.put_cache_control(:public, max_age: 300)

      header = get_resp_header(conn, "cache-control") |> List.first()
      assert header == "public, max-age=300"
    end

    test "adds private cache control header" do
      conn = build_conn()
      |> HTTPCache.put_cache_control(:private, max_age: 60)

      header = get_resp_header(conn, "cache-control") |> List.first()
      assert header == "private, max-age=60"
    end

    test "adds no-cache directive" do
      conn = build_conn()
      |> HTTPCache.put_cache_control(:private, no_cache: true)

      header = get_resp_header(conn, "cache-control") |> List.first()
      assert header =~ "no-cache"
    end

    test "adds must-revalidate directive" do
      conn = build_conn()
      |> HTTPCache.put_cache_control(:public, must_revalidate: true, max_age: 300)

      header = get_resp_header(conn, "cache-control") |> List.first()
      assert header =~ "must-revalidate"
    end
  end

  describe "put_vary/2" do
    test "adds Vary header with single value" do
      conn = build_conn()
      |> HTTPCache.put_vary("Accept")

      header = get_resp_header(conn, "vary") |> List.first()
      assert header == "Accept"
    end

    test "adds Vary header with multiple values" do
      conn = build_conn()
      |> HTTPCache.put_vary(["Accept", "Accept-Encoding", "Authorization"])

      header = get_resp_header(conn, "vary") |> List.first()
      assert header == "Accept, Accept-Encoding, Authorization"
    end
  end

  describe "disable_cache/1" do
    test "adds headers to disable caching" do
      conn = build_conn()
      |> HTTPCache.disable_cache()

      cache_control = get_resp_header(conn, "cache-control") |> List.first()
      pragma = get_resp_header(conn, "pragma") |> List.first()
      expires = get_resp_header(conn, "expires") |> List.first()

      assert cache_control =~ "no-store"
      assert cache_control =~ "no-cache"
      assert pragma == "no-cache"
      assert expires == "0"
    end
  end

  describe "cache_api_response/2" do
    test "adds standard API cache headers" do
      conn = build_conn()
      |> HTTPCache.cache_api_response(max_age: 120, public: false)

      cache_control = get_resp_header(conn, "cache-control") |> List.first()
      vary = get_resp_header(conn, "vary") |> List.first()

      assert cache_control == "private, max-age=120"
      assert vary == "Accept, Authorization"
    end

    test "uses default max_age when not specified" do
      conn = build_conn()
      |> HTTPCache.cache_api_response()

      cache_control = get_resp_header(conn, "cache-control") |> List.first()
      assert cache_control =~ "max-age=60"
    end
  end
end
