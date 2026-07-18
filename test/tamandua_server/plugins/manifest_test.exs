defmodule TamanduaServer.Plugins.ManifestTest do
  use ExUnit.Case, async: true

  alias Ecto.Changeset
  alias TamanduaServer.Plugins.Manifest
  alias TamanduaServer.Plugins.Marketplace

  @valid_checksum String.duplicate("a", 64)

  describe "normalize_attrs/1" do
    test "normalizes data-only manifest metadata" do
      attrs = %{
        "plugin_type" => " Collector ",
        "api_version" => " V1 ",
        "version" => " 1.2.3 ",
        "homepage_url" => " https://plugins.example.test/endpoint-collector ",
        "repository_url" => " https://plugins.example.test/repos/endpoint-collector ",
        "documentation_url" => " https://plugins.example.test/docs/endpoint-collector ",
        "wasm_url" => " https://plugins.example.test/endpoint-collector.wasm ",
        "signature_url" => " https://plugins.example.test/endpoint-collector.sig ",
        "public_key" => " test-public-key ",
        "license" => " Apache-2.0 ",
        "checksum_sha256" => String.duplicate("A", 64),
        "required_capabilities" => [" telemetry:read ", "", "events:read", "telemetry:read"],
        "name" => "Endpoint Collector"
      }

      assert Manifest.normalize_attrs(attrs) == %{
               "plugin_type" => "collector",
               "api_version" => "v1",
               "version" => "1.2.3",
               "homepage_url" => "https://plugins.example.test/endpoint-collector",
               "repository_url" => "https://plugins.example.test/repos/endpoint-collector",
               "documentation_url" => "https://plugins.example.test/docs/endpoint-collector",
               "wasm_url" => "https://plugins.example.test/endpoint-collector.wasm",
               "signature_url" => "https://plugins.example.test/endpoint-collector.sig",
               "public_key" => "test-public-key",
               "license" => "Apache-2.0",
               "checksum_sha256" => @valid_checksum,
               "required_capabilities" => ["telemetry:read", "events:read"],
               "name" => "Endpoint Collector"
             }
    end
  end

  describe "validate_attrs/1" do
    test "keeps additional manifest metadata optional" do
      assert :ok =
               Manifest.validate_attrs(%{
                 plugin_type: "collector",
                 api_version: "v1",
                 checksum_sha256: @valid_checksum,
                 required_capabilities: ["telemetry:read"]
               })
    end

    test "requires schema-required manifest fields" do
      assert {:error, errors} = Manifest.validate_attrs(%{})

      assert {:plugin_type, "is required"} in errors
      assert {:api_version, "is required"} in errors
      assert {:checksum_sha256, "is required"} in errors
    end

    test "treats nil required manifest fields as missing" do
      assert {:error, errors} =
               Manifest.validate_attrs(%{
                 plugin_type: nil,
                 api_version: nil,
                 checksum_sha256: nil
               })

      assert {:plugin_type, "is required"} in errors
      assert {:api_version, "is required"} in errors
      assert {:checksum_sha256, "is required"} in errors
    end

    test "accepts allowed manifest metadata" do
      assert :ok =
               Manifest.validate_attrs(%{
                 plugin_type: "collector",
                 api_version: "v1",
                 version: "1.0.0-rc.1+build.5",
                 homepage_url: "https://plugins.example.test/endpoint-collector",
                 repository_url: "https://plugins.example.test/repos/endpoint-collector",
                 documentation_url: "https://plugins.example.test/docs/endpoint-collector?version=1.0.0#readme",
                 wasm_url: "https://plugins.example.test:443/endpoint-collector.wasm",
                 signature_url: "https://plugins.example.test/endpoint-collector.sig",
                 public_key: "test-public-key",
                 license: "Apache-2.0",
                 checksum_sha256: @valid_checksum,
                 required_capabilities: ["telemetry:read", "events:read"]
               })
    end

    test "rejects unknown manifest contract values" do
      assert {:error, errors} =
               Manifest.validate_attrs(%{
                 plugin_type: "runtime",
                 api_version: "v2",
                 version: "1.0.0-01",
                 homepage_url: "https://plugins.example.test/has space",
                 repository_url: "https://user@plugins.example.test/repos/endpoint-collector",
                 documentation_url: 123,
                 wasm_url: "http://plugins.example.test/endpoint-collector.wasm",
                 signature_url: "https://user:pass@plugins.example.test/endpoint-collector.sig",
                 public_key: " ",
                 license: " ",
                 checksum_sha256: "not-a-checksum",
                 required_capabilities: ["telemetry:read", "runtime:execute"]
               })

      assert {:plugin_type, "is not an allowed plugin_type"} in errors
      assert {:api_version, "is not an allowed api_version"} in errors
      assert {:version, "must be a semantic version"} in errors
      assert {:homepage_url, "must be an HTTPS URL"} in errors
      assert {:repository_url, "must be an HTTPS URL"} in errors
      assert {:documentation_url, "must be a string"} in errors
      assert {:wasm_url, "must be an HTTPS URL"} in errors
      assert {:signature_url, "must be an HTTPS URL"} in errors
      assert {:public_key, "must be a non-empty string"} in errors
      assert {:license, "must be a non-empty string"} in errors
      assert {:checksum_sha256, "must be a lowercase 64-character SHA-256 hex digest"} in errors

      assert {:required_capabilities, "contains unknown capabilities: runtime:execute"} in errors
    end

    test "rejects duplicate atom and string aliases for manifest fields" do
      assert {:error, errors} =
               Manifest.validate_attrs(%{
                 plugin_type: "collector",
                 "plugin_type" => "runtime",
                 api_version: "v1",
                 checksum_sha256: @valid_checksum
               })

      assert {:plugin_type, "must not be provided with both atom and string keys"} in errors
    end
  end

  describe "Marketplace.changeset/2" do
    test "normalizes manifest fields before casting" do
      changeset = Marketplace.changeset(%Marketplace{}, valid_marketplace_attrs())

      assert changeset.valid?
      assert Changeset.get_change(changeset, :plugin_type) == "collector"
      assert Changeset.get_change(changeset, :api_version) == "v1"
      assert Changeset.get_change(changeset, :license) == "Apache-2.0"
      assert Changeset.get_change(changeset, :checksum_sha256) == @valid_checksum
      assert Changeset.get_change(changeset, :required_capabilities) == ["telemetry:read", "events:read"]
    end

    test "adds changeset errors for unknown capabilities" do
      attrs =
        valid_marketplace_attrs(%{
          required_capabilities: ["telemetry:read", "runtime:execute"]
        })

      changeset = Marketplace.changeset(%Marketplace{}, attrs)

      refute changeset.valid?

      assert {"contains unknown capabilities: runtime:execute", _meta} =
               Keyword.fetch!(changeset.errors, :required_capabilities)
    end

    test "adds changeset errors for unsupported manifest metadata" do
      attrs =
        valid_marketplace_attrs(%{
          plugin_type: "runtime",
          api_version: "v2",
          checksum_sha256: "bad"
        })

      changeset = Marketplace.changeset(%Marketplace{}, attrs)

      refute changeset.valid?
      assert {"is not an allowed plugin_type", _meta} = Keyword.fetch!(changeset.errors, :plugin_type)
      assert {"is not an allowed api_version", _meta} = Keyword.fetch!(changeset.errors, :api_version)
      assert {"must be a lowercase 64-character SHA-256 hex digest", _meta} =
               Keyword.fetch!(changeset.errors, :checksum_sha256)
    end

    test "adds changeset errors for invalid hardened manifest metadata" do
      attrs =
        valid_marketplace_attrs(%{
          version: "1.0.0-01",
          homepage_url: "http://plugins.example.test/endpoint-collector",
          repository_url: "https://user@plugins.example.test/repos/endpoint-collector",
          documentation_url: 123,
          wasm_url: "http://plugins.example.test/endpoint-collector.wasm",
          signature_url: "https://user:pass@plugins.example.test/endpoint-collector.sig",
          public_key: " ",
          license: " "
        })

      changeset = Marketplace.changeset(%Marketplace{}, attrs)

      refute changeset.valid?
      assert {"must be a semantic version", _meta} = Keyword.fetch!(changeset.errors, :version)
      assert {"must be an HTTPS URL", _meta} = Keyword.fetch!(changeset.errors, :homepage_url)
      assert {"must be an HTTPS URL", _meta} = Keyword.fetch!(changeset.errors, :repository_url)
      assert {"is invalid", _meta} = Keyword.fetch!(changeset.errors, :documentation_url)
      assert {"must be an HTTPS URL", _meta} = Keyword.fetch!(changeset.errors, :wasm_url)
      assert {"must be an HTTPS URL", _meta} = Keyword.fetch!(changeset.errors, :signature_url)
      assert {"must be a non-empty string", _meta} = Keyword.fetch!(changeset.errors, :public_key)
      assert {"must be a non-empty string", _meta} = Keyword.fetch!(changeset.errors, :license)
    end

    test "turns duplicate manifest aliases into changeset errors without cast ambiguity" do
      attrs =
        valid_marketplace_attrs(%{
          "plugin_type" => "runtime"
        })

      changeset = Marketplace.changeset(%Marketplace{}, attrs)

      refute changeset.valid?

      assert {"must not be provided with both atom and string keys", _meta} =
               Keyword.fetch!(changeset.errors, :plugin_type)
    end
  end

  defp valid_marketplace_attrs(overrides \\ %{}) do
    Map.merge(
      %{
        plugin_id: "endpoint-collector",
        name: "Endpoint Collector",
        description: "Collects endpoint telemetry metadata for marketplace discovery.",
        author: "Tamandua Labs",
        version: "1.0.0",
        plugin_type: " Collector ",
        api_version: " V1 ",
        wasm_url: "https://plugins.example.test/endpoint-collector.wasm",
        signature_url: "https://plugins.example.test/endpoint-collector.sig",
        public_key: "test-public-key",
        license: " Apache-2.0 ",
        checksum_sha256: String.duplicate("A", 64),
        required_capabilities: [" telemetry:read ", "events:read", "telemetry:read"]
      },
      overrides
    )
  end
end
