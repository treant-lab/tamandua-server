defmodule TamanduaServerWeb.Auth.SSOControllerTest do
  use TamanduaServerWeb.ConnCase

  alias TamanduaServer.Auth.SSO
  alias TamanduaServer.Auth.SSO.SSOConfig
  alias TamanduaServer.Repo

  describe "SAML endpoints" do
    setup do
      org = insert(:organization)

      {:ok, config} =
        %SSOConfig{}
        |> SSOConfig.changeset(%{
          organization_id: org.id,
          provider: :saml,
          enabled: true,
          jit_provisioning: true,
          settings: %{
            "idp_entity_id" => "https://idp.example.com",
            "idp_sso_url" => "https://idp.example.com/sso",
            "idp_certificate" => test_certificate(),
            "sp_entity_id" => "https://edr.example.com/saml/metadata",
            "acs_url" => "https://edr.example.com/auth/sso/saml/acs/#{org.id}"
          }
        })
        |> Repo.insert()

      {:ok, config: config, org: org}
    end

    test "GET /auth/sso/saml/metadata/:provider_id returns SP metadata XML", %{
      conn: conn,
      config: config
    } do
      conn = get(conn, ~p"/auth/sso/saml/metadata/#{config.id}")

      assert response(conn, 200) =~ "EntityDescriptor"
      assert response(conn, 200) =~ "SPSSODescriptor"
      assert response(conn, 200) =~ "AssertionConsumerService"
    end

    test "GET /auth/sso/saml/login/:provider_id redirects to IdP", %{conn: conn, config: config} do
      conn = get(conn, ~p"/auth/sso/saml/login/#{config.id}")

      assert redirected_to(conn) =~ config.settings["idp_sso_url"]
      assert redirected_to(conn) =~ "SAMLRequest="
    end

    test "POST /auth/sso/saml/acs/:provider_id handles valid SAML response", %{
      conn: conn,
      config: config
    } do
      saml_response = build_valid_saml_response(config)

      conn =
        post(conn, ~p"/auth/sso/saml/acs/#{config.id}", %{
          "SAMLResponse" => Base.encode64(saml_response)
        })

      assert redirected_to(conn) =~ "/"
      assert get_flash(conn, :info) =~ "Signed in via SSO"
    end

    test "POST /auth/sso/saml/acs/:provider_id rejects missing SAMLResponse", %{
      conn: conn,
      config: config
    } do
      conn = post(conn, ~p"/auth/sso/saml/acs/#{config.id}", %{})

      assert redirected_to(conn) =~ "/login"
      assert get_flash(conn, :error) =~ "Missing SAML response"
    end
  end

  describe "OAuth endpoints" do
    setup do
      org = insert(:organization)

      {:ok, config} =
        %SSOConfig{}
        |> SSOConfig.changeset(%{
          organization_id: org.id,
          provider: :azure_ad,
          enabled: true,
          jit_provisioning: true,
          settings: %{
            "tenant_id" => "tenant-123",
            "client_id" => "client-456",
            "client_secret" => "secret-789"
          }
        })
        |> Repo.insert()

      {:ok, config: config, org: org}
    end

    test "GET /auth/sso/oauth/authorize/:provider_id redirects to OAuth provider", %{
      conn: conn,
      config: config
    } do
      conn = get(conn, ~p"/auth/sso/oauth/authorize/#{config.id}")

      redirect_url = redirected_to(conn)
      assert redirect_url =~ "login.microsoftonline.com"
      assert redirect_url =~ "client_id=#{config.settings["client_id"]}"
      assert redirect_url =~ "response_type=code"
      assert redirect_url =~ "state="
      assert redirect_url =~ "code_challenge="
      assert redirect_url =~ "code_challenge_method=S256"
    end

    test "GET /auth/sso/oauth/callback/:provider_id handles OAuth error", %{
      conn: conn,
      config: config
    } do
      conn =
        get(conn, ~p"/auth/sso/oauth/callback/#{config.id}", %{
          "error" => "access_denied",
          "error_description" => "User denied access"
        })

      assert redirected_to(conn) =~ "/login"
      assert get_flash(conn, :error) =~ "Authentication failed"
    end
  end

  describe "list_providers/2" do
    setup do
      org = insert(:organization)

      {:ok, saml_config} =
        %SSOConfig{}
        |> SSOConfig.changeset(%{
          organization_id: org.id,
          provider: :saml,
          enabled: true,
          settings: %{
            "idp_entity_id" => "https://idp.example.com",
            "idp_sso_url" => "https://idp.example.com/sso",
            "idp_certificate" => test_certificate()
          }
        })
        |> Repo.insert()

      {:ok, oauth_config} =
        %SSOConfig{}
        |> SSOConfig.changeset(%{
          organization_id: org.id,
          provider: :google_workspace,
          enabled: false,
          settings: %{
            "client_id" => "client-123",
            "client_secret" => "secret-456"
          }
        })
        |> Repo.insert()

      {:ok, org: org, saml_config: saml_config, oauth_config: oauth_config}
    end

    test "returns only enabled providers", %{conn: conn, org: org, saml_config: saml_config} do
      conn = get(conn, ~p"/api/v1/sso/providers?organization_id=#{org.id}")

      assert %{"providers" => providers} = json_response(conn, 200)
      assert length(providers) == 1
      assert List.first(providers)["provider"] == "saml"
    end
  end

  # Helper functions

  defp test_certificate do
    """
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKJsmz7xFPilMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
    BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
    aWRnaXRzIFB0eSBMdGQwHhcNMTcwODIzMTg0MjI3WhcNMjcwODIxMTg0MjI3WjBF
    MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
    ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
    CgKCAQEAr1muwBA8FhXv7Kxd4WwqKxYNs3fSSSFCxZSPZ0JhJnZC7g5G1Q7S7cKD
    test-cert-data-here
    -----END CERTIFICATE-----
    """
  end

  defp build_valid_saml_response(_config) do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_test-response-123"
                    Version="2.0"
                    IssueInstant="2024-01-01T12:00:00Z">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        https://idp.example.com
      </saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="_test-assertion-456"
                      Version="2.0"
                      IssueInstant="2024-01-01T12:00:00Z">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
            testuser@example.com
          </saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="2024-01-01T11:55:00Z"
                         NotOnOrAfter="2024-01-01T12:05:00Z">
          <saml:AudienceRestriction>
            <saml:Audience>https://edr.example.com/saml/metadata</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
          <saml:Attribute Name="email">
            <saml:AttributeValue>testuser@example.com</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="displayName">
            <saml:AttributeValue>Test User</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>
    """
  end
end
