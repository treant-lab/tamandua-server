defmodule TamanduaServerWeb.API.V1.EmailSecurityTenantSourceTest do
  use ExUnit.Case, async: true

  @controller "lib/tamandua_server_web/controllers/api/v1/email_security_controller.ex"

  test "controller derives organization context and passes it to every provider call" do
    source = File.read!(@controller)

    refute source =~ "Microsoft365.get_status()"
    refute source =~ "GoogleWorkspace.get_status()"
    refute source =~ "Microsoft365.update_config(config)"
    refute source =~ "GoogleWorkspace.update_config(config)"

    for call <- [
          "Microsoft365.get_threat_intel(organization_id, opts)",
          "Microsoft365.list_quarantine(organization_id, opts)",
          "Microsoft365.release_from_quarantine(organization_id, message_id, opts)",
          "Microsoft365.get_security_alerts(organization_id, opts)",
          "Microsoft365.search_emails(organization_id, query, opts)",
          "GoogleWorkspace.get_gmail_logs(organization_id, start_time, end_time, opts)",
          "GoogleWorkspace.get_dlp_incidents(organization_id, opts)",
          "GoogleWorkspace.get_user_security(organization_id, email)",
          "GoogleWorkspace.get_login_events(organization_id, opts)"
        ] do
      assert source =~ call
    end
  end

  test "missing tenant and absent integration fail closed" do
    source = File.read!(@controller)

    assert source =~ "put_status(:forbidden)"

    assert source =~
             "integration_error_status(:integration_not_configured, _fallback), do: :not_found"

    assert source =~ "integration_error_status(:organization_required, _fallback), do: :forbidden"
  end

  test "mutating and read surfaces have explicit RBAC gates" do
    source = File.read!(@controller)
    roles = File.read!("lib/tamandua_server/accounts/role.ex")
    rbac = File.read!("lib/tamandua_server_web/plugs/rbac.ex")

    assert source =~ "[permission: :organization_integrations]"
    assert source =~ "when action in [:configure_m365, :configure_google]"
    assert source =~ "[permission: :response_execute]"
    assert source =~ "when action in [:m365_release_quarantine]"
    assert source =~ "[permission: :threat_intel_read]"
    assert source =~ "[permission: :alerts_read]"
    assert source =~ "[permission: :alerts_create]"
    assert source =~ "[permission: :alerts_update]"

    viewer_permissions = role_permissions_source(roles, :viewer, :responder)
    api_only_permissions = role_permissions_source(roles, :api_only, :_)
    refute viewer_permissions =~ ":organization_integrations"
    refute viewer_permissions =~ ":response_execute"
    refute api_only_permissions =~ ":organization_integrations"
    refute api_only_permissions =~ ":response_execute"

    assert rbac =~ "is_nil(user)"
    assert rbac =~ "unauthorized(conn, \"Authentication required\")"
  end

  test "correlator projections pass authenticated organization explicitly" do
    source = File.read!(@controller)

    for call <- [
          "EmailCorrelator.list_attack_chains(organization_id, opts)",
          "EmailCorrelator.get_attack_chain(organization_id, email_id)",
          "EmailCorrelator.get_user_risk(organization_id, email)",
          "EmailCorrelator.get_user_chains(organization_id, email, opts)",
          "EmailCorrelator.get_stats(organization_id)"
        ] do
      assert source =~ call
    end
  end

  test "provider configuration is a partial patch and rejects null secrets" do
    source = File.read!(@controller)

    assert source =~ "partial_provider_config("
    assert source =~ "Map.has_key?(params, key)"
    assert source =~ "key in secret_keys and is_nil(value)"
    assert source =~ ":secret_cannot_be_null"
    refute source =~ ~s(client_secret: params["client_secret"])
    refute source =~ ~s(service_account_key: params["service_account_key"])
  end

  defp role_permissions_source(source, role, next_role) do
    start_marker = "def default_permissions(:#{role})"
    start = source |> :binary.match(start_marker) |> elem(0)

    finish =
      if next_role == :_ do
        byte_size(source)
      else
        marker = "def default_permissions(:#{next_role})"

        {offset, _length} =
          :binary.match(source, marker, scope: {start + 1, byte_size(source) - start - 1})

        offset
      end

    binary_part(source, start, finish - start)
  end
end
