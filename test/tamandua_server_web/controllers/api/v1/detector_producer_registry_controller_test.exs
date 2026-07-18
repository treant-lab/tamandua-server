defmodule TamanduaServerWeb.API.V1.DetectorProducerRegistryControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts.{Permission, Role, RolePermission, UserRole}
  alias TamanduaServer.Authorization.RBAC
  alias TamanduaServer.Repo

  setup do
    organization = insert(:organization)
    other_organization = insert(:organization)
    viewer = insert(:user, organization: organization, role: "viewer")
    admin = insert(:user, organization: organization, role: "analyst")
    other_admin = insert(:user, organization: other_organization, role: "analyst")
    grant_permission!(admin, organization, :system_settings)
    grant_permission!(other_admin, other_organization, :system_settings)

    {:ok, viewer_token, _} = TamanduaServer.Guardian.encode_and_sign(viewer)
    {:ok, admin_token, _} = TamanduaServer.Guardian.encode_and_sign(admin)
    {:ok, other_admin_token, _} = TamanduaServer.Guardian.encode_and_sign(other_admin)

    %{
      viewer_token: viewer_token,
      admin_token: admin_token,
      other_admin_token: other_admin_token
    }
  end

  test "viewer cannot manage producer attestations", %{conn: conn, viewer_token: token} do
    response =
      conn
      |> put_req_header("authorization", "Bearer #{token}")
      |> get("/api/v1/detector-producer-attestations")

    assert json_response(response, 403)["required_permission"] == "system_settings"
  end

  test "admin creates, lists and revokes only inside its tenant", %{
    conn: conn,
    admin_token: token,
    other_admin_token: other_token
  } do
    created =
      conn
      |> put_req_header("authorization", "Bearer #{token}")
      |> post("/api/v1/detector-producer-attestations", attestation_attrs())
      |> json_response(201)

    id = created["data"]["id"]
    assert created["enforcement"] == "disabled"
    assert created["data"]["status"] == "active"

    listed =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> get("/api/v1/detector-producer-attestations")
      |> json_response(200)

    assert Enum.any?(listed["data"], &(&1["id"] == id))

    build_conn()
    |> put_req_header("authorization", "Bearer #{other_token}")
    |> post("/api/v1/detector-producer-attestations/#{id}/revoke")
    |> json_response(404)

    revoked =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> post("/api/v1/detector-producer-attestations/#{id}/revoke")
      |> json_response(200)

    assert revoked["data"]["status"] == "revoked"
    assert revoked["enforcement"] == "disabled"
  end

  defp grant_permission!(user, organization, permission_slug) do
    slug = Atom.to_string(permission_slug)

    permission =
      Repo.get_by(Permission, slug: slug) ||
        (%Permission{}
         |> Permission.changeset(%{
           name: slug,
           slug: slug,
           description: slug,
           category: "system"
         })
         |> Repo.insert!())

    role =
      %Role{}
      |> Role.changeset(%{
        name: "Detector registry administrator",
        slug: "detector_registry_admin_#{user.id}",
        builtin: false,
        priority: 80,
        organization_id: organization.id
      })
      |> Repo.insert!()

    %RolePermission{}
    |> RolePermission.changeset(%{role_id: role.id, permission_id: permission.id})
    |> Repo.insert!()

    %UserRole{}
    |> UserRole.changeset(%{
      user_id: user.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })
    |> Repo.insert!()

    RBAC.invalidate_cache(user)
  end

  defp attestation_attrs do
    %{
      "producer_id" => "tamandua/test-producer",
      "detector_id" => "detector/test",
      "detector_type" => "model",
      "detector_version" => "1.0.0",
      "source" => "governed-registry",
      "revision" => "revision-1",
      "artifact_sha256" => String.duplicate("a", 64),
      "input_schema_sha256" => String.duplicate("b", 64),
      "allowed_evidence_classes" => ["contract_smoke"],
      "allowed_claim_scopes" => ["contract_only"]
    }
  end
end
