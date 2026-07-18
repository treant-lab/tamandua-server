defmodule TamanduaServerWeb.InertiaTenantBoundarySourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../lib", __DIR__)

  defp read(relative_path), do: File.read!(Path.join(@root, relative_path))

  test "the Inertia pipeline proves the authenticated user's tenant before shared data" do
    router = read("tamandua_server_web/router.ex")

    fetch = index!(router, "plug(:fetch_current_user)", 2)
    authenticate = index!(router, "plug(:require_authenticated_user)")
    resolve = index!(router, "plug(TamanduaServerWeb.Plugs.ResolveInertiaTenant)")
    shared = index!(router, "plug(TamanduaServerWeb.Plugs.InertiaSharedData)")

    assert fetch < authenticate
    assert authenticate < resolve
    assert resolve < shared
    assert router =~ "scope \"/app\", TamanduaServerWeb do\n    pipe_through(:inertia)"
    refute router =~ "pipe_through([:inertia, :require_authenticated_user])"
  end

  test "resolver accepts only the current user organization and fails before shared props" do
    plug = read("tamandua_server_web/plugs/resolve_inertia_tenant.ex")

    assert plug =~ "current_user.organization_id"
    refute plug =~ "get_req_header"
    refute plug =~ "get_session"
    refute plug =~ "conn.params"
    refute plug =~ "current_organization_id]"
    assert plug =~ "send_resp(:forbidden, \"Forbidden\")"
    assert plug =~ "|> halt()"
    refute plug =~ "InertiaSharedData"
    refute plug =~ "socket_token"
  end

  test "account proof is an exact active user and active organization join under MultiTenant" do
    accounts = read("tamandua_server/accounts.ex")

    assert accounts =~ "Ecto.UUID.cast(user_id)"
    assert accounts =~ "Ecto.UUID.cast(organization_id)"
    assert accounts =~ "MultiTenant.with_organization(canonical_organization_id"
    assert accounts =~ "organization.id == u.organization_id"
    assert accounts =~ "organization.id == ^canonical_organization_id"
    assert accounts =~ "organization.is_active == true"
    assert accounts =~ "u.id == ^canonical_user_id"
    assert accounts =~ "u.organization_id == ^canonical_organization_id"
    assert accounts =~ "u.is_active == true"
    refute accounts =~ "SetOrganizationContext"
  end

  test "ShadowAI retains actor equality and wraps authorization plus reads in one tenant transaction" do
    controller = read("tamandua_server_web/controllers/inertia_controller.ex")

    shadow =
      controller |> String.split("def shadow_ai(conn, _params) do", parts: 2) |> List.last()

    actor = index!(shadow, "ResponseActor.from_user_scope")
    transaction = index!(shadow, "MultiTenant.with_organization(organization_id")
    authorization = index!(shadow, "authorize_or_render_inertia_page")
    reads = index!(shadow, "shadow_ai_for_organization")

    assert actor < transaction
    assert transaction < authorization
    assert authorization < reads
    assert shadow =~ "[:ai_investigate]"
    assert shadow =~ "forbidden_inertia_page(conn)"
  end

  test "permission and role caches bind user and organization and global roles are builtin only" do
    rbac = read("tamandua_server/authorization/rbac.ex")
    accounts = read("tamandua_server/accounts.ex")

    assert length(Regex.scan(~r/cache_key = \{user_id, organization_id\}/, rbac)) >= 4
    assert rbac =~ "invalidate_user_entries(@cache_table, user_id)"
    assert rbac =~ "invalidate_user_entries(@role_cache_table, user_id)"
    assert rbac =~ "r.builtin == true and is_nil(r.organization_id)"
    assert rbac =~ "r.organization_id == ^org_id"
    assert length(Regex.scan(~r/RBAC\.invalidate_cache\(/, accounts)) >= 2
  end

  defp index!(text, needle, occurrence \\ 1) do
    text
    |> :binary.matches(needle)
    |> Enum.at(occurrence - 1)
    |> case do
      {index, _length} -> index
      nil -> flunk("missing occurrence #{occurrence} of #{inspect(needle)}")
    end
  end
end
