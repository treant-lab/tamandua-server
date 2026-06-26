defmodule TamanduaServer.Accounts.PermissionRoleAppGuardResearchTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Accounts.{Permission, Role}

  describe "App Guard and research permissions" do
    test "valid_permission?/1 accepts App Guard and research slugs" do
      assert Permission.valid_permission?(:app_guard_apps_read)
      assert Permission.valid_permission?(:app_guard_events_ingest)
      assert Permission.valid_permission?(:app_guard_policy_update)

      assert Permission.valid_permission?(:research_programs_read)
      assert Permission.valid_permission?(:research_submissions_validate)
      assert Permission.valid_permission?(:research_rewards_manage)
    end

    test "permissions_for_category/1 includes App Guard slugs" do
      assert_permissions_include(Permission.permissions_for_category(:app_guard), [
        :app_guard_apps_read,
        :app_guard_apps_create,
        :app_guard_apps_update,
        :app_guard_builds_read,
        :app_guard_events_read,
        :app_guard_events_ingest,
        :app_guard_policy_read,
        :app_guard_policy_update
      ])
    end

    test "permissions_for_category/1 includes research slugs" do
      assert_permissions_include(Permission.permissions_for_category(:research), [
        :research_programs_read,
        :research_programs_create,
        :research_programs_update,
        :research_submissions_read,
        :research_submissions_create,
        :research_submissions_validate,
        :research_rewards_manage
      ])
    end
  end

  describe "default role permissions" do
    test "analyst includes App Guard and research review permissions" do
      assert_permissions_include(Role.default_permissions(:analyst), [
        :app_guard_apps_read,
        :app_guard_builds_read,
        :app_guard_events_read,
        :research_programs_read,
        :research_submissions_read,
        :research_submissions_validate
      ])
    end

    test "viewer includes read-only App Guard and research permissions" do
      assert_permissions_include(Role.default_permissions(:viewer), [
        :app_guard_apps_read,
        :app_guard_events_read,
        :research_programs_read
      ])
    end

    test "manager includes App Guard and research ownership permissions" do
      assert_permissions_include(Role.default_permissions(:manager), [
        :app_guard_apps_create,
        :app_guard_apps_update,
        :app_guard_policy_read,
        :app_guard_policy_update,
        :research_programs_create,
        :research_programs_update,
        :research_submissions_validate,
        :research_rewards_manage
      ])
    end

    test "api_only includes ingest and submission permissions" do
      assert_permissions_include(Role.default_permissions(:api_only), [
        :app_guard_events_ingest,
        :research_submissions_create
      ])
    end
  end

  defp assert_permissions_include(actual_permissions, expected_permissions) do
    for permission <- expected_permissions do
      assert permission in actual_permissions
    end
  end
end
