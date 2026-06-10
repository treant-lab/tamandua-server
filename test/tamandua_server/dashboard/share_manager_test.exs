defmodule TamanduaServer.Dashboard.ShareManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Dashboard
  alias TamanduaServer.Dashboard.{Share, ShareView}

  describe "share management" do
    setup do
      user = insert(:user)
      dashboard = insert(:dashboard_layout, user_id: user.id)

      %{user: user, dashboard: dashboard}
    end

    test "creates a share with valid attributes", %{user: user, dashboard: dashboard} do
      attrs = %{
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        share_type: "full_dashboard"
      }

      assert {:ok, share} = Dashboard.create_share(attrs)
      assert share.dashboard_layout_id == dashboard.id
      assert share.created_by_user_id == user.id
      assert share.share_type == "full_dashboard"
      assert share.share_token != nil
      assert share.is_active == true
    end

    test "creates a share with password protection", %{user: user, dashboard: dashboard} do
      attrs = %{
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        share_type: "full_dashboard",
        password: "secret123"
      }

      assert {:ok, share} = Dashboard.create_share(attrs)
      assert share.password_hash != nil
      assert Share.verify_password(share, "secret123") == true
      assert Share.verify_password(share, "wrong") == false
    end

    test "creates a share with expiry date", %{user: user, dashboard: dashboard} do
      expires_at = DateTime.add(DateTime.utc_now(), 7, :day)

      attrs = %{
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        share_type: "full_dashboard",
        expires_at: expires_at
      }

      assert {:ok, share} = Dashboard.create_share(attrs)
      assert share.expires_at != nil
      assert Share.accessible?(share) == true
    end

    test "creates a share with IP restrictions", %{user: user, dashboard: dashboard} do
      attrs = %{
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        share_type: "full_dashboard",
        allowed_ips: ["192.168.1.1", "10.0.0.1"]
      }

      assert {:ok, share} = Dashboard.create_share(attrs)
      assert Share.ip_allowed?(share, "192.168.1.1") == true
      assert Share.ip_allowed?(share, "1.2.3.4") == false
    end

    test "creates a share with domain restrictions", %{user: user, dashboard: dashboard} do
      attrs = %{
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        share_type: "full_dashboard",
        allowed_domains: ["example.com", "*.trusted.com"]
      }

      assert {:ok, share} = Dashboard.create_share(attrs)
      assert Share.domain_allowed?(share, "example.com") == true
      assert Share.domain_allowed?(share, "sub.trusted.com") == true
      assert Share.domain_allowed?(share, "untrusted.com") == false
    end

    test "validates specific_widgets requires widget_ids", %{user: user, dashboard: dashboard} do
      attrs = %{
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        share_type: "specific_widgets",
        widget_ids: []
      }

      assert {:error, changeset} = Dashboard.create_share(attrs)
      assert "must specify at least one widget" in errors_on(changeset).widget_ids
    end

    test "lists shares for a dashboard", %{user: user, dashboard: dashboard} do
      insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)
      insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)

      shares = Dashboard.list_shares_for_dashboard(dashboard.id)
      assert length(shares) == 2
    end

    test "lists shares by user", %{user: user, dashboard: dashboard} do
      insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)
      insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)

      shares = Dashboard.list_shares_by_user(user.id)
      assert length(shares) == 2
    end

    test "gets share by token", %{user: user, dashboard: dashboard} do
      share = insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)

      assert found_share = Dashboard.get_share_by_token(share.share_token)
      assert found_share.id == share.id
    end

    test "revokes a share", %{user: user, dashboard: dashboard} do
      share = insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)

      assert {:ok, revoked_share} = Dashboard.revoke_share(share)
      assert revoked_share.revoked_at != nil
      assert Share.accessible?(revoked_share) == false
    end

    test "toggles share active status", %{user: user, dashboard: dashboard} do
      share = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        is_active: true
      )

      assert {:ok, updated_share} = Dashboard.toggle_active(share)
      assert updated_share.is_active == false

      assert {:ok, updated_share} = Dashboard.toggle_active(updated_share)
      assert updated_share.is_active == true
    end

    test "regenerates share token", %{user: user, dashboard: dashboard} do
      share = insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)
      old_token = share.share_token

      assert {:ok, updated_share} = Dashboard.regenerate_token(share)
      assert updated_share.share_token != old_token
    end
  end

  describe "access validation" do
    setup do
      user = insert(:user)
      dashboard = insert(:dashboard_layout, user_id: user.id)

      share = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        is_active: true
      )

      %{user: user, dashboard: dashboard, share: share}
    end

    test "validates access for active share", %{share: share} do
      assert {:ok, _share} = Dashboard.validate_access(share.share_token)
    end

    test "rejects access for inactive share", %{share: share} do
      {:ok, inactive_share} = Dashboard.toggle_active(share)

      assert {:error, :not_accessible} = Dashboard.validate_access(inactive_share.share_token)
    end

    test "rejects access for revoked share", %{share: share} do
      {:ok, revoked_share} = Dashboard.revoke_share(share)

      assert {:error, :not_accessible} = Dashboard.validate_access(revoked_share.share_token)
    end

    test "rejects access for expired share", %{user: user, dashboard: dashboard} do
      expires_at = DateTime.add(DateTime.utc_now(), -1, :day)

      share = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        expires_at: expires_at
      )

      assert {:error, :not_accessible} = Dashboard.validate_access(share.share_token)
    end

    test "validates password when required", %{user: user, dashboard: dashboard} do
      share = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        password: "secret123"
      )

      assert {:error, :password_required} = Dashboard.validate_access(share.share_token)
      assert {:error, :invalid_password} = Dashboard.validate_access(share.share_token, password: "wrong")
      assert {:ok, _} = Dashboard.validate_access(share.share_token, password: "secret123")
    end

    test "validates IP restrictions", %{user: user, dashboard: dashboard} do
      share = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        allowed_ips: ["192.168.1.1"]
      )

      assert {:ok, _} = Dashboard.validate_access(share.share_token, ip_address: "192.168.1.1")
      assert {:error, :ip_not_allowed} = Dashboard.validate_access(share.share_token, ip_address: "1.2.3.4")
    end

    test "validates domain restrictions", %{user: user, dashboard: dashboard} do
      share = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        allowed_domains: ["example.com"]
      )

      assert {:ok, _} = Dashboard.validate_access(share.share_token, domain: "example.com")
      assert {:error, :domain_not_allowed} = Dashboard.validate_access(share.share_token, domain: "evil.com")
    end
  end

  describe "analytics" do
    setup do
      user = insert(:user)
      dashboard = insert(:dashboard_layout, user_id: user.id)

      share = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id
      )

      %{user: user, dashboard: dashboard, share: share}
    end

    test "records a view", %{share: share} do
      attrs = %{
        dashboard_share_id: share.id,
        viewed_at: DateTime.utc_now(),
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0"
      }

      assert {:ok, view} = Dashboard.record_view(share.id, attrs)
      assert view.dashboard_share_id == share.id
      assert view.ip_address == "192.168.1.1"
    end

    test "gets share analytics", %{share: share} do
      # Create some views
      for i <- 1..5 do
        insert(:share_view,
          dashboard_share_id: share.id,
          viewed_at: DateTime.utc_now(),
          session_id: "session_#{i}"
        )
      end

      analytics = Dashboard.get_share_analytics(share.id)

      assert analytics.total_views == 5
      assert analytics.unique_visitors == 5
    end

    test "gets user analytics", %{user: user, dashboard: dashboard, share: share} do
      # Create another share and views
      share2 = insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id
      )

      insert(:share_view, dashboard_share_id: share.id)
      insert(:share_view, dashboard_share_id: share2.id)
      insert(:share_view, dashboard_share_id: share2.id)

      analytics = Dashboard.get_user_analytics(user.id)

      assert analytics.total_shares == 2
      assert analytics.total_views == 3
    end

    test "tracks referrers", %{share: share} do
      insert(:share_view,
        dashboard_share_id: share.id,
        referrer: "https://google.com"
      )
      insert(:share_view,
        dashboard_share_id: share.id,
        referrer: "https://google.com"
      )
      insert(:share_view,
        dashboard_share_id: share.id,
        referrer: "https://twitter.com"
      )

      analytics = Dashboard.get_share_analytics(share.id)

      assert length(analytics.top_referrers) == 2
      google_ref = Enum.find(analytics.top_referrers, &(&1.referrer == "https://google.com"))
      assert google_ref.count == 2
    end
  end

  describe "bulk operations" do
    setup do
      user = insert(:user)
      dashboard = insert(:dashboard_layout, user_id: user.id)

      %{user: user, dashboard: dashboard}
    end

    test "revokes all shares for a dashboard", %{user: user, dashboard: dashboard} do
      insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)
      insert(:dashboard_share, dashboard_layout_id: dashboard.id, created_by_user_id: user.id)

      {count, _} = Dashboard.revoke_all_shares_for_dashboard(dashboard.id)
      assert count == 2

      shares = Dashboard.list_shares_for_dashboard(dashboard.id)
      assert Enum.all?(shares, fn share -> !is_nil(share.revoked_at) end)
    end

    test "cleans up expired shares", %{user: user, dashboard: dashboard} do
      # Create expired share
      expired = DateTime.add(DateTime.utc_now(), -1, :day)
      insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        expires_at: expired,
        is_active: true
      )

      # Create active share
      insert(:dashboard_share,
        dashboard_layout_id: dashboard.id,
        created_by_user_id: user.id,
        is_active: true
      )

      {count, _} = Dashboard.cleanup_expired_shares()
      assert count == 1
    end
  end
end
