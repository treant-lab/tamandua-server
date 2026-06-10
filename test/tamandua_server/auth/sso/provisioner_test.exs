defmodule TamanduaServer.Auth.SSO.ProvisionerTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Auth.SSO.{Provisioner, SSOConfig}
  alias TamanduaServer.Accounts

  describe "provision_user/2" do
    setup do
      org = insert(:organization)

      config = %SSOConfig{
        organization_id: org.id,
        provider: :saml,
        enabled: true,
        jit_provisioning: true,
        default_role: "analyst",
        group_role_mappings: %{
          "Admins" => "admin",
          "Security Team" => "analyst",
          "Viewers" => "viewer"
        },
        allowed_domains: []
      }

      {:ok, config: config, org: org}
    end

    test "creates new user with JIT provisioning enabled", %{config: config} do
      attrs = %{
        email: "newuser@example.com",
        name: "New User",
        groups: ["Security Team"],
        provider_user_id: "user123"
      }

      assert {:ok, user} = Provisioner.provision_user(config, attrs)
      assert user.email == "newuser@example.com"
      assert user.name == "New User"
      assert user.role == "analyst"
      assert user.organization_id == config.organization_id
      assert user.is_active
    end

    test "assigns correct role based on group mapping", %{config: config} do
      attrs = %{
        email: "admin@example.com",
        name: "Admin User",
        groups: ["Admins"],
        provider_user_id: "admin123"
      }

      assert {:ok, user} = Provisioner.provision_user(config, attrs)
      assert user.role == "admin"
    end

    test "selects highest-priority role when user has multiple groups", %{config: config} do
      attrs = %{
        email: "multi@example.com",
        name: "Multi Group User",
        groups: ["Viewers", "Security Team", "Admins"],
        provider_user_id: "multi123"
      }

      # Admin has highest priority
      assert {:ok, user} = Provisioner.provision_user(config, attrs)
      assert user.role == "admin"
    end

    test "returns error when JIT provisioning is disabled", %{config: config} do
      config = %{config | jit_provisioning: false}

      attrs = %{
        email: "newuser@example.com",
        name: "New User",
        groups: [],
        provider_user_id: "user123"
      }

      assert {:error, :jit_provisioning_disabled} = Provisioner.create_user_from_sso(config, attrs)
    end

    test "enforces domain restrictions", %{config: config} do
      config = %{config | allowed_domains: ["example.com", "company.com"]}

      # Allowed domain
      attrs_ok = %{
        email: "user@example.com",
        name: "User",
        groups: [],
        provider_user_id: "user123"
      }

      assert {:ok, _user} = Provisioner.provision_user(config, attrs_ok)

      # Disallowed domain
      attrs_bad = %{
        email: "user@evil.com",
        name: "User",
        groups: [],
        provider_user_id: "user456"
      }

      assert {:error, :domain_not_allowed} = Provisioner.provision_user(config, attrs_bad)
    end

    test "updates existing user attributes", %{config: config} do
      # Create initial user
      {:ok, user} =
        Accounts.create_user(%{
          email: "existing@example.com",
          name: "Old Name",
          organization_id: config.organization_id,
          password_hash: "hash",
          role: "viewer"
        })

      # Update via SSO
      attrs = %{
        email: "existing@example.com",
        name: "New Name",
        groups: ["Admins"],
        provider_user_id: "user789"
      }

      assert {:ok, updated_user} = Provisioner.provision_user(config, attrs)
      assert updated_user.name == "New Name"
      assert updated_user.role == "admin"
    end

    test "returns error when user belongs to different org", %{config: config} do
      other_org = insert(:organization)

      {:ok, user} =
        Accounts.create_user(%{
          email: "other@example.com",
          name: "Other User",
          organization_id: other_org.id,
          password_hash: "hash",
          role: "analyst"
        })

      attrs = %{
        email: "other@example.com",
        name: "Other User",
        groups: [],
        provider_user_id: "user999"
      }

      assert {:error, :user_belongs_to_different_org} = Provisioner.provision_user(config, attrs)
    end
  end

  describe "deprovision_user/2" do
    test "disables user account" do
      org = insert(:organization)

      {:ok, user} =
        Accounts.create_user(%{
          email: "user@example.com",
          name: "User",
          organization_id: org.id,
          password_hash: "hash",
          role: "analyst",
          is_active: true
        })

      assert user.is_active

      assert :ok = Provisioner.deprovision_user(user, "Removed from IdP")

      updated_user = Accounts.get_user(user.id)
      refute updated_user.is_active
    end
  end

  describe "map_groups_to_role/2" do
    test "returns default role when no groups match" do
      config = %SSOConfig{
        default_role: "viewer",
        group_role_mappings: %{"Admins" => "admin"}
      }

      assert "viewer" = Provisioner.map_groups_to_role(config, ["Unknown Group"])
    end

    test "returns analyst when default_role is nil" do
      config = %SSOConfig{
        default_role: nil,
        group_role_mappings: %{}
      }

      assert "analyst" = Provisioner.map_groups_to_role(config, [])
    end

    test "prioritizes admin over analyst" do
      config = %SSOConfig{
        default_role: "viewer",
        group_role_mappings: %{
          "Admins" => "admin",
          "Analysts" => "analyst"
        }
      }

      assert "admin" = Provisioner.map_groups_to_role(config, ["Analysts", "Admins"])
    end
  end

  describe "validate_sso_attributes/1" do
    test "validates presence of email" do
      assert {:error, :missing_email} = Provisioner.validate_sso_attributes(%{})
      assert {:error, :missing_email} = Provisioner.validate_sso_attributes(%{name: "User"})
      assert :ok = Provisioner.validate_sso_attributes(%{email: "user@example.com"})
    end
  end
end
