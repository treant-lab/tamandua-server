defmodule TamanduaServer.InsiderThreat.PeerGroupTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.InsiderThreat.{PeerGroup, PeerGroupMember}
  alias TamanduaServer.Accounts.{Organization, User}

  setup do
    org = insert(:organization)
    user1 = insert(:user, organization: org, role: "analyst")
    user2 = insert(:user, organization: org, role: "analyst")
    user3 = insert(:user, organization: org, role: "admin")

    {:ok, org: org, user1: user1, user2: user2, user3: user3}
  end

  describe "create/1" do
    test "creates a peer group", %{org: org} do
      attrs = %{
        name: "Analysts",
        description: "Security analysts",
        group_type: "role",
        organization_id: org.id
      }

      assert {:ok, peer_group} = PeerGroup.create(attrs)
      assert peer_group.name == "Analysts"
      assert peer_group.group_type == "role"
      assert peer_group.organization_id == org.id
    end

    test "requires name and group_type", %{org: org} do
      assert {:error, changeset} = PeerGroup.create(%{organization_id: org.id})
      assert "can't be blank" in errors_on(changeset).name
      assert "can't be blank" in errors_on(changeset).group_type
    end

    test "validates group_type inclusion" do
      assert {:error, changeset} =
               PeerGroup.create(%{
                 name: "Test",
                 group_type: "invalid",
                 organization_id: Ecto.UUID.generate()
               })

      assert "is invalid" in errors_on(changeset).group_type
    end
  end

  describe "add_member/2 and remove_member/2" do
    test "adds and removes members from peer group", %{org: org, user1: user1, user2: user2} do
      {:ok, peer_group} =
        PeerGroup.create(%{
          name: "Test Group",
          group_type: "manual",
          organization_id: org.id
        })

      # Add members
      assert {:ok, _member1} = PeerGroup.add_member(peer_group.id, user1.id)
      assert {:ok, _member2} = PeerGroup.add_member(peer_group.id, user2.id)

      # Verify members
      peer_group = PeerGroup.get(peer_group.id)
      user_ids = PeerGroup.get_user_ids(peer_group)
      assert user1.id in user_ids
      assert user2.id in user_ids

      # Remove member
      assert :ok = PeerGroup.remove_member(peer_group.id, user1.id)

      peer_group = PeerGroup.get(peer_group.id)
      user_ids = PeerGroup.get_user_ids(peer_group)
      refute user1.id in user_ids
      assert user2.id in user_ids
    end

    test "prevents duplicate members", %{org: org, user1: user1} do
      {:ok, peer_group} =
        PeerGroup.create(%{
          name: "Test Group",
          group_type: "manual",
          organization_id: org.id
        })

      assert {:ok, _member} = PeerGroup.add_member(peer_group.id, user1.id)
      assert {:error, _changeset} = PeerGroup.add_member(peer_group.id, user1.id)
    end
  end

  describe "is_outlier?/4" do
    test "detects outliers based on standard deviation", %{org: org} do
      {:ok, peer_group} =
        PeerGroup.create(%{
          name: "Test Group",
          group_type: "manual",
          organization_id: org.id,
          baseline: %{
            data_access: %{
              mean: 100.0,
              std_dev: 10.0
            }
          }
        })

      # Within 2 std dev (80-120) - not outlier
      refute PeerGroup.is_outlier?(peer_group, Ecto.UUID.generate(), :data_access, 110.0)
      refute PeerGroup.is_outlier?(peer_group, Ecto.UUID.generate(), :data_access, 90.0)

      # Beyond 2 std dev - outlier
      assert PeerGroup.is_outlier?(peer_group, Ecto.UUID.generate(), :data_access, 125.0)
      assert PeerGroup.is_outlier?(peer_group, Ecto.UUID.generate(), :data_access, 75.0)
    end
  end

  describe "calculate_deviation/3" do
    test "calculates standard deviation from baseline", %{org: org} do
      {:ok, peer_group} =
        PeerGroup.create(%{
          name: "Test Group",
          group_type: "manual",
          organization_id: org.id,
          baseline: %{
            data_access: %{
              mean: 100.0,
              std_dev: 10.0
            }
          }
        })

      # 1 std dev above mean
      assert PeerGroup.calculate_deviation(peer_group, :data_access, 110.0) == 1.0

      # 2 std dev below mean
      assert PeerGroup.calculate_deviation(peer_group, :data_access, 80.0) == -2.0

      # At mean
      assert PeerGroup.calculate_deviation(peer_group, :data_access, 100.0) == 0.0
    end
  end

  describe "list_by_organization/1" do
    test "lists all peer groups for an organization", %{org: org} do
      other_org = insert(:organization)

      {:ok, _pg1} =
        PeerGroup.create(%{name: "Group 1", group_type: "role", organization_id: org.id})

      {:ok, _pg2} =
        PeerGroup.create(%{name: "Group 2", group_type: "role", organization_id: org.id})

      {:ok, _pg3} =
        PeerGroup.create(%{
          name: "Group 3",
          group_type: "role",
          organization_id: other_org.id
        })

      groups = PeerGroup.list_by_organization(org.id)
      assert length(groups) == 2
      assert Enum.all?(groups, &(&1.organization_id == org.id))
    end
  end

  # Helper to insert test data
  defp insert(schema, attrs \\ %{}) do
    case schema do
      :organization ->
        %Organization{
          id: Ecto.UUID.generate(),
          name: "Test Org",
          slug: "test-org"
        }
        |> Organization.changeset(attrs)
        |> Repo.insert!()

      :user ->
        %User{
          id: Ecto.UUID.generate(),
          email: "user-#{System.unique_integer()}@example.com",
          password_hash: Bcrypt.hash_pwd_salt("password"),
          name: "Test User",
          role: "analyst",
          is_active: true
        }
        |> User.changeset(attrs)
        |> Repo.insert!()
    end
  end
end
