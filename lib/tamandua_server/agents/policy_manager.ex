defmodule TamanduaServer.Agents.PolicyManager do
  @moduledoc """
  Business logic for managing agent policies.

  Handles policy creation, updates, inheritance, versioning, and assignment.
  """

  import Ecto.Query
  import Ecto.Changeset, only: [get_change: 2, put_change: 3]
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{
    CollectorCatalog,
    Policy,
    PolicyAssignment,
    PolicyGroupAssignment,
    PolicyHistory,
    Agent
  }

  @doc """
  Lists all policies for an organization.
  """
  def list_policies(organization_id, opts \\ []) do
    query =
      from p in Policy,
        where: p.organization_id == ^organization_id,
        order_by: [desc: p.updated_at],
        preload: [:parent_policy, :created_by, :updated_by]

    query =
      if opts[:status] do
        where(query, [p], p.status == ^opts[:status])
      else
        query
      end

    query =
      if opts[:scope] do
        where(query, [p], p.scope == ^opts[:scope])
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets a single policy by ID.
  """
  def get_policy(id) do
    Repo.get(Policy, id)
    |> Repo.preload([:parent_policy, :created_by, :updated_by, :group_assignments, :agent_assignments])
  end

  @doc """
  Gets a policy by name and organization.
  """
  def get_policy_by_name(organization_id, name) do
    Repo.get_by(Policy, organization_id: organization_id, name: name)
    |> Repo.preload([:parent_policy, :created_by, :updated_by])
  end

  @doc """
  Creates a new policy.
  """
  def create_policy(attrs, user_id) do
    attrs =
      attrs
      |> Map.put(:created_by_id, user_id)
      |> Map.put(:updated_by_id, user_id)

    %Policy{}
    |> Policy.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, policy} ->
        # Record history
        record_history(policy, "created", %{}, user_id)
        {:ok, policy}

      error ->
        error
    end
  end

  @doc """
  Creates a policy from a template.
  """
  def create_from_template(organization_id, template_name, attrs, user_id) do
    with {:ok, template_data} <- load_template(template_name) do
      policy_attrs =
        attrs
        |> Map.put(:organization_id, organization_id)
        |> Map.put(:template_name, template_name)
        |> Map.put(:policy_type, "template")
        |> Map.put(:policy_data, template_data)

      create_policy(policy_attrs, user_id)
    end
  end

  @doc """
  Updates a policy and creates a new version if status is active.
  """
  def update_policy(%Policy{} = policy, attrs, user_id) do
    old_data = policy.policy_data

    changeset =
      policy
      |> Policy.changeset(Map.put(attrs, :updated_by_id, user_id))

    # If policy is active and policy_data changed, increment version
    changeset =
      if policy.status == "active" and
           get_change(changeset, :policy_data) do
        put_change(changeset, :version, policy.version + 1)
      else
        changeset
      end

    Repo.update(changeset)
    |> case do
      {:ok, updated_policy} ->
        # Record history with diff
        new_data = updated_policy.policy_data
        diff = compute_diff(old_data, new_data)

        record_history(
          updated_policy,
          "updated",
          %{
            changes: attrs,
            diff: diff
          },
          user_id
        )

        {:ok, updated_policy}

      error ->
        error
    end
  end

  @doc """
  Activates a policy (changes status to active).
  """
  def activate_policy(%Policy{} = policy, user_id) do
    update_policy(policy, %{status: "active"}, user_id)
    |> case do
      {:ok, policy} ->
        record_history(policy, "activated", %{}, user_id)
        {:ok, policy}

      error ->
        error
    end
  end

  @doc """
  Deactivates a policy (changes status to inactive).
  """
  def deactivate_policy(%Policy{} = policy, user_id) do
    update_policy(policy, %{status: "inactive"}, user_id)
    |> case do
      {:ok, policy} ->
        record_history(policy, "deactivated", %{}, user_id)
        {:ok, policy}

      error ->
        error
    end
  end

  @doc """
  Deletes a policy.
  """
  def delete_policy(%Policy{} = policy) do
    Repo.delete(policy)
  end

  @doc """
  Assigns a policy to a group.
  """
  def assign_to_group(policy_id, group_id, opts \\ []) do
    attrs = %{
      policy_id: policy_id,
      group_id: group_id,
      overrides: opts[:overrides] || %{},
      priority: opts[:priority] || 0,
      assigned_by_id: opts[:assigned_by_id]
    }

    %PolicyGroupAssignment{}
    |> PolicyGroupAssignment.changeset(attrs)
    |> Repo.insert(on_conflict: :replace_all, conflict_target: [:policy_id, :group_id])
  end

  @doc """
  Assigns a policy to an agent.
  """
  def assign_to_agent(policy_id, agent_id, opts \\ []) do
    attrs = %{
      policy_id: policy_id,
      agent_id: agent_id,
      overrides: opts[:overrides] || %{},
      priority: opts[:priority] || 100,
      assigned_by_id: opts[:assigned_by_id]
    }

    %PolicyAssignment{}
    |> PolicyAssignment.changeset(attrs)
    |> Repo.insert(on_conflict: :replace_all, conflict_target: [:policy_id, :agent_id])
  end

  @doc """
  Removes a policy assignment from a group.
  """
  def unassign_from_group(policy_id, group_id) do
    from(a in PolicyGroupAssignment,
      where: a.policy_id == ^policy_id and a.group_id == ^group_id
    )
    |> Repo.delete_all()

    :ok
  end

  @doc """
  Removes a policy assignment from an agent.
  """
  def unassign_from_agent(policy_id, agent_id) do
    from(a in PolicyAssignment,
      where: a.policy_id == ^policy_id and a.agent_id == ^agent_id
    )
    |> Repo.delete_all()

    :ok
  end

  @doc """
  Computes the effective policy for an agent by merging organization, group, and agent policies.

  Policy inheritance order (higher priority overrides lower):
  1. Organization-level policy (lowest priority)
  2. Group-level policies (by priority)
  3. Agent-level policy (highest priority)
  """
  def compute_effective_policy(agent_id) do
    agent = Repo.get(Agent, agent_id) |> Repo.preload([:organization])

    if agent do
      # Get organization policy
      org_policy = get_organization_policy(agent.organization_id)

      # Get group policies
      group_policies = get_agent_group_policies(agent_id)

      # Get agent-specific policy
      agent_policy = get_agent_policy(agent_id)

      # Merge policies in order of precedence
      effective_policy =
        [org_policy | group_policies]
        |> Enum.concat([agent_policy])
        |> Enum.filter(& &1)
        |> merge_policies()

      {:ok, effective_policy}
    else
      {:error, :agent_not_found}
    end
  end

  @doc """
  Compares two policies and returns a diff.
  """
  def compare_policies(policy_id_1, policy_id_2) do
    policy_1 = get_policy(policy_id_1)
    policy_2 = get_policy(policy_id_2)

    if policy_1 && policy_2 do
      diff = compute_diff(policy_1.policy_data, policy_2.policy_data)
      {:ok, diff}
    else
      {:error, :policy_not_found}
    end
  end

  @doc """
  Simulates applying a policy to an agent without actually deploying it.
  """
  def simulate_policy(agent_id, policy_id) do
    agent = Repo.get(Agent, agent_id)
    policy = get_policy(policy_id)

    if agent && policy do
      # Get current effective policy
      {:ok, current_policy} = compute_effective_policy(agent_id)

      # Simulate new effective policy
      simulated_policy = Policy.merge_with_parent(policy)

      # Compare
      diff = compute_diff(current_policy, simulated_policy)

      {:ok,
       %{
         current: current_policy,
         simulated: simulated_policy,
         diff: diff
       }}
    else
      {:error, :not_found}
    end
  end

  @doc """
  Gets the policy history for a policy.
  """
  def get_policy_history(policy_id) do
    from(h in PolicyHistory,
      where: h.policy_id == ^policy_id,
      order_by: [desc: h.inserted_at],
      preload: [:changed_by]
    )
    |> Repo.all()
  end

  ## Private Functions

  defp get_organization_policy(organization_id) do
    from(p in Policy,
      where: p.organization_id == ^organization_id,
      where: p.scope == "organization",
      where: p.status == "active",
      order_by: [desc: p.version],
      limit: 1
    )
    |> Repo.one()
    |> case do
      nil -> nil
      policy -> policy.policy_data
    end
  end

  defp get_agent_group_policies(agent_id) do
    from(a in PolicyGroupAssignment,
      join: gm in "group_members", on: gm.group_id == a.group_id,
      join: p in Policy, on: p.id == a.policy_id,
      where: gm.agent_id == ^agent_id,
      where: p.status == "active",
      order_by: [asc: a.priority],
      select: %{policy: p.policy_data, overrides: a.overrides}
    )
    |> Repo.all()
    |> Enum.map(fn %{policy: policy, overrides: overrides} ->
      deep_merge(policy, overrides)
    end)
  end

  defp get_agent_policy(agent_id) do
    from(a in PolicyAssignment,
      join: p in Policy, on: p.id == a.policy_id,
      where: a.agent_id == ^agent_id,
      where: p.status == "active",
      order_by: [desc: a.priority],
      limit: 1,
      select: %{policy: p.policy_data, overrides: a.overrides}
    )
    |> Repo.one()
    |> case do
      nil -> nil
      %{policy: policy, overrides: overrides} -> deep_merge(policy, overrides)
    end
  end

  defp merge_policies([]), do: %{}
  defp merge_policies([policy]), do: policy

  defp merge_policies([base | rest]) do
    Enum.reduce(rest, base, &deep_merge(&2, &1))
  end

  defp deep_merge(left, right) when is_map(left) and is_map(right) do
    Map.merge(left, right, fn
      _k, v1, v2 when is_map(v1) and is_map(v2) -> deep_merge(v1, v2)
      _k, _v1, v2 -> v2
    end)
  end

  defp deep_merge(_left, right), do: right

  defp compute_diff(old_map, new_map) when is_map(old_map) and is_map(new_map) do
    all_keys = Map.keys(old_map) ++ Map.keys(new_map) |> Enum.uniq()

    Enum.reduce(all_keys, %{}, fn key, acc ->
      old_val = Map.get(old_map, key)
      new_val = Map.get(new_map, key)

      cond do
        old_val == new_val ->
          acc

        is_map(old_val) and is_map(new_val) ->
          nested_diff = compute_diff(old_val, new_val)

          if nested_diff == %{} do
            acc
          else
            Map.put(acc, key, nested_diff)
          end

        true ->
          Map.put(acc, key, %{old: old_val, new: new_val})
      end
    end)
  end

  defp compute_diff(old_val, new_val) do
    if old_val == new_val do
      %{}
    else
      %{old: old_val, new: new_val}
    end
  end

  defp record_history(policy, change_type, changes, user_id) do
    attrs = %{
      policy_id: policy.id,
      version: policy.version,
      previous_version: if(policy.version > 1, do: policy.version - 1),
      change_type: change_type,
      changes: changes,
      diff: changes[:diff] || %{},
      changed_by_id: user_id
    }

    %PolicyHistory{}
    |> PolicyHistory.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, _history} -> :ok
      {:error, reason} -> Logger.error("Failed to record policy history: #{inspect(reason)}")
    end
  end

  defp load_template(template_name) do
    if template_name in Policy.available_templates() do
      {:ok, CollectorCatalog.default_template(template_name)}
    else
      {:error, :template_not_found}
    end
  end

  defp baseline_template do
    %{
      "collectors" => %{
        "process" => %{"enabled" => true, "interval_ms" => 5000},
        "file" => %{"enabled" => true, "interval_ms" => 30000},
        "network" => %{"enabled" => true, "interval_ms" => 10000},
        "dns" => %{"enabled" => true, "interval_ms" => 10000},
        "registry" => %{"enabled" => false, "interval_ms" => 60000}
      },
      "resource_limits" => %{
        "max_cpu_percent" => 10,
        "max_memory_mb" => 500,
        "max_disk_mb" => 1000
      },
      "detection" => %{
        "yara_enabled" => true,
        "sigma_enabled" => true,
        "ml_enabled" => true,
        "custom_rules" => []
      },
      "response" => %{
        "allowed_actions" => ["isolate", "kill_process"],
        "auto_response_enabled" => false,
        "max_actions_per_hour" => 10
      },
      "network" => %{
        "allowed_domains" => [],
        "blocked_domains" => [],
        "proxy_enabled" => false
      }
    }
  end

  defp high_security_template do
    %{
      "collectors" => %{
        "process" => %{"enabled" => true, "interval_ms" => 2000},
        "file" => %{"enabled" => true, "interval_ms" => 5000},
        "network" => %{"enabled" => true, "interval_ms" => 2000},
        "dns" => %{"enabled" => true, "interval_ms" => 2000},
        "registry" => %{"enabled" => true, "interval_ms" => 10000},
        "kernel_events" => %{"enabled" => true, "interval_ms" => 1000}
      },
      "resource_limits" => %{
        "max_cpu_percent" => 25,
        "max_memory_mb" => 1024,
        "max_disk_mb" => 5000
      },
      "detection" => %{
        "yara_enabled" => true,
        "sigma_enabled" => true,
        "ml_enabled" => true,
        "custom_rules" => []
      },
      "response" => %{
        "allowed_actions" => ["isolate", "kill_process", "quarantine"],
        "auto_response_enabled" => true,
        "max_actions_per_hour" => 50
      },
      "network" => %{
        "allowed_domains" => [],
        "blocked_domains" => [],
        "proxy_enabled" => true
      }
    }
  end

  defp performance_template do
    %{
      "collectors" => %{
        "process" => %{"enabled" => true, "interval_ms" => 15000},
        "file" => %{"enabled" => false, "interval_ms" => 60000},
        "network" => %{"enabled" => true, "interval_ms" => 30000},
        "dns" => %{"enabled" => false, "interval_ms" => 60000},
        "registry" => %{"enabled" => false, "interval_ms" => 120000}
      },
      "resource_limits" => %{
        "max_cpu_percent" => 5,
        "max_memory_mb" => 256,
        "max_disk_mb" => 500
      },
      "detection" => %{
        "yara_enabled" => false,
        "sigma_enabled" => true,
        "ml_enabled" => false,
        "custom_rules" => []
      },
      "response" => %{
        "allowed_actions" => ["isolate"],
        "auto_response_enabled" => false,
        "max_actions_per_hour" => 5
      },
      "network" => %{
        "allowed_domains" => [],
        "blocked_domains" => [],
        "proxy_enabled" => false
      }
    }
  end

  defp forensics_template do
    %{
      "collectors" => %{
        "process" => %{"enabled" => true, "interval_ms" => 1000},
        "file" => %{"enabled" => true, "interval_ms" => 2000},
        "network" => %{"enabled" => true, "interval_ms" => 1000},
        "dns" => %{"enabled" => true, "interval_ms" => 1000},
        "registry" => %{"enabled" => true, "interval_ms" => 5000},
        "kernel_events" => %{"enabled" => true, "interval_ms" => 500}
      },
      "resource_limits" => %{
        "max_cpu_percent" => 50,
        "max_memory_mb" => 2048,
        "max_disk_mb" => 20000
      },
      "detection" => %{
        "yara_enabled" => true,
        "sigma_enabled" => true,
        "ml_enabled" => true,
        "custom_rules" => []
      },
      "response" => %{
        "allowed_actions" => ["isolate", "kill_process", "quarantine", "delete_file"],
        "auto_response_enabled" => false,
        "max_actions_per_hour" => 100
      },
      "network" => %{
        "allowed_domains" => [],
        "blocked_domains" => [],
        "proxy_enabled" => false
      }
    }
  end
end
