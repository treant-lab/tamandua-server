defmodule TamanduaServerWeb.GraphQL.Resolvers.UserResolver do
  @moduledoc """
  GraphQL resolvers for User and Organization queries.
  """

  alias TamanduaServer.{Accounts, Agents, Repo}
  alias TamanduaServer.Alerts.Alert
  import Ecto.Query

  # Query resolvers

  def current_user(_parent, _args, %{context: context}) do
    user_id = context[:current_user_id]

    case user_id do
      nil -> {:error, "Not authenticated"}
      id -> {:ok, Accounts.get_user(id)}
    end
  end

  def get_user(_parent, %{id: id}, %{context: context}) do
    org_id = context[:organization_id]

    user = Accounts.get_user(id)

    cond do
      is_nil(org_id) ->
        {:error, "User not found"}

      user == nil ->
        {:error, "User not found"}

      user.organization_id != org_id ->
        {:error, "User not found"}

      true ->
        {:ok, user}
    end
  end

  def list_users(_parent, _args, %{context: context}) do
    case context[:organization_id] do
      nil ->
        # Fail-closed: this branch used to return ALL users across every
        # organization ("admin view") without any authorization check. Until
        # a real admin authorization path exists, refuse instead of leaking
        # the cross-tenant user list.
        {:error, "Not authorized"}

      org_id ->
        {:ok, Accounts.list_users(org_id)}
    end
  end

  def get_organization(_parent, %{id: id}, %{context: context}) do
    org_id = context[:organization_id]

    org = Accounts.get_organization(id)

    cond do
      is_nil(org_id) ->
        {:error, "Organization not found"}

      org == nil ->
        {:error, "Organization not found"}

      org.id != org_id ->
        {:error, "Organization not found"}

      true ->
        {:ok, org}
    end
  end

  def list_organizations(_parent, _args, %{context: context}) do
    user = context[:current_user_id] && Accounts.get_user(context[:current_user_id])

    if TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization.system_operator?(user) do
      {:ok, Accounts.list_organizations()}
    else
      {:error, "Not authorized"}
    end
  end

  # Field resolvers

  def organization(user, _args, %{context: context}) do
    if user.organization_id && user.organization_id == context[:organization_id] do
      {:ok, Accounts.get_organization(user.organization_id)}
    else
      {:ok, nil}
    end
  end

  def roles(user, _args, %{context: context}) do
    org_id = context[:organization_id]

    if org_id && user.organization_id == org_id do
      roles =
        user
        |> Accounts.get_user_roles()
        |> Enum.filter(&role_available_to_org?(&1, org_id))

      {:ok, roles}
    else
      {:ok, []}
    end
  rescue
    _ -> {:ok, []}
  end

  def permissions(user, _args, %{context: context}) do
    if user.organization_id == context[:organization_id] do
      permissions = Accounts.get_user_permissions(user)
      {:ok, MapSet.to_list(permissions)}
    else
      {:ok, []}
    end
  rescue
    _ -> {:ok, []}
  end

  def assigned_alerts(user, args, %{context: context}) do
    limit = args[:limit] || 20
    status = args[:status]
    org_id = context[:organization_id]

    if org_id && user.organization_id == org_id do
      query =
        from(a in Alert,
          where: a.assigned_to_id == ^user.id and a.organization_id == ^org_id,
          order_by: [desc: a.inserted_at],
          limit: ^limit
        )

      query = if status, do: where(query, [a], a.status == ^status), else: query

      {:ok, Repo.all(query)}
    else
      {:ok, []}
    end
  end

  def agent_count(organization, _args, %{context: context}) do
    if organization.id == context[:organization_id] do
      count = Agents.count_agents_for_org(organization.id)
      {:ok, count}
    else
      {:ok, 0}
    end
  end

  def organization_users(organization, _args, %{context: context}) do
    if organization.id == context[:organization_id] do
      users = Accounts.list_users(organization.id)
      {:ok, users}
    else
      {:ok, []}
    end
  end

  # Mutation resolvers

  def login(_parent, %{input: input}, _resolution) do
    email = input.email
    password = input.password
    totp_code = input[:totp_code]

    case Accounts.authenticate_user(email, password) do
      {:ok, user} ->
        if user.mfa_enabled do
          if totp_code do
            if Accounts.verify_totp(user.mfa_secret, totp_code) do
              generate_auth_result(user)
            else
              {:error, "Invalid MFA code"}
            end
          else
            {:ok,
             %{
               token: nil,
               user: nil,
               expires_at: nil,
               requires_mfa: true
             }}
          end
        else
          generate_auth_result(user)
        end

      {:error, :invalid_credentials} ->
        {:error, "Invalid email or password"}
    end
  end

  def create_user(_parent, %{input: input}, %{context: context}) do
    caller = context[:current_user_id] && Accounts.get_user(context[:current_user_id])

    case context[:organization_id] do
      nil ->
        {:error, "Not authorized"}

      org_id ->
        if Map.has_key?(input, :role) and
             (is_nil(caller) or not Accounts.user_can?(caller, :users_role_assign)) do
          {:error, "Insufficient permissions"}
        else
          attrs = Map.put(input, :organization_id, org_id)

          case Accounts.create_user(attrs) do
            {:ok, user} -> {:ok, user}
            {:error, changeset} -> {:error, format_errors(changeset)}
          end
        end
    end
  end

  def update_user(_parent, %{id: id, input: input}, %{context: context}) do
    org_id = context[:organization_id]
    caller = context[:current_user_id] && Accounts.get_user(context[:current_user_id])

    user = Accounts.get_user(id)

    cond do
      is_nil(org_id) ->
        {:error, "User not found"}

      user == nil ->
        {:error, "User not found"}

      user.organization_id != org_id ->
        {:error, "User not found"}

      Map.has_key?(input, :role) and
          (is_nil(caller) or not Accounts.user_can?(caller, :users_role_assign)) ->
        {:error, "Insufficient permissions"}

      true ->
        # The schema conditionally requires :users_role_assign whenever the
        # legacy role field is present. Mirror that check here so direct resolver
        # callers cannot widen the update surface.
        allowed_fields =
          if caller && Accounts.user_can?(caller, :users_role_assign) do
            [:name, :role, :mfa_enabled]
          else
            [:name, :mfa_enabled]
          end

        case Accounts.update_user(user, Map.take(input, allowed_fields)) do
          {:ok, updated} -> {:ok, updated}
          {:error, changeset} -> {:error, format_errors(changeset)}
        end
    end
  end

  def delete_user(_parent, %{id: id}, %{context: context}) do
    org_id = context[:organization_id]

    user = Accounts.get_user(id)

    cond do
      is_nil(org_id) ->
        {:ok, %{success: false, id: id, message: "User not found"}}

      user == nil ->
        {:ok, %{success: false, id: id, message: "User not found"}}

      user.organization_id != org_id ->
        {:ok, %{success: false, id: id, message: "User not found"}}

      true ->
        case Accounts.delete_user(user) do
          {:ok, _} -> {:ok, %{success: true, id: id, message: "User deleted"}}
          {:error, _} -> {:ok, %{success: false, id: id, message: "Failed to delete user"}}
        end
    end
  end

  def assign_role(_parent, %{user_id: user_id, role_id: role_id}, %{context: context}) do
    org_id = context[:organization_id]
    actor = context[:current_user_id] && Accounts.get_user(context[:current_user_id])
    user = Accounts.get_user(user_id)
    role = Accounts.get_role(role_id)

    cond do
      is_nil(org_id) or is_nil(actor) or actor.organization_id != org_id ->
        {:error, "User not found"}

      user == nil ->
        {:error, "User not found"}

      user.organization_id != org_id ->
        {:error, "User not found"}

      role == nil ->
        {:error, "Role not found"}

      not role_available_to_org?(role, org_id) ->
        {:error, "Role not found"}

      true ->
        case Accounts.assign_role_to_user(user, role, actor: actor) do
          {:ok, _} -> {:ok, Accounts.get_user_with_roles(user_id)}
          {:error, reason} -> {:error, inspect(reason)}
        end
    end
  end

  def revoke_role(_parent, %{user_id: user_id, role_id: role_id}, %{context: context}) do
    org_id = context[:organization_id]
    actor = context[:current_user_id] && Accounts.get_user(context[:current_user_id])
    user = Accounts.get_user(user_id)
    role = Accounts.get_role(role_id)

    cond do
      is_nil(org_id) or is_nil(actor) or actor.organization_id != org_id ->
        {:error, "User not found"}

      user == nil ->
        {:error, "User not found"}

      user.organization_id != org_id ->
        {:error, "User not found"}

      role == nil ->
        {:error, "Role not found"}

      not role_available_to_org?(role, org_id) ->
        {:error, "Role not found"}

      true ->
        case Accounts.revoke_role_from_user(user, role, actor: actor) do
          {:ok, _} -> {:ok, Accounts.get_user_with_roles(user_id)}
          {:error, reason} -> {:error, inspect(reason)}
        end
    end
  end

  # Private helpers

  defp role_available_to_org?(role, org_id) do
    role.organization_id == org_id || (is_nil(role.organization_id) && role.builtin == true)
  end

  defp generate_auth_result(user) do
    token = Accounts.generate_user_session_token(user)
    expires_at = DateTime.utc_now() |> DateTime.add(24 * 60 * 60, :second)

    Accounts.update_last_login(user)

    {:ok,
     %{
       token: token,
       user: user,
       expires_at: expires_at,
       requires_mfa: false
     }}
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
  end
end
