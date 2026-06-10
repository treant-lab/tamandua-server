defmodule TamanduaServer.Authorization.AccessPolicy do
  @moduledoc """
  Schema for ABAC Access Policies.

  Access policies define fine-grained conditions for allowing or denying
  access to specific permissions. Policies support:

  - Time-based restrictions (business hours, time windows)
  - Location-based restrictions (IP CIDR ranges)
  - User attribute conditions
  - Device restrictions (trusted device lists)
  - MFA requirements

  ## Policy Structure

  ```
  %AccessPolicy{
    name: "Business Hours Response",
    organization_id: "org-uuid",
    permission: "response_execute",
    conditions: %{
      time_restriction: %{
        type: "business_hours",
        timezone: "America/New_York",
        start_hour: 9,
        end_hour: 17,
        days: [1, 2, 3, 4, 5]
      },
      ip_restriction: %{
        type: "cidr",
        allowed: ["10.0.0.0/8", "192.168.0.0/16"]
      },
      require_mfa: true
    },
    effect: :allow,
    priority: 100,
    is_active: true
  }
  ```

  ## Evaluation Order

  Policies are evaluated in priority order (highest first). The first
  policy whose conditions match determines the access decision. If no
  policies match, access is allowed (default RBAC behavior applies).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, Role}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @effects [:allow, :deny]

  @derive {Jason.Encoder, only: [
    :id, :name, :description, :permission, :conditions,
    :effect, :priority, :is_active, :organization_id,
    :applies_to_roles, :inserted_at, :updated_at
  ]}

  schema "access_policies" do
    field :name, :string
    field :description, :string
    field :permission, :string  # "*" for all permissions, or specific permission slug
    field :conditions, :map, default: %{}
    field :effect, Ecto.Enum, values: @effects, default: :allow
    field :priority, :integer, default: 50
    field :is_active, :boolean, default: true

    # Optional: restrict policy to specific roles
    field :applies_to_roles, {:array, :string}, default: []

    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name permission effect)a
  @optional_fields ~w(description conditions priority is_active organization_id applies_to_roles)a

  @doc """
  Changeset for creating or updating an access policy.
  """
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:effect, @effects)
    |> validate_number(:priority, greater_than_or_equal_to: 0, less_than_or_equal_to: 1000)
    |> validate_conditions()
    |> unique_constraint([:organization_id, :name])
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_conditions(changeset) do
    case get_change(changeset, :conditions) do
      nil -> changeset
      conditions when is_map(conditions) ->
        changeset
        |> validate_time_restriction(conditions["time_restriction"])
        |> validate_ip_restriction(conditions["ip_restriction"])
        |> validate_device_restriction(conditions["device_restriction"])
        |> validate_user_attributes(conditions["user_attributes"])
      _ ->
        add_error(changeset, :conditions, "must be a map")
    end
  end

  defp validate_time_restriction(changeset, nil), do: changeset
  defp validate_time_restriction(changeset, %{"type" => "business_hours"} = config) do
    cond do
      is_integer(config["start_hour"]) and (config["start_hour"] < 0 or config["start_hour"] > 23) ->
        add_error(changeset, :conditions, "time_restriction.start_hour must be 0-23")

      is_integer(config["end_hour"]) and (config["end_hour"] < 0 or config["end_hour"] > 23) ->
        add_error(changeset, :conditions, "time_restriction.end_hour must be 0-23")

      is_list(config["days"]) and not Enum.all?(config["days"], &(&1 >= 1 and &1 <= 7)) ->
        add_error(changeset, :conditions, "time_restriction.days must be 1-7 (Monday-Sunday)")

      true ->
        changeset
    end
  end
  defp validate_time_restriction(changeset, %{"type" => "time_window"} = config) do
    with {:ok, _, _} <- DateTime.from_iso8601(config["start"] || ""),
         {:ok, _, _} <- DateTime.from_iso8601(config["end"] || "") do
      changeset
    else
      _ -> add_error(changeset, :conditions, "time_restriction start/end must be valid ISO8601 datetimes")
    end
  end
  defp validate_time_restriction(changeset, %{"type" => type}) do
    add_error(changeset, :conditions, "unknown time_restriction type: #{type}")
  end
  defp validate_time_restriction(changeset, _), do: changeset

  defp validate_ip_restriction(changeset, nil), do: changeset
  defp validate_ip_restriction(changeset, %{"type" => "cidr"} = config) do
    allowed = config["allowed"] || []
    blocked = config["blocked"] || []

    invalid_cidrs = (allowed ++ blocked)
    |> Enum.reject(&valid_cidr?/1)

    if Enum.empty?(invalid_cidrs) do
      changeset
    else
      add_error(changeset, :conditions, "invalid CIDR ranges: #{inspect(invalid_cidrs)}")
    end
  end
  defp validate_ip_restriction(changeset, _), do: changeset

  defp validate_device_restriction(changeset, nil), do: changeset
  defp validate_device_restriction(changeset, %{"trusted_devices" => devices}) when is_list(devices) do
    changeset
  end
  defp validate_device_restriction(changeset, _), do: changeset

  defp validate_user_attributes(changeset, nil), do: changeset
  defp validate_user_attributes(changeset, attrs) when is_map(attrs), do: changeset
  defp validate_user_attributes(changeset, _) do
    add_error(changeset, :conditions, "user_attributes must be a map")
  end

  defp valid_cidr?(cidr) when is_binary(cidr) do
    case String.split(cidr, "/") do
      [ip_str, prefix_str] ->
        case {:inet.parse_address(String.to_charlist(ip_str)), Integer.parse(prefix_str)} do
          {{:ok, {_, _, _, _}}, {prefix, ""}} when prefix >= 0 and prefix <= 32 -> true
          {{:ok, {_, _, _, _, _, _, _, _}}, {prefix, ""}} when prefix >= 0 and prefix <= 128 -> true
          _ -> false
        end

      [ip_str] ->
        case :inet.parse_address(String.to_charlist(ip_str)) do
          {:ok, _} -> true
          _ -> false
        end

      _ ->
        false
    end
  end
  defp valid_cidr?(_), do: false

  @doc """
  Returns the list of valid effects.
  """
  def effects, do: @effects

  @doc """
  Creates a business hours policy configuration.
  """
  def business_hours_config(opts \\ []) do
    %{
      "type" => "business_hours",
      "timezone" => Keyword.get(opts, :timezone, "UTC"),
      "start_hour" => Keyword.get(opts, :start_hour, 9),
      "end_hour" => Keyword.get(opts, :end_hour, 17),
      "days" => Keyword.get(opts, :days, [1, 2, 3, 4, 5])
    }
  end

  @doc """
  Creates a CIDR IP restriction configuration.
  """
  def ip_restriction_config(opts \\ []) do
    config = %{"type" => "cidr"}

    config = if allowed = Keyword.get(opts, :allowed) do
      Map.put(config, "allowed", allowed)
    else
      config
    end

    if blocked = Keyword.get(opts, :blocked) do
      Map.put(config, "blocked", blocked)
    else
      config
    end
  end

  @doc """
  Creates a time window restriction configuration.
  """
  def time_window_config(start_datetime, end_datetime) do
    %{
      "type" => "time_window",
      "start" => DateTime.to_iso8601(start_datetime),
      "end" => DateTime.to_iso8601(end_datetime)
    }
  end

  @doc """
  Creates a device restriction configuration.
  """
  def device_restriction_config(trusted_devices) when is_list(trusted_devices) do
    %{"trusted_devices" => trusted_devices}
  end
end
