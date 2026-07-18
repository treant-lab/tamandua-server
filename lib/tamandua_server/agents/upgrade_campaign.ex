defmodule TamanduaServer.Agents.UpgradeCampaign do
  @moduledoc """
  Manages agent upgrade campaigns with rollout strategies.

  An upgrade campaign orchestrates:
  - Target agent selection
  - Rollout strategy execution
  - Health monitoring
  - Automatic rollback on failure
  - Progress tracking and reporting
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{RolloutStrategy}
  alias __MODULE__

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rollouts" do
    field :strategy, :string
    field :canary_percentage, :integer
    field :stages, {:array, :map}
    field :current_stage, :integer
    field :status, :string
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :rollback_reason, :string

    # Virtual fields for runtime data
    field :manual_approval_granted, :boolean, virtual: true, default: false
    field :progress_percentage, :float, virtual: true
    field :estimated_completion, :utc_datetime, virtual: true

    belongs_to :update_package, TamanduaServer.Agents.UpdatePackage
    belongs_to :organization, TamanduaServer.Accounts.Organization

    has_many :agent_updates, TamanduaServer.Agents.AgentUpdate, foreign_key: :rollout_id

    timestamps()
  end

  @doc false
  def changeset(campaign, attrs) do
    campaign
    |> cast(attrs, [
      :strategy,
      :canary_percentage,
      :stages,
      :current_stage,
      :status,
      :started_at,
      :completed_at,
      :rollback_reason,
      :update_package_id,
      :organization_id
    ])
    |> validate_required([:strategy, :update_package_id, :organization_id])
    |> validate_inclusion(:strategy, ["canary", "phased", "blue_green", "immediate"])
    |> validate_inclusion(:status, ["pending", "in_progress", "completed", "failed", "rolled_back"])
    |> foreign_key_constraint(:update_package_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Create a new upgrade campaign.
  """
  @spec create(map()) :: {:ok, UpgradeCampaign.t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    stages = RolloutStrategy.get_stage_config(attrs[:strategy] || "canary")

    %UpgradeCampaign{}
    |> changeset(Map.put(attrs, :stages, stages))
    |> put_change(:status, "pending")
    |> put_change(:current_stage, 0)
    |> Repo.insert()
  end

  @doc """
  Start an upgrade campaign.
  """
  @spec start(UpgradeCampaign.t()) :: {:ok, UpgradeCampaign.t()} | {:error, Ecto.Changeset.t()}
  def start(%UpgradeCampaign{} = campaign) do
    campaign
    |> changeset(%{status: "in_progress", started_at: DateTime.utc_now()})
    |> Repo.update()
  end

  @doc """
  Advance campaign to next stage.
  """
  @spec advance_stage(UpgradeCampaign.t()) ::
          {:ok, UpgradeCampaign.t()} | {:error, Ecto.Changeset.t() | atom()}
  def advance_stage(%UpgradeCampaign{} = campaign) do
    next_stage = campaign.current_stage + 1

    if next_stage >= length(campaign.stages) do
      # Campaign complete
      complete(campaign)
    else
      campaign
      |> changeset(%{current_stage: next_stage})
      |> Repo.update()
    end
  end

  @doc """
  Complete a campaign.
  """
  @spec complete(UpgradeCampaign.t()) :: {:ok, UpgradeCampaign.t()} | {:error, Ecto.Changeset.t()}
  def complete(%UpgradeCampaign{} = campaign) do
    campaign
    |> changeset(%{status: "completed", completed_at: DateTime.utc_now()})
    |> Repo.update()
  end

  @doc """
  Rollback a campaign.
  """
  @spec rollback(UpgradeCampaign.t(), String.t()) ::
          {:ok, UpgradeCampaign.t()} | {:error, Ecto.Changeset.t()}
  def rollback(%UpgradeCampaign{} = campaign, reason) do
    campaign
    |> changeset(%{
      status: "rolled_back",
      completed_at: DateTime.utc_now(),
      rollback_reason: reason
    })
    |> Repo.update()
  end

  @doc """
  Get campaign progress statistics.
  """
  @spec get_progress(UpgradeCampaign.t()) :: map()
  def get_progress(%UpgradeCampaign{} = campaign) do
    campaign = Repo.preload(campaign, :agent_updates)
    updates = campaign.agent_updates

    total = length(updates)

    status_counts = %{
      pending: Enum.count(updates, &(&1.status == "pending")),
      in_progress: Enum.count(updates, &(&1.status == "in_progress")),
      completed: Enum.count(updates, &(&1.status == "completed")),
      failed: Enum.count(updates, &(&1.status == "failed"))
    }

    success_rate =
      if total > 0 do
        Float.round(status_counts.completed / total * 100, 1)
      else
        0.0
      end

    failure_rate =
      if total > 0 do
        Float.round(status_counts.failed / total * 100, 1)
      else
        0.0
      end

    overall_percentage =
      if total > 0 do
        Float.round((status_counts.completed + status_counts.failed) / total * 100, 1)
      else
        0.0
      end

    %{
      total_agents: total,
      status_counts: status_counts,
      success_rate: success_rate,
      failure_rate: failure_rate,
      overall_percentage: overall_percentage,
      current_stage: campaign.current_stage,
      total_stages: length(campaign.stages),
      stage_name: get_current_stage_name(campaign),
      estimated_completion: estimate_completion_time(campaign, updates)
    }
  end

  @doc """
  List all campaigns for an organization.
  """
  @spec list_campaigns(binary(), keyword()) :: list(UpgradeCampaign.t())
  def list_campaigns(organization_id, opts \\ []) do
    UpgradeCampaign
    |> where([c], c.organization_id == ^organization_id)
    |> maybe_filter_status(opts[:status])
    |> maybe_filter_strategy(opts[:strategy])
    |> order_by([c], desc: c.inserted_at)
    |> limit(^Keyword.get(opts, :limit, 50))
    |> Repo.all()
    |> Repo.preload([:update_package, :agent_updates])
  end

  @doc """
  Get a campaign by ID.
  """
  @spec get_campaign(binary()) :: {:ok, UpgradeCampaign.t()} | {:error, :not_found}
  def get_campaign(campaign_id) do
    case Repo.get(UpgradeCampaign, campaign_id) do
      nil ->
        {:error, :not_found}

      campaign ->
        {:ok, Repo.preload(campaign, [:update_package, :agent_updates, :organization])}
    end
  end

  @doc """
  Check if campaign can advance to next stage.
  """
  @spec can_advance?(UpgradeCampaign.t()) :: {:ok, :advance} | {:error, atom()}
  def can_advance?(%UpgradeCampaign{} = campaign) do
    campaign = Repo.preload(campaign, :agent_updates)
    current_stage_config = Enum.at(campaign.stages, campaign.current_stage)

    RolloutStrategy.can_advance?(campaign, current_stage_config, campaign.agent_updates)
  end

  @doc """
  Check if campaign should be rolled back.
  """
  @spec should_rollback?(UpgradeCampaign.t()) :: {:rollback, String.t()} | :continue
  def should_rollback?(%UpgradeCampaign{} = campaign) do
    campaign = Repo.preload(campaign, :agent_updates)
    current_stage_config = Enum.at(campaign.stages, campaign.current_stage)

    RolloutStrategy.should_rollback?(campaign.agent_updates, current_stage_config)
  end

  @doc """
  Grant manual approval for advancing to next stage.
  """
  @spec grant_approval(UpgradeCampaign.t(), binary()) ::
          {:ok, UpgradeCampaign.t()} | {:error, Ecto.Changeset.t()}
  def grant_approval(%UpgradeCampaign{} = campaign, _user_id) do
    # In production, would store approval metadata
    # For now, just update campaign
    {:ok, %{campaign | manual_approval_granted: true}}
  end

  @doc """
  Cancel a pending or in-progress campaign.
  """
  @spec cancel(UpgradeCampaign.t()) :: {:ok, UpgradeCampaign.t()} | {:error, Ecto.Changeset.t()}
  def cancel(%UpgradeCampaign{} = campaign) do
    campaign
    |> changeset(%{status: "failed", completed_at: DateTime.utc_now()})
    |> Repo.update()
  end

  @doc """
  Get campaign health metrics.
  """
  @spec get_health_metrics(UpgradeCampaign.t()) :: map()
  def get_health_metrics(%UpgradeCampaign{} = campaign) do
    campaign = Repo.preload(campaign, :agent_updates)

    updates_by_status =
      campaign.agent_updates
      |> Enum.group_by(& &1.status)

    completed = Map.get(updates_by_status, "completed", [])
    failed = Map.get(updates_by_status, "failed", [])

    avg_duration =
      if length(completed) > 0 do
        durations =
          Enum.map(completed, fn u ->
            if u.started_at and u.completed_at do
              DateTime.diff(u.completed_at, u.started_at)
            else
              0
            end
          end)

        Enum.sum(durations) / length(durations)
      else
        0
      end

    error_types =
      failed
      |> Enum.map(& &1.error_message)
      |> Enum.reject(&is_nil/1)
      |> Enum.frequencies()

    %{
      avg_update_duration: avg_duration,
      success_count: length(completed),
      failure_count: length(failed),
      error_types: error_types,
      health_status: determine_health_status(campaign.agent_updates)
    }
  end

  # Private Functions

  defp maybe_filter_status(query, nil), do: query

  defp maybe_filter_status(query, status) do
    where(query, [c], c.status == ^status)
  end

  defp maybe_filter_strategy(query, nil), do: query

  defp maybe_filter_strategy(query, strategy) do
    where(query, [c], c.strategy == ^strategy)
  end

  defp get_current_stage_name(campaign) do
    stage = Enum.at(campaign.stages, campaign.current_stage)
    if stage, do: stage["name"] || stage[:name], else: "Unknown"
  end

  defp estimate_completion_time(campaign, updates) do
    completed_count = Enum.count(updates, &(&1.status == "completed"))

    completed_updates =
      updates
      |> Enum.filter(&(&1.status == "completed"))
      |> Enum.filter(&(&1.started_at && &1.completed_at))

    cond do
      campaign.status != "in_progress" ->
        nil

      length(updates) == 0 ->
        nil

      completed_count == 0 ->
        nil

      Enum.empty?(completed_updates) ->
        nil

      true ->
        avg_duration =
          completed_updates
          |> Enum.map(fn u -> DateTime.diff(u.completed_at, u.started_at) end)
          |> Enum.sum()
          |> Kernel./(length(completed_updates))

        remaining_count = length(updates) - completed_count
        estimated_seconds = remaining_count * avg_duration

        # Add wait time for remaining stages
        wait_time =
          campaign.stages
          |> Enum.drop(campaign.current_stage + 1)
          |> Enum.map(&(&1["wait_time"] || &1[:wait_time] || 0))
          |> Enum.sum()

        total_estimated_seconds = estimated_seconds + wait_time

        DateTime.add(DateTime.utc_now(), round(total_estimated_seconds), :second)
    end
  end

  defp determine_health_status(agent_updates) do
    total = length(agent_updates)

    if total == 0 do
      :unknown
    else
      failed = Enum.count(agent_updates, &(&1.status == "failed"))
      failure_rate = failed / total

      cond do
        failure_rate > 0.15 -> :critical
        failure_rate > 0.05 -> :degraded
        true -> :healthy
      end
    end
  end
end
