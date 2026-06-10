defmodule TamanduaServer.Support.SLAConfig do
  @moduledoc """
  Enterprise SLA configuration by license tier and priority.

  ## SLA Tiers

  - **Enterprise**: Fastest response (15min P1, 1h P2)
  - **Pro**: Standard response (30min P1, 2h P2)
  - **Trial/Free**: Best-effort (no SLA guarantees)

  ## Priority Definitions

  - **P1 (Critical)**: System-wide outage, data breach, critical security
  - **P2 (High)**: Single-customer impact, degraded performance
  - **P3 (Medium)**: Non-urgent issues, feature requests
  - **P4 (Low)**: General questions, documentation requests

  ## Escalation

  Each priority level has an escalation ladder that automatically
  notifies higher tiers if SLA is breached:

  - **P1**: Manager (15min) → VP (30min) → CEO (60min)
  - **P2**: Manager (60min) → VP (240min)
  - **P3**: Manager (480min)
  - **P4**: No auto-escalation
  """

  # Response time in minutes, Resolution time in minutes
  @sla_matrix %{
    enterprise: %{
      p1: %{response: 15, resolution: 240},    # 15min / 4h
      p2: %{response: 60, resolution: 480},    # 1h / 8h
      p3: %{response: 240, resolution: 1440},  # 4h / 24h
      p4: %{response: 480, resolution: 2880}   # 8h / 48h
    },
    pro: %{
      p1: %{response: 30, resolution: 480},    # 30min / 8h
      p2: %{response: 120, resolution: 960},   # 2h / 16h
      p3: %{response: 480, resolution: 2880},  # 8h / 48h
      p4: %{response: 960, resolution: 4320}   # 16h / 72h
    },
    trial: %{
      p1: %{response: 240, resolution: 1440},  # 4h / 24h (best effort)
      p2: %{response: 480, resolution: 2880},  # 8h / 48h
      p3: %{response: 1440, resolution: 4320}, # 24h / 72h
      p4: %{response: 2880, resolution: 10080} # 48h / 7d
    }
  }

  @escalation_config %{
    p1: [
      %{after_minutes: 15, to: :engineering_manager, channels: [:pagerduty, :slack]},
      %{after_minutes: 30, to: :vp_engineering, channels: [:pagerduty, :slack, :email]},
      %{after_minutes: 60, to: :ceo, channels: [:phone, :email]}
    ],
    p2: [
      %{after_minutes: 60, to: :engineering_manager, channels: [:slack, :email]},
      %{after_minutes: 240, to: :vp_engineering, channels: [:slack, :email]}
    ],
    p3: [
      %{after_minutes: 480, to: :engineering_manager, channels: [:email]}
    ],
    p4: []  # No auto-escalation for P4
  }

  @doc """
  Get SLA configuration for a license tier and priority.

  ## Examples

      iex> SLAConfig.get_sla(:enterprise, :p1)
      %{response: 15, resolution: 240}

      iex> SLAConfig.get_sla(:pro, :p2)
      %{response: 120, resolution: 960}
  """
  def get_sla(tier, priority) when is_atom(tier) and is_atom(priority) do
    Map.get(@sla_matrix, tier, @sla_matrix.trial)
    |> Map.get(priority, %{response: 1440, resolution: 4320})
  end

  def get_sla(tier, priority) when is_binary(tier) and is_atom(priority) do
    tier_atom = String.to_existing_atom(tier)
    get_sla(tier_atom, priority)
  rescue
    ArgumentError -> get_sla(:trial, priority)
  end

  def get_sla(tier, priority) when is_atom(tier) and is_binary(priority) do
    priority_atom = String.to_existing_atom(priority)
    get_sla(tier, priority_atom)
  rescue
    ArgumentError -> get_sla(tier, :p3)
  end

  def get_sla(tier, priority) when is_binary(tier) and is_binary(priority) do
    tier_atom = String.to_existing_atom(tier)
    priority_atom = String.to_existing_atom(priority)
    get_sla(tier_atom, priority_atom)
  rescue
    ArgumentError -> get_sla(:trial, :p3)
  end

  @doc """
  Calculate SLA deadlines for a ticket.

  Returns {:ok, %{response_deadline: DateTime, resolution_deadline: DateTime}}

  ## Examples

      iex> SLAConfig.calculate_deadlines(:enterprise, :p1)
      {:ok, %{response_deadline: ~U[2026-04-15 10:15:00Z], resolution_deadline: ~U[2026-04-15 14:00:00Z]}}
  """
  def calculate_deadlines(tier, priority, created_at \\ DateTime.utc_now()) do
    sla = get_sla(tier, priority)

    {:ok, %{
      response_deadline: DateTime.add(created_at, sla.response * 60, :second),
      resolution_deadline: DateTime.add(created_at, sla.resolution * 60, :second)
    }}
  end

  @doc """
  Get escalation configuration for a priority level.

  ## Examples

      iex> SLAConfig.get_escalation_config(:p1)
      [%{after_minutes: 15, to: :engineering_manager, channels: [:pagerduty, :slack]}, ...]
  """
  def get_escalation_config(priority) when is_atom(priority) do
    Map.get(@escalation_config, priority, [])
  end

  def get_escalation_config(priority) when is_binary(priority) do
    priority_atom = String.to_existing_atom(priority)
    get_escalation_config(priority_atom)
  rescue
    ArgumentError -> []
  end

  @doc """
  Get all supported tiers.
  """
  def tiers, do: Map.keys(@sla_matrix)

  @doc """
  Get all priorities.
  """
  def priorities, do: ~w(p1 p2 p3 p4)a
end
