defmodule TamanduaServer.LiveResponse.ScreenCaptureAdmission do
  @moduledoc """
  Server-owned admission authority for screen-capture policy evidence.

  Single-scope policy evidence remains observable during the compatibility
  window. Multi-scope evidence is emitted only when the current authenticated
  desktop socket and its freshly observed local broker both negotiate the exact
  lexical policy-v2 hash algorithm. The policy is never narrowed as fallback.
  """

  alias TamanduaServer.Agents.{Agent, Registry}
  alias TamanduaServer.LiveResponse.{ScreenCapturePolicy, ScreenSessionBroker}

  @runtime_max_age_ms :timer.seconds(90)
  @algorithm "screen_capture_policy_hash_sha256_lexical_v2"
  @allowed_scopes ~w(active_window monitor virtual_desktop)

  @type denial_reason ::
          :runtime_snapshot_unavailable
          | :runtime_tenant_mismatch
          | :runtime_connection_mismatch
          | :runtime_snapshot_stale
          | :runtime_snapshot_from_future
          | :invalid_policy_scope_evidence
          | :agent_policy_hash_algorithm_not_negotiated
          | :broker_not_ready
          | :broker_policy_hash_algorithm_not_negotiated
          | :policy_hash_algorithm_missing

  @spec authorize(Agent.t() | map(), String.t(), map(), map()) ::
          :ok | {:error, {:screen_capture_admission_denied, denial_reason()}}
  def authorize(_agent, _organization_id, %{kind: :mobile}, _policy), do: :ok

  def authorize(agent, organization_id, %{kind: :desktop}, policy) do
    if Registry.canonical_organization_id?(organization_id) do
      case scope_count(policy) do
        {:ok, 1} -> :ok
        {:ok, count} when count > 1 -> authorize_multi_scope(agent, organization_id, policy)
        :error -> deny(:invalid_policy_scope_evidence)
      end
    else
      deny(:runtime_tenant_mismatch)
    end
  end

  def authorize(_agent, _organization_id, _delivery, _policy),
    do: deny(:runtime_snapshot_unavailable)

  def algorithm, do: @algorithm
  def runtime_max_age_ms, do: @runtime_max_age_ms

  defp authorize_multi_scope(agent, organization_id, policy) do
    with :ok <- policy_algorithm(policy),
         {:ok, runtime} <- Registry.get(agent_id(agent)),
         {:ok, snapshot} <- current_snapshot(runtime, organization_id),
         :ok <- fresh_snapshot(snapshot),
         :ok <- agent_algorithm(snapshot),
         {:ok, broker} <- broker_status(agent, snapshot),
         :ok <- broker_ready(broker),
         :ok <- broker_algorithm(broker) do
      :ok
    else
      {:error, {:screen_capture_admission_denied, _reason}} = error -> error
      {:error, :not_found} -> deny(:runtime_snapshot_unavailable)
    end
  end

  defp current_snapshot(runtime, organization_id) do
    snapshot = runtime[:runtime_snapshot]

    cond do
      not is_map(snapshot) ->
        deny(:runtime_snapshot_unavailable)

      not Registry.same_canonical_organization_id?(
        runtime[:organization_id],
        organization_id
      ) or
          not Registry.same_canonical_organization_id?(
            snapshot[:organization_id],
            organization_id
          ) ->
        deny(:runtime_tenant_mismatch)

      snapshot[:socket_pid] != runtime[:socket_pid] or
        snapshot[:worker_pid] != runtime[:worker_pid] or
          snapshot[:connection_epoch] != runtime[:connection_epoch] ->
        deny(:runtime_connection_mismatch)

      not live_pid?(snapshot[:socket_pid]) or not live_pid?(snapshot[:worker_pid]) ->
        deny(:runtime_connection_mismatch)

      true ->
        {:ok, snapshot}
    end
  end

  defp fresh_snapshot(%{server_received_monotonic_ms: received}) when is_integer(received) do
    age = System.monotonic_time(:millisecond) - received

    cond do
      age < 0 -> deny(:runtime_snapshot_from_future)
      age > @runtime_max_age_ms -> deny(:runtime_snapshot_stale)
      true -> :ok
    end
  end

  defp fresh_snapshot(_snapshot), do: deny(:runtime_snapshot_unavailable)

  defp policy_algorithm(policy) do
    if get_in(policy, [:policy, :hash_algorithm]) == ScreenCapturePolicy.hash_algorithm(),
      do: :ok,
      else: deny(:policy_hash_algorithm_missing)
  end

  defp agent_algorithm(snapshot) do
    if @algorithm in (snapshot[:capabilities] || []),
      do: :ok,
      else: deny(:agent_policy_hash_algorithm_not_negotiated)
  end

  defp broker_status(agent, snapshot) do
    case snapshot[:screen_session_broker] do
      broker when is_map(broker) ->
        {:ok, ScreenSessionBroker.status(agent_os(agent), %{"screen_session_broker" => broker})}

      _ ->
        deny(:broker_not_ready)
    end
  end

  defp broker_ready(%{ready: true}), do: :ok
  defp broker_ready(_broker), do: deny(:broker_not_ready)

  defp broker_algorithm(broker) do
    if @algorithm in (broker[:policy_hash_algorithms] || []),
      do: :ok,
      else: deny(:broker_policy_hash_algorithm_not_negotiated)
  end

  defp scope_count(%{allowed_scopes: scopes}) when is_list(scopes) do
    canonical = scopes |> Enum.uniq() |> Enum.sort()

    if scopes == canonical and Enum.all?(scopes, &(&1 in @allowed_scopes)),
      do: {:ok, length(scopes)},
      else: :error
  end

  defp scope_count(_policy), do: :error

  defp live_pid?(pid) when is_pid(pid), do: Process.alive?(pid)
  defp live_pid?(_pid), do: false

  defp agent_id(%{id: id}), do: id
  defp agent_os(%{os_type: os}), do: os

  defp deny(reason), do: {:error, {:screen_capture_admission_denied, reason}}
end
