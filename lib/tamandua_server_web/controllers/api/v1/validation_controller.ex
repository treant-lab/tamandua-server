defmodule TamanduaServerWeb.API.V1.ValidationController do
  @moduledoc """
  API Controller for EDR Validation and Testing

  Provides endpoints to run Atomic Red Team tests against connected agents
  and generate detection coverage reports.
  """

  use TamanduaServerWeb, :controller
  alias TamanduaServer.Validation.EDRTester

  @doc """
  GET /api/v1/validation/tests
  List all available Atomic Red Team tests
  """
  def list_tests(conn, _params) do
    case EDRTester.get_available_tests() do
      {:ok, tests} ->
        json(conn, %{success: true, tests: tests})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  POST /api/v1/validation/tests/:technique_id
  Run a specific test against an agent
  """
  def run_test(conn, %{"technique_id" => technique_id} = params) do
    agent_id = params["agent_id"]
    test_number = bounded_test_number(params["test_number"])
    simulate = params["simulate"] == "true" or params["simulate"] == true

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{success: false, error: "agent_id is required"})
    else
      case EDRTester.run_test(agent_id, technique_id, test_number, simulate: simulate) do
        {:ok, result} ->
          json(conn, %{success: true, result: result})

        {:error, :unknown_technique} ->
          conn
          |> put_status(:not_found)
          |> json(%{success: false, error: "Unknown technique: #{technique_id}"})

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{success: false, error: inspect(reason)})
      end
    end
  end

  @doc """
  POST /api/v1/validation/suite
  Run a full test suite against an agent
  """
  def run_suite(conn, params) do
    agent_id = params["agent_id"]
    dry_run = params["dry_run"] == "true" or params["dry_run"] == true
    categories = parse_categories(params["categories"])

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{success: false, error: "agent_id is required"})
    else
      opts = [dry_run: dry_run]
      opts = if categories, do: Keyword.put(opts, :categories, categories), else: opts

      case EDRTester.run_test_suite(agent_id, opts) do
        {:ok, results} ->
          json(conn, %{success: true, results: results.results, summary: results.summary})

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{success: false, error: inspect(reason)})
      end
    end
  end

  @doc """
  POST /api/v1/validation/tactic/:tactic
  Run tests for a specific MITRE tactic
  """
  def run_tactic(conn, %{"tactic" => tactic} = params) do
    agent_id = params["agent_id"]
    tactic_atom = parse_tactic(tactic)

    cond do
      is_nil(agent_id) ->
        conn
        |> put_status(:bad_request)
        |> json(%{success: false, error: "agent_id is required"})

      is_nil(tactic_atom) ->
        conn
        |> put_status(:bad_request)
        |> json(%{success: false, error: "Invalid tactic: #{tactic}"})

      true ->
        case EDRTester.run_tactic_tests(agent_id, tactic_atom) do
          {:ok, results} ->
            json(conn, %{success: true, tactic: tactic, results: results.results, summary: results.summary})

          {:error, reason} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{success: false, error: inspect(reason)})
        end
    end
  end

  @doc """
  GET /api/v1/validation/results/:agent_id
  Get test results for an agent
  """
  def get_results(conn, %{"agent_id" => agent_id}) do
    case EDRTester.get_results(agent_id) do
      {:ok, results} ->
        json(conn, %{success: true, agent_id: agent_id, results: results})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  GET /api/v1/validation/coverage/:agent_id
  Get coverage report for an agent
  """
  def coverage_report(conn, %{"agent_id" => agent_id}) do
    case EDRTester.get_coverage_report(agent_id) do
      {:ok, report} ->
        json(conn, %{success: true, report: report})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  GET /api/v1/validation/benchmark
  Get benchmark comparison with competitors
  """
  def benchmark(conn, _params) do
    case EDRTester.get_benchmark_comparison() do
      {:ok, comparison} ->
        json(conn, %{success: true, comparison: comparison})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  GET /api/v1/validation/gaps/:agent_id
  Get detection gaps and recommendations for an agent
  """
  def gaps(conn, %{"agent_id" => agent_id}) do
    case EDRTester.get_gaps_and_recommendations(agent_id) do
      {:ok, data} ->
        json(conn, %{success: true, gaps: data.gaps, recommendations: data.recommendations, coverage: data.coverage})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  GET /api/v1/validation/stats
  Get overall validation stats
  """
  def stats(conn, _params) do
    case EDRTester.get_stats() do
      {:ok, stats} ->
        json(conn, %{success: true, stats: stats})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  # Helper functions

  @allowed_validation_categories ~w(
    initial_access execution persistence privilege_escalation defense_evasion
    credential_access discovery lateral_movement collection command_control
    command_and_control exfiltration impact
  )

  defp parse_tactic(tactic), do: safe_to_existing_atom(tactic, @allowed_validation_categories)

  defp parse_categories(nil), do: nil
  defp parse_categories("all"), do: :all
  defp parse_categories(categories) when is_binary(categories) do
    categories
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&safe_to_existing_atom(&1, @allowed_validation_categories))
    |> Enum.reject(&is_nil/1)
    |> empty_to_nil()
  end
  defp parse_categories(categories) when is_list(categories) do
    categories
    |> Enum.map(fn c ->
      if is_binary(c), do: safe_to_existing_atom(c, @allowed_validation_categories), else: c
    end)
    |> Enum.reject(&is_nil/1)
    |> empty_to_nil()
  end
  defp parse_categories(_), do: nil

  defp empty_to_nil([]), do: nil
  defp empty_to_nil(values), do: values

  defp safe_to_existing_atom(value, allowed) when is_binary(value) and value in allowed do
    String.to_existing_atom(value)
  end
  defp safe_to_existing_atom(value, allowed) when is_atom(value) do
    if Atom.to_string(value) in allowed, do: value, else: nil
  end
  defp safe_to_existing_atom(_, _), do: nil

  defp bounded_test_number(value), do: value |> parse_int(1) |> max(1) |> min(100)

  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default
end
