defmodule TamanduaServerWeb.FallbackController do
  @moduledoc """
  Translates controller action results into valid `Plug.Conn` responses.

  Handles various error tuples returned from controller actions and
  converts them into appropriate HTTP responses with JSON bodies.
  """
  use TamanduaServerWeb, :controller

  @doc """
  Handle Ecto changeset errors (validation failures).
  """
  def call(conn, {:error, %Ecto.Changeset{} = changeset}) do
    conn
    |> put_status(:unprocessable_entity)
    |> put_view(json: TamanduaServerWeb.ChangesetJSON)
    |> render(:error, changeset: changeset)
  end

  @doc """
  Handle not found errors.
  """
  def call(conn, {:error, :not_found}) do
    conn
    |> put_status(:not_found)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:"404")
  end

  @doc """
  Handle unauthorized errors (authentication required).
  """
  def call(conn, {:error, :unauthorized}) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:"401")
  end

  @doc """
  Handle forbidden errors (insufficient permissions).
  """
  def call(conn, {:error, :forbidden}) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:"403")
  end

  @doc """
  Handle agent-related errors.
  """
  def call(conn, {:error, :agent_not_found}) do
    conn
    |> put_status(:not_found)
    |> json(%{error: "Agent not found", code: "agent_not_found"})
  end

  def call(conn, {:error, :agent_offline}) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{error: "Agent is offline", code: "agent_offline"})
  end

  def call(conn, {:error, :agent_disconnected}) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{error: "Agent disconnected during operation", code: "agent_disconnected"})
  end

  @doc """
  Handle timeout errors.
  """
  def call(conn, {:error, :timeout}) do
    conn
    |> put_status(:gateway_timeout)
    |> json(%{error: "Operation timed out", code: "timeout"})
  end

  @doc """
  Handle required parameter errors.
  """
  def call(conn, {:error, :missing_required_param, key}) when is_binary(key) or is_atom(key) do
    conn
    |> put_status(:bad_request)
    |> json(%{
      error: "Missing required parameter",
      code: "missing_required_param",
      parameter: to_string(key)
    })
  end

  @doc """
  Handle validation errors with details.
  """
  def call(conn, {:error, :invalid_params, details}) when is_map(details) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Invalid parameters", code: "invalid_params", details: details})
  end

  def call(conn, {:error, :invalid_params}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Invalid parameters", code: "invalid_params"})
  end

  @doc """
  Handle rate limiting errors.
  """
  def call(conn, {:error, :rate_limited}) do
    conn
    |> put_status(:too_many_requests)
    |> json(%{error: "Rate limit exceeded", code: "rate_limited"})
  end

  @doc """
  Handle conflict errors (e.g., duplicate resources).
  """
  def call(conn, {:error, :conflict, message}) when is_binary(message) do
    conn
    |> put_status(:conflict)
    |> json(%{error: message, code: "conflict"})
  end

  def call(conn, {:error, :conflict}) do
    conn
    |> put_status(:conflict)
    |> json(%{error: "Resource conflict", code: "conflict"})
  end

  # Approval reconciliation is intentionally fail-closed, but malformed
  # evidence and concurrent terminal transitions are expected client/domain
  # outcomes rather than server faults. Keep messages generic so the API does
  # not disclose command or execution state.
  def call(conn, {:error, reason})
      when reason in [:invalid_evidence_ref, :invalid_reconciliation] do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Invalid reconciliation request", code: Atom.to_string(reason)})
  end

  def call(conn, {:error, reason})
      when reason in [:unauthorized_or_invalid_transition, :evidence_already_used] do
    conn
    |> put_status(:conflict)
    |> json(%{error: "Reconciliation conflict", code: Atom.to_string(reason)})
  end

  @doc """
  Handle service unavailable errors.
  """
  def call(conn, {:error, :service_unavailable, service}) when is_binary(service) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{error: "Service unavailable: #{service}", code: "service_unavailable"})
  end

  def call(conn, {:error, :service_unavailable}) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{error: "Service unavailable", code: "service_unavailable"})
  end

  def call(conn, {:error, :persistence_unavailable}) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{error: "Service unavailable", code: "persistence_unavailable"})
  end

  @doc """
  Handle generic string error messages.
  """
  def call(conn, {:error, message}) when is_binary(message) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: message})
  end

  @doc """
  Handle atom error codes not explicitly matched.
  """
  def call(conn, {:error, reason}) when is_atom(reason) do
    conn
    |> put_status(:internal_server_error)
    |> json(%{error: "An error occurred", code: Atom.to_string(reason)})
  end

  @doc """
  Handle errors with additional context.
  """
  def call(conn, {:error, reason, context}) when is_atom(reason) and is_map(context) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: humanize_error(reason), code: Atom.to_string(reason), context: context})
  end

  @doc """
  Catch-all for unexpected error formats.
  """
  def call(conn, {:error, reason}) do
    conn
    |> put_status(:internal_server_error)
    |> json(%{error: "An unexpected error occurred", details: inspect(reason)})
  end

  # Private helpers

  defp humanize_error(atom) do
    atom
    |> Atom.to_string()
    |> String.replace("_", " ")
    |> String.capitalize()
  end
end
