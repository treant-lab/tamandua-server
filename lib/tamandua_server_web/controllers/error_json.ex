defmodule TamanduaServerWeb.ErrorJSON do
  @moduledoc """
  JSON error responses for API endpoints.
  """

  @doc """
  Renders a 400 Bad Request error.
  """
  def render("400.json", _assigns) do
    %{error: "bad_request", message: "Bad request"}
  end

  @doc """
  Renders a 401 Unauthorized error.
  """
  def render("401.json", _assigns) do
    %{error: "unauthorized", message: "Authentication required"}
  end

  @doc """
  Renders a 403 Forbidden error.
  """
  def render("403.json", _assigns) do
    %{error: "forbidden", message: "You don't have permission to perform this action"}
  end

  @doc """
  Renders a 404 Not Found error.
  """
  def render("404.json", _assigns) do
    %{error: "not_found", message: "Resource not found"}
  end

  @doc """
  Renders a 422 Unprocessable Entity error.
  """
  def render("422.json", _assigns) do
    %{error: "unprocessable_entity", message: "Unable to process request"}
  end

  @doc """
  Renders a 500 Internal Server Error.
  """
  def render("500.json", _assigns) do
    %{error: "internal_server_error", message: "An unexpected error occurred"}
  end

  @doc """
  Renders custom error with details.
  """
  def error(%{error: error, message: message} = assigns) do
    response = %{error: error, message: message}

    if Map.has_key?(assigns, :required_permission) do
      Map.put(response, :required_permission, assigns.required_permission)
    else
      response
    end
  end

  def error(%{error: error}) do
    %{error: error}
  end

  # Catch-all for template rendering
  def render(template, _assigns) do
    %{error: Phoenix.Controller.status_message_from_template(template)}
  end
end
