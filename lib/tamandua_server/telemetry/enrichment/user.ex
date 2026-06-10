defmodule TamanduaServer.Telemetry.Enrichment.User do
  @moduledoc """
  Enriches telemetry events with user context information.

  Adds user information when events contain usernames:
  - Email address
  - Department
  - Role/privileges
  - User risk score

  Enrichment is added to the event under the :enrichment.user key.
  """

  require Logger
  alias TamanduaServer.Telemetry.Enrichment.Cache

  @doc """
  Enrich an event with user context.

  Extracts username from event payload and looks up user metadata.

  ## Examples

      iex> enrich_event(%{payload: %{"user" => "jsmith"}, event_type: "process_create"})
      %{payload: %{"user" => "jsmith"}, enrichment: %{user: %{email: "jsmith@example.com", ...}}}
  """
  @spec enrich_event(map()) :: map()
  def enrich_event(event) do
    username = extract_username(event)

    if username do
      case Cache.get_or_lookup_user(username) do
        {:ok, user_info} ->
          enrichment = Map.get(event, :enrichment, %{})
          enrichment = Map.put(enrichment, :user, user_info)
          Map.put(event, :enrichment, enrichment)

        {:error, _reason} ->
          # User not found or lookup failed, return event unchanged
          event
      end
    else
      event
    end
  end

  # ──────────────────────────────────────────────────────────────────
  # Username Extraction
  # ──────────────────────────────────────────────────────────────────

  defp extract_username(event) do
    payload = event[:payload] || event["payload"] || %{}

    # Try common username fields
    get_in(payload, ["user"]) ||
      get_in(payload, [:user]) ||
      get_in(payload, ["username"]) ||
      get_in(payload, [:username]) ||
      get_in(payload, ["user_name"]) ||
      get_in(payload, [:user_name]) ||
      get_in(payload, ["account_name"]) ||
      get_in(payload, [:account_name])
  end
end
