defmodule TamanduaServer.Integrations.WebhookParsers.Behaviour do
  @moduledoc """
  Behaviour for webhook parsers.

  Each integration-specific parser must implement the parse/2 callback.
  """

  @doc """
  Parse a webhook payload into a normalized format.

  ## Parameters

  - `payload` - The raw webhook payload (map)
  - `opts` - Additional options (e.g., headers, integration config)

  ## Returns

  - `{:ok, parsed}` - Successfully parsed webhook with normalized fields
  - `{:error, reason}` - Failed to parse webhook

  ## Normalized Format

  The parsed result should be a map with the following fields:

  - `:action_type` - The type of action (atom):
    - `:alert_status_update` - Update alert status
    - `:alert_enrichment` - Add enrichment data
    - `:alert_comment` - Add comment/note
    - `:incident_sync` - Sync incident state
    - `:interactive_response` - Handle interactive response
  - `:alert_reference` - Map to identify the alert:
    - `:alert_id` - Tamandua alert UUID (if available)
    - `:external_id` - External system ID
    - `:title` - Alert/incident title
  - `:external_id` - External ticket/incident ID
  - `:external_status` - Status in external system
  - `:external_url` - Link to external ticket/incident
  - `:user` - User who performed the action
  - `:comment` - Comment/note text
  - `:resolution_notes` - Resolution notes
  - `:enrichment_data` - Map of enrichment data
  - `:metadata` - Additional metadata
  - `:raw_payload` - Original webhook payload
  """
  @callback parse(payload :: map(), opts :: keyword()) ::
    {:ok, map()} | {:error, term()}
end
