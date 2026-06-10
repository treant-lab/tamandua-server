defmodule TamanduaServer.EmailSecurity.EmailEvent do
  @moduledoc """
  Struct for normalized email security events.
  """

  defstruct [
    :id,
    :source,
    :event_type,
    :timestamp,
    :sender,
    :recipient,
    :subject,
    :message_id,
    :threat_type,
    :severity,
    :verdict,
    :confidence,
    :urls,
    :attachments,
    :raw_data,
    :organization_id
  ]

  @type t :: %__MODULE__{
    id: String.t() | nil,
    source: atom(),
    event_type: atom(),
    timestamp: DateTime.t() | nil,
    sender: String.t() | nil,
    recipient: String.t() | nil,
    subject: String.t() | nil,
    message_id: String.t() | nil,
    threat_type: String.t() | nil,
    severity: String.t() | nil,
    verdict: String.t() | nil,
    confidence: float() | nil,
    urls: list() | nil,
    attachments: list() | nil,
    raw_data: map() | nil,
    organization_id: String.t() | nil
  }
end
