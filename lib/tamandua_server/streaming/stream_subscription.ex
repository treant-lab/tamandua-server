defmodule TamanduaServer.Streaming.StreamSubscription do
  @moduledoc """
  Struct representing a stream subscription.
  """

  @type t :: %__MODULE__{
    stream_id: String.t(),
    subscriber_pid: pid(),
    filters: map(),
    options: map(),
    registered_at: integer(),
    events_sent: integer(),
    last_event_at: integer() | nil,
    queue_size: integer()
  }

  defstruct [
    :stream_id,
    :subscriber_pid,
    :filters,
    :options,
    :registered_at,
    events_sent: 0,
    last_event_at: nil,
    queue_size: 0
  ]
end
