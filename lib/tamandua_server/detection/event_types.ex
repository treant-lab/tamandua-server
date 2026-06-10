defmodule TamanduaServer.Detection.EventTypes do
  @moduledoc """
  Structured event type normalization.

  Converts incoming event types (strings or atoms) to canonical atoms and
  provides category grouping used by the behavioral engine and correlator.
  """

  @type event_type ::
          :process_create
          | :process_terminate
          | :process_inject
          | :file_create
          | :file_modify
          | :file_delete
          | :file_execute
          | :file_read
          | :file_rename
          | :module_load
          | :network_connect
          | :network_anomaly
          | :network_listen
          | :registry_set
          | :registry_set_value
          | :scheduled_task_create
          | :wmi_event
          | :dns_query
          | :honeyfile_access
          | :authentication
          | :logon
          | :login
          # ETW tampering event types (MITRE T1562.006)
          | :etw_tampering
          | :etw_prologue_patched
          | :ntdll_stub_modified
          | :fresh_ntdll_mapping
          | :ntdll_write_detected
          | :syscall_region_tampered
          | :unknown

  @type event_category :: :process | :file | :network | :registry | :dns | :auth | :deception | :defense_evasion | :unknown

  # ETW tampering event subtypes
  @etw_tampering_subtypes [
    "etw_tampering",
    "etw_prologue_patched",
    "ntdll_stub_modified",
    "fresh_ntdll_mapping",
    "ntdll_write_detected",
    "syscall_region_tampered"
  ]

  @doc "List of all ETW tampering event subtypes"
  def etw_tampering_subtypes, do: @etw_tampering_subtypes

  @known_types %{
    "process_create" => :process_create,
    "process" => :process_create,
    "process_start" => :process_create,
    "process_terminate" => :process_terminate,
    "process_inject" => :process_inject,
    "file_create" => :file_create,
    "file_modify" => :file_modify,
    "file_delete" => :file_delete,
    "file_execute" => :file_execute,
    "file_read" => :file_read,
    "file_rename" => :file_rename,
    "module_load" => :module_load,
    "file" => :file_create,
    "network_connect" => :network_connect,
    "network_connection" => :network_connect,
    "network" => :network_connect,
    "network_anomaly" => :network_anomaly,
    "network_listen" => :network_listen,
    "registry_set" => :registry_set,
    "registry_set_value" => :registry_set_value,
    "registry_modify" => :registry_set,
    "scheduled_task_create" => :scheduled_task_create,
    "wmi_event" => :wmi_event,
    "dns_query" => :dns_query,
    "honeyfile_access" => :honeyfile_access,
    "authentication" => :authentication,
    "logon" => :logon,
    "login" => :login,
    # ETW tampering event types (MITRE T1562.006)
    "etw_tampering" => :etw_tampering,
    "etw_prologue_patched" => :etw_prologue_patched,
    "ntdll_stub_modified" => :ntdll_stub_modified,
    "fresh_ntdll_mapping" => :fresh_ntdll_mapping,
    "ntdll_write_detected" => :ntdll_write_detected,
    "syscall_region_tampered" => :syscall_region_tampered
  }

  @doc """
  Normalize an event type to a canonical atom.

  Accepts atoms, strings, or nil. Unknown types map to `:unknown`.
  """
  @spec normalize(term()) :: event_type()
  def normalize(type) when is_atom(type) and not is_nil(type) do
    case Map.get(@known_types, Atom.to_string(type)) do
      nil -> type
      canonical -> canonical
    end
  end

  def normalize(type) when is_binary(type) do
    Map.get(@known_types, String.downcase(type), :unknown)
  end

  def normalize(_), do: :unknown

  @doc """
  Return the high-level category for a normalized event type.
  """
  @spec category(event_type()) :: event_category()
  def category(type) when type in [:process_create, :process_terminate, :process_inject], do: :process
  def category(type) when type in [:file_create, :file_modify, :file_delete, :file_execute, :file_read, :file_rename, :module_load], do: :file
  def category(type) when type in [:network_connect, :network_anomaly, :network_listen], do: :network
  def category(type) when type in [:registry_set, :registry_set_value], do: :registry
  def category(:scheduled_task_create), do: :process
  def category(:wmi_event), do: :process
  def category(:dns_query), do: :dns
  def category(type) when type in [:authentication, :logon, :login], do: :auth
  def category(:honeyfile_access), do: :deception
  def category(type) when type in [:etw_tampering, :etw_prologue_patched, :ntdll_stub_modified,
                                    :fresh_ntdll_mapping, :ntdll_write_detected, :syscall_region_tampered],
    do: :defense_evasion
  def category(_), do: :unknown

  @doc """
  Check if the event type is ETW tampering-related.
  """
  @spec etw_tampering?(event_type()) :: boolean()
  def etw_tampering?(type), do: category(type) == :defense_evasion

  @doc """
  Check if the event type is process-related.
  """
  @spec process?(event_type()) :: boolean()
  def process?(type), do: category(type) == :process

  @doc """
  Check if the event type is file-related.
  """
  @spec file?(event_type()) :: boolean()
  def file?(type), do: category(type) == :file

  @doc """
  Check if the event type is auth-related.
  """
  @spec auth?(event_type()) :: boolean()
  def auth?(type), do: category(type) == :auth

  @doc """
  Check if the event type is network-related.
  """
  @spec network?(event_type()) :: boolean()
  def network?(type), do: category(type) == :network
end
