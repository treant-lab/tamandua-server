defmodule TamanduaServer.Hunting.HuntSchema do
  @moduledoc """
  Defines the hunt query schema including field definitions and operators.
  This is the single source of truth for hunt fields - frontend fetches from here.
  """

  @doc """
  Returns all field definitions grouped by category.
  """
  def field_definitions do
    %{
      "process" => [
        %{field: "process.name", label: "Process Name", type: "string", description: "The name of the executable"},
        %{field: "process.path", label: "Process Path", type: "string", description: "Full path to the executable"},
        %{field: "process.cmdline", label: "Command Line", type: "string", description: "Full command line including arguments"},
        %{field: "process.pid", label: "Process ID", type: "number", description: "Process identifier"},
        %{field: "process.ppid", label: "Parent PID", type: "number", description: "Parent process identifier"},
        %{field: "process.user", label: "User", type: "string", description: "User running the process"},
        %{field: "process.sha256", label: "SHA256 Hash", type: "string", description: "SHA256 hash of the executable"},
        %{field: "process.is_elevated", label: "Is Elevated", type: "boolean", description: "Whether the process has elevated privileges"},
        %{field: "process.parent", label: "Parent Process", type: "string", description: "Name of the parent process"},
        %{field: "process.integrity_level", label: "Integrity Level", type: "string", description: "Process integrity level (Low, Medium, High, System)"},
        %{field: "process.is_signed", label: "Is Signed", type: "boolean", description: "Whether the executable is digitally signed"},
        %{field: "process.signer", label: "Signer", type: "string", description: "Digital signature signer name"}
      ],
      "network" => [
        %{field: "network.remote_ip", label: "Remote IP", type: "string", description: "Destination IP address"},
        %{field: "network.remote_port", label: "Remote Port", type: "number", description: "Destination port number"},
        %{field: "network.local_port", label: "Local Port", type: "number", description: "Source port number"},
        %{field: "network.protocol", label: "Protocol", type: "string", description: "Network protocol (TCP, UDP, etc.)"},
        %{field: "network.direction", label: "Direction", type: "string", description: "Connection direction (inbound, outbound)"},
        %{field: "network.bytes_sent", label: "Bytes Sent", type: "number", description: "Number of bytes sent"},
        %{field: "network.bytes_recv", label: "Bytes Received", type: "number", description: "Number of bytes received"},
        %{field: "network.state", label: "Connection State", type: "string", description: "TCP connection state"},
        %{field: "network.local_ip", label: "Local IP", type: "string", description: "Source IP address"}
      ],
      "file" => [
        %{field: "file.path", label: "File Path", type: "string", description: "Full path to the file"},
        %{field: "file.name", label: "File Name", type: "string", description: "Name of the file"},
        %{field: "file.sha256", label: "SHA256 Hash", type: "string", description: "SHA256 hash of the file"},
        %{field: "file.operation", label: "Operation", type: "string", description: "File operation (create, modify, delete, read)"},
        %{field: "file.size", label: "File Size", type: "number", description: "Size of the file in bytes"},
        %{field: "file.extension", label: "Extension", type: "string", description: "File extension"},
        %{field: "file.entropy", label: "Entropy", type: "number", description: "Shannon entropy of file contents"}
      ],
      "dns" => [
        %{field: "dns.query", label: "DNS Query", type: "string", description: "DNS query domain name"},
        %{field: "dns.query_type", label: "Query Type", type: "string", description: "DNS record type (A, AAAA, TXT, etc.)"},
        %{field: "dns.response", label: "Response", type: "string", description: "DNS response data"},
        %{field: "dns.response_code", label: "Response Code", type: "string", description: "DNS response code (NOERROR, NXDOMAIN, etc.)"}
      ],
      "registry" => [
        %{field: "registry.path", label: "Registry Path", type: "string", description: "Full registry key path"},
        %{field: "registry.key", label: "Key Name", type: "string", description: "Registry key name"},
        %{field: "registry.value", label: "Value", type: "string", description: "Registry value data"},
        %{field: "registry.value_type", label: "Value Type", type: "string", description: "Registry value type (REG_SZ, REG_DWORD, etc.)"},
        %{field: "registry.operation", label: "Operation", type: "string", description: "Registry operation (create, modify, delete)"}
      ],
      "general" => [
        %{field: "event.type", label: "Event Type", type: "string", description: "Type of telemetry event"},
        %{field: "agent.id", label: "Agent ID", type: "string", description: "Unique agent identifier"},
        %{field: "agent.hostname", label: "Hostname", type: "string", description: "Agent hostname"},
        %{field: "agent.os", label: "Operating System", type: "string", description: "Agent operating system"},
        %{field: "agent.version", label: "Agent Version", type: "string", description: "Agent software version"}
      ]
    }
  end

  @doc """
  Returns a flat list of all fields.
  """
  def all_fields do
    field_definitions()
    |> Map.values()
    |> List.flatten()
  end

  @doc """
  Returns all available operators with their metadata.
  """
  def operators do
    [
      %{value: ":", label: "equals", symbol: "=", types: ["string", "number", "boolean"]},
      %{value: ":*", label: "contains", symbol: "contains", types: ["string"]},
      %{value: ":~", label: "regex", symbol: "regex", types: ["string"]},
      %{value: ":^", label: "starts with", symbol: "startsWith", types: ["string"]},
      %{value: ":$", label: "ends with", symbol: "endsWith", types: ["string"]},
      %{value: ":>", label: "greater than", symbol: ">", types: ["number"]},
      %{value: ":<", label: "less than", symbol: "<", types: ["number"]},
      %{value: ":>=", label: "greater or equal", symbol: ">=", types: ["number"]},
      %{value: ":<=", label: "less or equal", symbol: "<=", types: ["number"]},
      %{value: ":!", label: "not equals", symbol: "!=", types: ["string", "number", "boolean"]},
      %{value: ":in", label: "in list", symbol: "in", types: ["string", "number"]},
      %{value: ":!in", label: "not in list", symbol: "not_in", types: ["string", "number"]}
    ]
  end

  @doc """
  Returns all MITRE ATT&CK categories for templates.
  """
  def mitre_categories do
    [
      "Initial Access",
      "Execution",
      "Persistence",
      "Privilege Escalation",
      "Defense Evasion",
      "Credential Access",
      "Discovery",
      "Lateral Movement",
      "Collection",
      "Command and Control",
      "Exfiltration",
      "Impact"
    ]
  end

  @doc """
  Returns the full schema including fields, operators, and categories.
  """
  def full_schema do
    %{
      fields: field_definitions(),
      all_fields: all_fields(),
      operators: operators(),
      categories: mitre_categories()
    }
  end
end
