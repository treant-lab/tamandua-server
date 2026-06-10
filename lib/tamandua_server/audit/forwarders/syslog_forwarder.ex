defmodule TamanduaServer.Audit.Forwarders.SyslogForwarder do
  @moduledoc """
  Forwards audit logs to syslog server.
  """

  def forward(audit_log, config) do
    host = config["host"]
    port = config["port"] || 514
    protocol = config["protocol"] || "udp"
    facility = config["facility"] || 16  # local0

    severity_map = %{
      "critical" => 2,
      "high" => 3,
      "medium" => 4,
      "low" => 5,
      "info" => 6
    }

    severity = Map.get(severity_map, audit_log.severity, 6)
    priority = facility * 8 + severity

    message = build_syslog_message(priority, audit_log)

    case protocol do
      "udp" -> send_udp(host, port, message)
      "tcp" -> send_tcp(host, port, message)
      _ -> {:error, "Unknown protocol: #{protocol}"}
    end
  end

  defp build_syslog_message(priority, log) do
    timestamp = Calendar.strftime(log.inserted_at, "%b %d %H:%M:%S")
    hostname = "tamandua-edr"
    
    message_parts = [
      "action=#{log.action}",
      "resource_type=#{log.resource_type}",
      "severity=#{log.severity}",
      "success=#{log.success}",
      if(log.user_id, do: "user_id=#{log.user_id}", else: nil),
      if(log.ip_address, do: "ip=#{log.ip_address}", else: nil)
    ]
    |> Enum.filter(& &1)
    |> Enum.join(" ")

    "<#{priority}>#{timestamp} #{hostname} tamandua-audit: #{message_parts}"
  end

  defp send_udp(host, port, message) do
    case :gen_udp.open(0) do
      {:ok, socket} ->
        result = :gen_udp.send(socket, to_charlist(host), port, message)
        :gen_udp.close(socket)
        if result == :ok, do: {:ok, :forwarded}, else: {:error, result}
      
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp send_tcp(host, port, message) do
    case :gen_tcp.connect(to_charlist(host), port, [:binary, active: false], 5000) do
      {:ok, socket} ->
        result = :gen_tcp.send(socket, message <> "\n")
        :gen_tcp.close(socket)
        if result == :ok, do: {:ok, :forwarded}, else: {:error, result}
      
      {:error, reason} ->
        {:error, reason}
    end
  end
end
