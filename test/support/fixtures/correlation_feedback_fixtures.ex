defmodule TamanduaServer.CorrelationFeedbackFixtures do
  @moduledoc """
  Pure feedback/readiness fixtures for correlation contract tests.
  """

  alias TamanduaServer.CorrelationDatasets

  def feedback_cases do
    [
      %{
        dataset: :benign_saas,
        verdict: :false_positive,
        expected_link?: false,
        reason: "common SaaS domain is ambient enterprise traffic"
      },
      %{
        dataset: :noisy_temp,
        verdict: :false_positive,
        expected_link?: false,
        reason: "shared temp/cache path is noisy local context"
      },
      %{
        dataset: :shared_mitre_only,
        verdict: :false_positive,
        expected_link?: false,
        reason: "shared generic MITRE technique has no concrete entity"
      },
      %{
        dataset: :strong_hash,
        verdict: :true_positive,
        expected_link?: true,
        reason: "same valid sha256 is concrete entity evidence"
      },
      %{
        dataset: :strong_domain,
        verdict: :true_positive,
        expected_link?: true,
        reason: "rare shared domain plus temporal context is actionable"
      },
      %{
        dataset: :process_chain,
        verdict: :true_positive,
        expected_link?: true,
        reason: "same-agent parent/child process chain is causal evidence"
      }
    ]
  end

  def dataset(:benign_saas), do: CorrelationDatasets.benign_saas()
  def dataset(:noisy_temp), do: CorrelationDatasets.noisy_temp()
  def dataset(:shared_mitre_only), do: CorrelationDatasets.shared_mitre_only()
  def dataset(:strong_hash), do: CorrelationDatasets.strong_hash()
  def dataset(:strong_domain), do: CorrelationDatasets.strong_domain()
  def dataset(:process_chain), do: CorrelationDatasets.process_chain()

  def readiness_cases do
    [
      %{
        name: :ready_network,
        expected_ready?: true,
        event:
          CorrelationDatasets.event(
            "ready-network",
            "network_connect",
            %{
              remote_ip: "8.8.8.8",
              remote_port: 443,
              protocol: "tcp",
              pid: 123,
              process_name: "curl"
            }
          ),
        missing: []
      },
      %{
        name: :incomplete_network,
        expected_ready?: false,
        event:
          CorrelationDatasets.event(
            "incomplete-network",
            "network_connect",
            %{remote_ip: "8.8.8.8"}
          ),
        missing: ["network.remote_port", "network.protocol", "process.pid", "process.name"]
      },
      %{
        name: :ready_process,
        expected_ready?: true,
        event:
          CorrelationDatasets.event(
            "ready-process",
            "process_create",
            %{
              pid: 444,
              ppid: 100,
              process_name: "powershell.exe",
              process_path: "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
              user: "alice"
            }
          ),
        missing: []
      },
      %{
        name: :dns_without_process_context,
        expected_ready?: false,
        event:
          CorrelationDatasets.event(
            "dns-no-process",
            "dns_query",
            %{domain: "c2.example-malware.test"}
          ),
        missing: ["process.pid", "process.name"]
      }
    ]
  end
end
