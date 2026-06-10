defmodule TamanduaServer.Solana.AttestationMode do
  @moduledoc """
  Configures how attestations are published to Solana.

  ## Modes

  ### `:local_only` (Air-gapped)
  - Attestations are stored locally only
  - No Solana interaction
  - Proofs are verifiable via hash but not public
  - Cost: $0

  ### `:relay` (Recommended for self-hosted)
  - Attestations are sent to Treant relay API
  - Treant aggregates and publishes in batched transactions
  - Cost for operator: $0 (Treant subsidizes)
  - Benefit: Network gains threat intel, operator gets public proofs

  ### `:self_pay` (Full control)
  - Operator configures own Solana wallet
  - Operator pays transaction fees directly
  - Cost: ~0.000005 SOL per attestation (~$0.001)
  - Benefit: Full sovereignty, no dependency on Treant

  ## Configuration

      # In config/runtime.exs
      config :tamandua_server, TamanduaServer.Solana.AttestationMode,
        mode: :relay,  # :local_only | :relay | :self_pay
        relay_url: "https://relay.tamandua.treantlab.org/api/v1/attestations",
        relay_api_key: System.get_env("TAMANDUA_RELAY_API_KEY")

  ## Network Value

  The relay model creates a positive-sum game:
  - Self-hosted operators get free on-chain proofs
  - Treant pays minimal fees (~$10/month for 1000 operators)
  - Network gains comprehensive threat intelligence
  - Security oracle becomes stronger with more data

  This is similar to how threat intel feeds work: contribute to receive.
  """

  require Logger

  @default_relay_url "https://relay.tamandua.treantlab.org/api/v1/attestations"

  @type mode :: :local_only | :relay | :self_pay
  @type attestation :: %{
    incident_hash: binary(),
    severity: integer(),
    mitre_technique: String.t(),
    rule_hash: binary(),
    org_pseudonym: binary(),
    agent_pseudonym: binary(),
    timestamp: DateTime.t()
  }

  @doc """
  Get current attestation mode.
  """
  @spec mode() :: mode()
  def mode do
    config()[:mode] || :relay
  end

  @doc """
  Submit an attestation using the configured mode.
  """
  @spec submit(attestation()) :: {:ok, map()} | {:error, term()}
  def submit(attestation) do
    case mode() do
      :local_only ->
        submit_local(attestation)

      :relay ->
        submit_relay(attestation)

      :self_pay ->
        submit_self_pay(attestation)
    end
  end

  @doc """
  Check if attestations will be published on-chain.
  """
  @spec on_chain?() :: boolean()
  def on_chain? do
    mode() in [:relay, :self_pay]
  end

  # Local-only: store attestation hash locally, no Solana
  defp submit_local(attestation) do
    hash = compute_attestation_hash(attestation)

    Logger.info("[Attestation] Local-only mode: stored attestation hash=#{Base.encode16(hash, case: :lower)}")

    {:ok, %{
      mode: :local_only,
      attestation_hash: hash,
      on_chain: false,
      message: "Attestation stored locally. Configure relay mode for on-chain publication."
    }}
  end

  # Relay: send to Treant relay for batched publication
  defp submit_relay(attestation) do
    relay_url = config()[:relay_url] || @default_relay_url
    api_key = config()[:relay_api_key]

    payload = %{
      attestation: encode_attestation(attestation),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    headers = [
      {"Content-Type", "application/json"},
      {"X-Tamandua-Relay-Key", api_key || ""}
    ]

    case Req.post(relay_url, json: payload, headers: headers, receive_timeout: 10_000) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        case decode_relay_response(body) do
          {:ok, %{"batch_id" => batch_id, "position" => position}} ->
            Logger.info("[Attestation] Relay accepted: batch=#{batch_id}, position=#{position}")

            {:ok, %{
              mode: :relay,
              batch_id: batch_id,
              position: position,
              on_chain: :pending,
              message: "Attestation queued for batch publication"
            }}

          {:ok, response} ->
            {:ok, %{mode: :relay, on_chain: :pending, response: response}}

          {:error, _} ->
            {:ok, %{mode: :relay, on_chain: :pending, message: "Accepted by relay"}}
        end

      {:ok, %Req.Response{status: status, body: body}} ->
        Logger.warning("[Attestation] Relay rejected: status=#{status}, body=#{body}")
        # Fallback to local
        submit_local(attestation)

      {:error, reason} ->
        Logger.warning("[Attestation] Relay unreachable: #{inspect(reason)}, falling back to local")
        # Fallback to local if relay is down
        submit_local(attestation)
    end
  end

  # Self-pay: direct Solana transaction
  defp submit_self_pay(attestation) do
    alias TamanduaServer.Solana.Client

    case Client.submit_attestation(attestation) do
      {:ok, signature} ->
        {:ok, %{
          mode: :self_pay,
          tx_signature: signature,
          on_chain: true,
          solscan_url: Client.solscan_url(signature)
        }}

      {:error, reason} ->
        Logger.warning("[Attestation] Self-pay failed: #{inspect(reason)}, falling back to local")
        submit_local(attestation)
    end
  end

  # Compute deterministic hash for attestation
  defp compute_attestation_hash(attestation) do
    data = [
      attestation.incident_hash,
      <<attestation.severity::8>>,
      attestation.mitre_technique,
      attestation.rule_hash,
      attestation.org_pseudonym,
      attestation.agent_pseudonym,
      DateTime.to_unix(attestation.timestamp) |> Integer.to_string()
    ]
    |> Enum.join("|")

    :crypto.hash(:sha256, data)
  end

  # Encode attestation for relay API
  defp encode_attestation(attestation) do
    %{
      ih: Base.encode16(attestation.incident_hash, case: :lower),
      s: attestation.severity,
      mt: attestation.mitre_technique,
      rh: Base.encode16(attestation.rule_hash, case: :lower),
      op: Base.encode16(attestation.org_pseudonym, case: :lower),
      ap: Base.encode16(attestation.agent_pseudonym, case: :lower),
      ts: DateTime.to_unix(attestation.timestamp)
    }
  end

  defp config do
    Application.get_env(:tamandua_server, __MODULE__, [])
  end

  defp decode_relay_response(body) when is_map(body), do: {:ok, body}
  defp decode_relay_response(body) when is_binary(body), do: Jason.decode(body)
  defp decode_relay_response(_body), do: {:error, :invalid_response}
end
