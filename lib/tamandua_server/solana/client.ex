defmodule TamanduaServer.Solana.Client do
  @moduledoc """
  Solana RPC client for the Tamanduá Sentinel attestation system.

  Direct JSON-RPC integration - no CLI dependency required.

  ## Configuration

      config :tamandua_server, TamanduaServer.Solana.Client,
        rpc_url: "https://api.devnet.solana.com",
        keypair_path: "~/.config/solana/id.json",
        enabled: true

  ## Usage

      # Submit an attestation
      {:ok, signature} = Client.submit_attestation(%{
        incident_hash: <<...>>,
        severity: 4,
        mitre_technique: "T1555.003",
        rule_hash: <<...>>,
        org_pseudonym: <<...>>,
        agent_pseudonym: <<...>>,
        timestamp: ~U[2026-05-07 12:00:00Z]
      })

      # Pay a detection bounty
      {:ok, signature} = Client.pay_bounty(incident_hash, rule_author_pubkey, amount_lamports)
  """

  use GenServer
  require Logger
  import Bitwise

  @default_rpc_url "https://api.devnet.solana.com"

  # Solana constants
  @lamports_per_sol 1_000_000_000
  @memo_program_id "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Submit an incident attestation to Solana.
  Uses the Memo program to store attestation data on-chain.
  """
  @spec submit_attestation(map()) :: {:ok, String.t()} | {:error, term()}
  def submit_attestation(params) do
    if enabled?() do
      GenServer.call(__MODULE__, {:submit_attestation, params}, 30_000)
    else
      Logger.debug("[Solana] Integration disabled, skipping attestation")
      {:error, :solana_disabled}
    end
  end

  @doc """
  Pay a detection bounty to a rule author.
  Transfers SOL with memo containing bounty metadata.
  """
  @spec pay_bounty(binary(), String.t(), non_neg_integer()) :: {:ok, String.t()} | {:error, term()}
  def pay_bounty(incident_hash, rule_author_pubkey, amount_lamports) do
    if enabled?() do
      GenServer.call(__MODULE__, {:pay_bounty, incident_hash, rule_author_pubkey, amount_lamports}, 30_000)
    else
      Logger.debug("[Solana] Integration disabled, skipping bounty")
      {:error, :solana_disabled}
    end
  end

  @doc """
  Submit a raw Memo Program payload.

  This is used by the attestation relay batcher after it has already built a
  compact, privacy-safe batch memo.
  """
  @spec submit_memo(String.t()) :: {:ok, String.t()} | {:error, term()}
  def submit_memo(memo) when is_binary(memo) do
    if enabled?() do
      GenServer.call(__MODULE__, {:submit_memo, memo}, 30_000)
    else
      Logger.debug("[Solana] Integration disabled, skipping memo")
      {:error, :solana_disabled}
    end
  end

  @doc """
  Check if Solana integration is enabled.
  """
  def enabled? do
    config()[:enabled] != false
  end

  @doc """
  Get the Solana RPC URL.
  """
  def rpc_url do
    config()[:rpc_url] || @default_rpc_url
  end

  @doc """
  Get the attestation mode (anchor or memo).
  """
  def attestation_mode do
    config()[:attestation_mode] || "memo"
  end

  @doc """
  Get Solscan URL for a transaction signature.
  """
  def solscan_url(signature) do
    cluster = if String.contains?(rpc_url(), "devnet"), do: "devnet", else: "mainnet"
    "https://solscan.io/tx/#{signature}?cluster=#{cluster}"
  end

  @doc """
  Get the signer's public key (base58 encoded).
  """
  def get_signer_pubkey do
    GenServer.call(__MODULE__, :get_signer_pubkey)
  end

  @doc """
  Get attestation data from Solana by incident hash.

  Note: This requires a transaction indexer to search by memo content.
  Currently returns an error as we don't have an indexer set up.
  For hackathon demo, attestations are tracked in the local database.
  """
  @spec get_attestation(binary()) :: {:ok, map()} | {:error, term()}
  def get_attestation(_incident_hash) do
    # Attestation lookup requires a custom indexer (e.g., Helius, Triton)
    # For now, we track attestations locally in the alerts table
    {:error, :indexer_not_configured}
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    state = %{
      rpc_url: rpc_url(),
      keypair: load_keypair(),
      http_opts: [receive_timeout: 30_000]
    }

    if enabled?() do
      case state.keypair do
        {:ok, {_secret, pubkey}} ->
          Logger.info("[Solana] Client initialized, signer: #{base58_encode(pubkey)}, RPC: #{state.rpc_url}")
        {:error, reason} ->
          Logger.warning("[Solana] Client initialized but keypair unavailable: #{inspect(reason)}")
      end
    else
      Logger.info("[Solana] Client disabled")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:submit_attestation, params}, _from, state) do
    result = do_submit_attestation(params, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:pay_bounty, incident_hash, rule_author, amount}, _from, state) do
    result = do_pay_bounty(incident_hash, rule_author, amount, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:submit_memo, memo}, _from, state) do
    result = do_submit_raw_memo(memo, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_signer_pubkey, _from, state) do
    result = case state.keypair do
      {:ok, {_secret, pubkey}} -> {:ok, base58_encode(pubkey)}
      error -> error
    end
    {:reply, result, state}
  end

  # Private - Attestation

  defp do_submit_attestation(params, state) do
    case attestation_mode() do
      "anchor" -> do_submit_anchor_attestation(params, state)
      "memo" -> do_submit_memo_attestation(params, state)
      _ -> do_submit_memo_attestation(params, state)  # fallback
    end
  end

  defp do_submit_memo_attestation(params, state) do
    with {:ok, {secret_key, pubkey}} <- state.keypair,
         {:ok, blockhash} <- get_recent_blockhash(state),
         memo <- build_attestation_memo(params),
         {:ok, tx} <- build_memo_transaction(pubkey, memo, blockhash),
         {:ok, signed_tx} <- sign_transaction(tx, secret_key),
         {:ok, signature} <- send_transaction(signed_tx, state) do
      Logger.info("[Solana] Memo attestation submitted: #{signature}")
      {:ok, signature}
    else
      {:error, reason} = error ->
        Logger.error("[Solana] Memo attestation failed: #{inspect(reason)}")
        error
    end
  end

  defp do_submit_raw_memo(memo, state) do
    with {:ok, {secret_key, pubkey}} <- state.keypair,
         {:ok, blockhash} <- get_recent_blockhash(state),
         {:ok, tx} <- build_memo_transaction(pubkey, memo, blockhash),
         {:ok, signed_tx} <- sign_transaction(tx, secret_key),
         {:ok, signature} <- send_transaction(signed_tx, state) do
      Logger.info("[Solana] Raw memo submitted: #{signature}")
      {:ok, signature}
    else
      {:error, reason} = error ->
        Logger.error("[Solana] Raw memo failed: #{inspect(reason)}")
        error
    end
  end

  defp do_submit_anchor_attestation(_params, _state) do
    # Stub for future Anchor program
    Logger.warning("[Solana] Anchor mode selected but not yet deployed, falling back to memo")
    {:error, :anchor_not_deployed}
  end

  defp build_attestation_memo(params) do
    case Map.get(params, :attestation_type) do
      "endpoint_health" -> build_health_attestation_memo(params)
      "fleet_health" -> build_fleet_health_attestation_memo(params)
      "remediation" -> build_remediation_attestation_memo(params)
      _ -> build_incident_attestation_memo(params)
    end
  end

  defp build_incident_attestation_memo(params) do
    incident_hash = Map.get(params, :incident_hash, :crypto.strong_rand_bytes(32))
    severity = Map.get(params, :severity, 3)
    mitre_technique = Map.get(params, :mitre_technique, "UNKNOWN") |> String.slice(0, 12)
    rule_hash = Map.get(params, :rule_hash, :crypto.strong_rand_bytes(32))
    org_pseudonym = Map.get(params, :org_pseudonym, :crypto.strong_rand_bytes(32))
    agent_pseudonym = Map.get(params, :agent_pseudonym, :crypto.strong_rand_bytes(32))
    timestamp = Map.get(params, :timestamp, DateTime.utc_now()) |> DateTime.to_unix()

    base = %{
      t: "tamandua_attestation",
      v: 2,
      ih: Base.encode16(incident_hash, case: :lower),
      s: severity,
      m: mitre_technique,
      rh: Base.encode16(rule_hash, case: :lower),
      op: Base.encode16(org_pseudonym, case: :lower),
      ap: Base.encode16(agent_pseudonym, case: :lower),
      ts: timestamp
    }

    manifest_hash = Map.get(params, :manifest_hash)

    v2_summary =
      %{
        mh: if(is_binary(manifest_hash), do: Base.encode16(manifest_hash, case: :lower), else: nil),
        ic: Map.get(params, :ioc_count),
        it: Map.get(params, :ioc_types),
        cf: compact_confidence(Map.get(params, :confidence)),
        tlp: Map.get(params, :tlp),
        tc: compact_string(Map.get(params, :threat_class), 24),
        mf: compact_string(Map.get(params, :malware_family), 24)
      }
      |> Enum.reject(fn {_key, value} -> is_nil(value) or value == [] end)
      |> Map.new()

    memo = Jason.encode!(Map.merge(base, v2_summary))

    if byte_size(memo) <= 566 do
      memo
    else
      Logger.warning("[Solana] Attestation memo exceeded 566 bytes; omitting optional v2 summary")
      Jason.encode!(base)
    end
  end

  defp build_health_attestation_memo(params) do
    posture_hash = Map.get(params, :posture_hash, :crypto.strong_rand_bytes(32))
    org_pseudonym = Map.get(params, :org_pseudonym, :crypto.strong_rand_bytes(32))
    agent_pseudonym = Map.get(params, :agent_pseudonym, :crypto.strong_rand_bytes(32))
    timestamp = Map.get(params, :timestamp, DateTime.utc_now()) |> DateTime.to_unix()

    memo =
      %{
        t: "tamandua_health",
        v: 1,
        ph: Base.encode16(posture_hash, case: :lower),
        op: Base.encode16(org_pseudonym, case: :lower),
        ap: Base.encode16(agent_pseudonym, case: :lower),
        st: compact_string(Map.get(params, :posture_status), 16),
        ca: Map.get(params, :critical_alerts, 0),
        ha: Map.get(params, :high_alerts, 0),
        aa: Map.get(params, :active_alerts, 0),
        wh: Map.get(params, :window_hours),
        pp: compact_string(Map.get(params, :policy_profile), 20),
        ts: timestamp
      }
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()
      |> Jason.encode!()

    if byte_size(memo) <= 566 do
      memo
    else
      Logger.warning("[Solana] Health attestation memo exceeded 566 bytes; omitting optional fields")

      Jason.encode!(%{
        t: "tamandua_health",
        v: 1,
        ph: Base.encode16(posture_hash, case: :lower),
        op: Base.encode16(org_pseudonym, case: :lower),
        ap: Base.encode16(agent_pseudonym, case: :lower),
        ts: timestamp
      })
    end
  end

  defp build_fleet_health_attestation_memo(params) do
    # Fleet-level "Proof of Health" attestation
    # Aggregates health data from all connected agents
    posture_hash = Map.get(params, :posture_hash, :crypto.strong_rand_bytes(32))
    org_pseudonym = Map.get(params, :org_pseudonym, :crypto.strong_rand_bytes(32))
    timestamp = Map.get(params, :timestamp, DateTime.utc_now()) |> DateTime.to_unix()

    # Fleet-specific metrics
    total_agents = Map.get(params, :active_alerts, 0)  # Reusing field for total
    healthy_agents = Map.get(params, :window_hours, 0) # Reusing field placeholder

    memo =
      %{
        t: "tamandua_fleet",
        v: 1,
        fh: Base.encode16(posture_hash, case: :lower),
        op: Base.encode16(org_pseudonym, case: :lower),
        st: compact_string(Map.get(params, :posture_status), 12),
        ta: total_agents,
        ca: Map.get(params, :critical_alerts, 0),
        wa: Map.get(params, :high_alerts, 0),
        pp: compact_string(Map.get(params, :policy_profile), 24),
        ts: timestamp
      }
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()
      |> Jason.encode!()

    if byte_size(memo) <= 566 do
      memo
    else
      Logger.warning("[Solana] Fleet health attestation memo exceeded 566 bytes; using compact format")

      Jason.encode!(%{
        t: "tamandua_fleet",
        v: 1,
        fh: Base.encode16(posture_hash, case: :lower),
        st: compact_string(Map.get(params, :posture_status), 12),
        ta: total_agents,
        ts: timestamp
      })
    end
  end

  defp build_remediation_attestation_memo(params) do
    remediation_hash = Map.get(params, :remediation_hash, :crypto.strong_rand_bytes(32))
    org_pseudonym = Map.get(params, :org_pseudonym, :crypto.strong_rand_bytes(32))
    agent_pseudonym = Map.get(params, :agent_pseudonym, :crypto.strong_rand_bytes(32))
    timestamp = Map.get(params, :timestamp, DateTime.utc_now()) |> DateTime.to_unix()
    action_type = Map.get(params, :action_type, "unknown") |> compact_string(16)
    status = Map.get(params, :status, "success") |> compact_string(8)

    # Optional: link to original incident
    incident_hash = Map.get(params, :incident_hash)

    base = %{
      t: "tamandua_remediation",
      v: 1,
      rh: Base.encode16(remediation_hash, case: :lower),
      at: action_type,
      op: Base.encode16(org_pseudonym, case: :lower),
      ap: Base.encode16(agent_pseudonym, case: :lower),
      st: status,
      ts: timestamp
    }

    # Add incident hash link if available (Proof of Incident reference)
    memo_data =
      if is_binary(incident_hash) do
        Map.put(base, :ih, Base.encode16(incident_hash, case: :lower))
      else
        base
      end

    memo = Jason.encode!(memo_data)

    if byte_size(memo) <= 566 do
      memo
    else
      Logger.warning("[Solana] Remediation memo exceeded 566 bytes; using minimal version")

      Jason.encode!(%{
        t: "tamandua_remediation",
        v: 1,
        rh: Base.encode16(remediation_hash, case: :lower),
        at: action_type,
        ts: timestamp
      })
    end
  end

  defp compact_confidence(nil), do: nil
  defp compact_confidence(value) when is_float(value), do: Float.round(value, 2)
  defp compact_confidence(value) when is_integer(value), do: value
  defp compact_confidence(_), do: nil

  defp compact_string(nil, _max), do: nil
  defp compact_string(value, max) when is_binary(value), do: String.slice(value, 0, max)
  defp compact_string(value, max), do: value |> to_string() |> String.slice(0, max)

  # Private - Bounty Payment

  defp do_pay_bounty(incident_hash, rule_author_pubkey, amount_lamports, state) do
    with {:ok, {secret_key, pubkey}} <- state.keypair,
         {:ok, recipient} <- base58_decode(rule_author_pubkey),
         {:ok, blockhash} <- get_recent_blockhash(state),
         memo <- build_bounty_memo(incident_hash, amount_lamports),
         {:ok, tx} <- build_transfer_with_memo(pubkey, recipient, amount_lamports, memo, blockhash),
         {:ok, signed_tx} <- sign_transaction(tx, secret_key),
         {:ok, signature} <- send_transaction(signed_tx, state) do
      sol_amount = amount_lamports / @lamports_per_sol
      Logger.info("[Solana] Bounty paid: #{sol_amount} SOL to #{rule_author_pubkey}, tx: #{signature}")
      {:ok, signature}
    else
      {:error, reason} = error ->
        Logger.error("[Solana] Bounty payment failed: #{inspect(reason)}")
        error
    end
  end

  defp build_bounty_memo(incident_hash, amount_lamports) do
    Jason.encode!(%{
      t: "tamandua_bounty",
      v: 1,
      ih: Base.encode16(incident_hash, case: :lower),
      a: amount_lamports
    })
  end

  # Private - Transaction Building

  defp build_memo_transaction(payer, memo, blockhash) when byte_size(memo) <= 566 do
    # Memo instruction: program_id + accounts (none) + data (memo bytes)
    memo_program = base58_decode!(@memo_program_id)

    tx = %{
      signatures: [<<0::512>>],  # Placeholder for signature
      message: %{
        header: %{
          num_required_signatures: 1,
          num_readonly_signed_accounts: 0,
          num_readonly_unsigned_accounts: 1
        },
        account_keys: [payer, memo_program],
        recent_blockhash: blockhash,
        instructions: [
          %{
            program_id_index: 1,
            accounts: [],
            data: memo
          }
        ]
      }
    }

    {:ok, tx}
  end

  defp build_memo_transaction(_payer, memo, _blockhash) do
    {:error, {:memo_too_large, byte_size(memo)}}
  end

  defp build_transfer_with_memo(from, to, lamports, memo, blockhash) do
    system_program = <<0::256>>  # 11111111111111111111111111111111
    memo_program = base58_decode!(@memo_program_id)

    # Transfer instruction data: u32 instruction (2 = transfer) + u64 lamports
    transfer_data = <<2::little-32, lamports::little-64>>

    tx = %{
      signatures: [<<0::512>>],
      message: %{
        header: %{
          num_required_signatures: 1,
          num_readonly_signed_accounts: 0,
          num_readonly_unsigned_accounts: 2
        },
        account_keys: [from, to, system_program, memo_program],
        recent_blockhash: blockhash,
        instructions: [
          # Transfer instruction
          %{
            program_id_index: 2,
            accounts: [0, 1],
            data: transfer_data
          },
          # Memo instruction
          %{
            program_id_index: 3,
            accounts: [],
            data: memo
          }
        ]
      }
    }

    {:ok, tx}
  end

  defp sign_transaction(tx, secret_key) do
    # Serialize message for signing
    message_bytes = serialize_message(tx.message)

    # Sign with Ed25519
    signature = :crypto.sign(:eddsa, :sha512, message_bytes, [secret_key, :ed25519])

    # Replace placeholder signature
    signed_tx = %{tx | signatures: [signature]}

    {:ok, signed_tx}
  end

  defp serialize_message(message) do
    header = <<
      message.header.num_required_signatures::8,
      message.header.num_readonly_signed_accounts::8,
      message.header.num_readonly_unsigned_accounts::8
    >>

    accounts = serialize_compact_array(message.account_keys, &Function.identity/1)
    blockhash = message.recent_blockhash
    instructions = serialize_compact_array(message.instructions, &serialize_instruction/1)

    header <> accounts <> blockhash <> instructions
  end

  defp serialize_instruction(ix) do
    <<ix.program_id_index::8>> <>
    serialize_compact_array(ix.accounts, fn idx -> <<idx::8>> end) <>
    serialize_compact_array_raw(ix.data)
  end

  defp serialize_compact_array(items, serializer) do
    len = length(items)
    len_bytes = encode_compact_u16(len)
    data = Enum.map(items, serializer) |> Enum.join()
    len_bytes <> data
  end

  defp serialize_compact_array_raw(data) when is_binary(data) do
    encode_compact_u16(byte_size(data)) <> data
  end

  defp encode_compact_u16(n) when n < 128, do: <<n::8>>
  defp encode_compact_u16(n) when n < 16384, do: <<(n &&& 0x7F) ||| 0x80, n >>> 7>>
  defp encode_compact_u16(n), do: <<(n &&& 0x7F) ||| 0x80, ((n >>> 7) &&& 0x7F) ||| 0x80, n >>> 14>>

  # Private - RPC Calls

  defp get_recent_blockhash(state) do
    case rpc_call("getLatestBlockhash", [%{commitment: "finalized"}], state) do
      {:ok, %{"value" => %{"blockhash" => blockhash}}} ->
        {:ok, base58_decode!(blockhash)}
      {:ok, %{"value" => %{"blockhash" => blockhash}}} when is_binary(blockhash) ->
        {:ok, base58_decode!(blockhash)}
      {:error, _} = error ->
        error
      other ->
        {:error, {:unexpected_response, other}}
    end
  end

  defp send_transaction(tx, state) do
    # Serialize full transaction
    tx_bytes = serialize_transaction(tx)
    tx_base64 = Base.encode64(tx_bytes)

    case rpc_call("sendTransaction", [tx_base64, %{encoding: "base64", skipPreflight: false}], state) do
      {:ok, signature} when is_binary(signature) ->
        {:ok, signature}
      {:error, %{"message" => msg}} ->
        {:error, {:rpc_error, msg}}
      {:error, _} = error ->
        error
    end
  end

  defp serialize_transaction(tx) do
    sig_count = encode_compact_u16(length(tx.signatures))
    sigs = Enum.join(tx.signatures)
    message = serialize_message(tx.message)

    sig_count <> sigs <> message
  end

  defp rpc_call(method, params, state) do
    body = Jason.encode!(%{
      jsonrpc: "2.0",
      id: 1,
      method: method,
      params: params
    })

    headers = [{"content-type", "application/json"}]

    case Req.post(state.rpc_url, body: body, headers: headers, receive_timeout: 30_000) do
      {:ok, %{status: 200, body: %{"result" => result}}} ->
        {:ok, result}

      {:ok, %{status: 200, body: %{"error" => error}}} ->
        {:error, error}

      {:ok, %{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private - Keypair Loading

  defp load_keypair do
    keypair_path = config()[:keypair_path] || "~/.config/solana/id.json"
    expanded_path = Path.expand(keypair_path)

    if File.exists?(expanded_path) do
      case File.read(expanded_path) do
        {:ok, content} ->
          case Jason.decode(content) do
            {:ok, bytes} when is_list(bytes) and length(bytes) == 64 ->
              # First 32 bytes = secret key, last 32 bytes = public key
              secret_bytes = Enum.take(bytes, 32) |> :erlang.list_to_binary()
              public_bytes = Enum.drop(bytes, 32) |> :erlang.list_to_binary()
              # Ed25519 secret key is 64 bytes: secret || public
              full_secret = secret_bytes <> public_bytes
              {:ok, {full_secret, public_bytes}}

            {:ok, _} ->
              {:error, :invalid_keypair_format}

            {:error, reason} ->
              {:error, {:json_parse_error, reason}}
          end

        {:error, reason} ->
          {:error, {:file_read_error, reason}}
      end
    else
      {:error, {:keypair_not_found, expanded_path}}
    end
  end

  # Private - Base58 Encoding/Decoding

  @base58_alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  defp base58_encode(bytes) when is_binary(bytes) do
    # Count leading zeros
    leading_zeros = count_leading_zeros(bytes, 0)
    ones = String.duplicate("1", leading_zeros)

    # Convert to integer and encode
    int_val = :binary.decode_unsigned(bytes, :big)

    if int_val == 0 do
      ones
    else
      ones <> do_base58_encode(int_val, [])
    end
  end

  defp do_base58_encode(0, acc), do: IO.iodata_to_binary(acc)
  defp do_base58_encode(n, acc) do
    char = Enum.at(@base58_alphabet, rem(n, 58))
    do_base58_encode(div(n, 58), [char | acc])
  end

  defp count_leading_zeros(<<0, rest::binary>>, count), do: count_leading_zeros(rest, count + 1)
  defp count_leading_zeros(_, count), do: count

  defp base58_decode(str) when is_binary(str) do
    chars = String.to_charlist(str)

    # Count leading '1's (which represent leading zero bytes)
    {leading_ones, rest} = Enum.split_while(chars, &(&1 == ?1))
    leading_zeros = :binary.copy(<<0>>, length(leading_ones))

    # Convert from base58
    case decode_base58_chars(rest, 0) do
      {:ok, int_val} ->
        bytes = if int_val == 0, do: <<>>, else: :binary.encode_unsigned(int_val, :big)
        {:ok, leading_zeros <> bytes}

      :error ->
        {:error, :invalid_base58}
    end
  end

  defp decode_base58_chars([], acc), do: {:ok, acc}
  defp decode_base58_chars([char | rest], acc) do
    case Enum.find_index(@base58_alphabet, &(&1 == char)) do
      nil -> :error
      idx -> decode_base58_chars(rest, acc * 58 + idx)
    end
  end

  defp base58_decode!(str) do
    case base58_decode(str) do
      {:ok, bytes} -> bytes
      {:error, reason} -> raise "Base58 decode failed: #{inspect(reason)}"
    end
  end

  defp config do
    Application.get_env(:tamandua_server, __MODULE__, [])
  end
end
