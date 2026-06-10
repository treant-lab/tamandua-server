defmodule TamanduaServer.WalletAuth do
  @moduledoc """
  Sign-In with Solana style challenge generation and verification.

  The challenge is intentionally stored server-side and consumed once. The signed
  message is bound to the requesting domain and short-lived to prevent replay.
  """

  require Logger

  @table :tamandua_wallet_auth_challenges
  @ttl_seconds 300
  @chain "solana"
  @base58_alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  def issue_challenge(wallet_address, provider, domain) do
    with {:ok, wallet_address} <- normalize_wallet(wallet_address),
         :ok <- validate_provider(provider) do
      ensure_table()

      issued_at = DateTime.utc_now()
      expires_at = DateTime.add(issued_at, @ttl_seconds, :second)
      nonce = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)

      message = """
      #{domain} wants you to sign in with your Solana wallet:
      #{wallet_address}

      Statement: Sign in to Tamandua without sharing your private keys.
      URI: https://#{domain}
      Version: 1
      Chain ID: solana:devnet
      Nonce: #{nonce}
      Issued At: #{DateTime.to_iso8601(issued_at)}
      Expiration Time: #{DateTime.to_iso8601(expires_at)}
      """

      key = challenge_key(wallet_address, message)
      :ets.insert(@table, {key, wallet_address, provider || "unknown", message, expires_at})

      {:ok,
       %{
         chain: @chain,
         wallet_address: wallet_address,
         provider: provider || "unknown",
         message: message,
         expires_at: expires_at
       }}
    end
  end

  def verify_and_consume(wallet_address, message, signature, provider) do
    with {:ok, wallet_address} <- normalize_wallet(wallet_address),
         :ok <- validate_provider(provider),
         {:ok, public_key} <- base58_decode(wallet_address),
         true <- byte_size(public_key) == 32 || {:error, :invalid_wallet_address},
         {:ok, signature_bytes} <- decode_signature(signature),
         true <- byte_size(signature_bytes) == 64 || {:error, :invalid_signature},
         :ok <- consume_challenge(wallet_address, message),
         :ok <- verify_signature(message, signature_bytes, public_key) do
      {:ok, %{chain: @chain, wallet_address: wallet_address, provider: provider || "unknown"}}
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
      other ->
        Logger.warning("Unexpected wallet auth verification result: #{inspect(other)}")
        {:error, :verification_failed}
    end
  end

  defp consume_challenge(wallet_address, message) do
    ensure_table()
    key = challenge_key(wallet_address, message)

    case :ets.take(@table, key) do
      [{^key, ^wallet_address, _provider, ^message, expires_at}] ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
          :ok
        else
          {:error, :challenge_expired}
        end

      [] ->
        {:error, :challenge_not_found}
    end
  end

  defp verify_signature(message, signature, public_key) do
    case :crypto.verify(:eddsa, :sha512, message, signature, [public_key, :ed25519]) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  rescue
    error ->
      Logger.warning("Wallet signature verification failed: #{inspect(error)}")
      {:error, :signature_verification_unavailable}
  end

  defp normalize_wallet(wallet_address) when is_binary(wallet_address) do
    wallet_address = String.trim(wallet_address)

    if wallet_address =~ ~r/^[1-9A-HJ-NP-Za-km-z]{32,44}$/ do
      {:ok, wallet_address}
    else
      {:error, :invalid_wallet_address}
    end
  end

  defp normalize_wallet(_), do: {:error, :invalid_wallet_address}

  defp validate_provider(nil), do: :ok
  defp validate_provider(provider) when provider in ["phantom", "backpack", "solflare", "metamask", "unknown"], do: :ok
  defp validate_provider(_), do: {:error, :invalid_wallet_provider}

  defp decode_signature(signature) when is_binary(signature) do
    cond do
      String.starts_with?(signature, "base64:") ->
        signature
        |> String.replace_prefix("base64:", "")
        |> Base.decode64()

      String.starts_with?(signature, "base58:") ->
        signature
        |> String.replace_prefix("base58:", "")
        |> base58_decode()

      true ->
        base58_decode(signature)
    end
  end

  defp decode_signature(_), do: {:error, :invalid_signature}

  defp challenge_key(wallet_address, message) do
    {wallet_address, :crypto.hash(:sha256, message)}
  end

  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined -> :ets.new(@table, [:set, :public, :named_table])
      _ -> :ok
    end
  end

  defp base58_decode(str) when is_binary(str) do
    leading_zeroes =
      str
      |> String.to_charlist()
      |> Enum.take_while(&(&1 == ?1))
      |> length()

    rest = str |> String.to_charlist() |> Enum.drop(leading_zeroes)

    with {:ok, int_val} <- decode_base58_chars(rest, 0) do
      bytes = :binary.encode_unsigned(int_val)
      {:ok, :binary.copy(<<0>>, leading_zeroes) <> bytes}
    end
  rescue
    _ -> {:error, :invalid_base58}
  end

  defp decode_base58_chars([], acc), do: {:ok, acc}

  defp decode_base58_chars([char | rest], acc) do
    case Enum.find_index(@base58_alphabet, &(&1 == char)) do
      nil -> {:error, :invalid_base58}
      idx -> decode_base58_chars(rest, acc * 58 + idx)
    end
  end
end
