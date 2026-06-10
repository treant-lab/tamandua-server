defmodule TamanduaServer.BackupCase do
  @moduledoc """
  Test case template for backup-related tests.

  Provides helpers for setting up mock Vault clients and temporary backup directories.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      import TamanduaServer.BackupCase
    end
  end

  setup tags do
    context = %{}

    context =
      if tags[:tmp_dir] do
        tmp_dir = Path.join(System.tmp_dir!(), "tamandua_test_#{System.unique_integer()}")
        File.mkdir_p!(tmp_dir)

        on_exit(fn -> File.rm_rf(tmp_dir) end)

        Map.put(context, :tmp_dir, tmp_dir)
      else
        context
      end

    context =
      if tags[:mock_vault] do
        # Set up mock Vault configuration
        test_key = :crypto.strong_rand_bytes(32) |> Base.encode64()

        Application.put_env(:tamandua_server, TamanduaServer.Backup.VaultClient,
          vault_url: "http://localhost:8200",
          vault_token: "test_token",
          vault_path: "secret/data/tamandua/backup",
          key_name: "master_encryption_key",
          fallback_key: test_key
        )

        on_exit(fn ->
          Application.delete_env(:tamandua_server, TamanduaServer.Backup.VaultClient)
        end)

        Map.put(context, :test_master_key, test_key)
      else
        context
      end

    {:ok, context}
  end

  @doc """
  Creates a mock backup directory with manifest and encrypted files.
  """
  def create_mock_backup(backup_dir, opts \\ []) do
    File.mkdir_p!(backup_dir)

    timestamp = Keyword.get(opts, :timestamp, DateTime.utc_now() |> DateTime.to_iso8601())
    backup_type = Keyword.get(opts, :type, "full")

    # Create manifest
    manifest = %{
      timestamp: timestamp,
      type: backup_type,
      version: "1.0",
      encryption: "AES-256-GCM",
      files: [],
      total_size: 0
    }

    manifest_path = Path.join(backup_dir, "manifest.json")
    File.write!(manifest_path, Jason.encode!(manifest, pretty: true))

    # Create mock encrypted files if requested
    if Keyword.get(opts, :create_files, false) do
      alias TamanduaServer.Backup.Encryptor

      files = Keyword.get(opts, :files, ["postgres.sql.enc", "redis.rdb.enc"])

      Enum.each(files, fn file ->
        {:ok, encrypted, _} = Encryptor.encrypt("mock data for #{file}")
        File.write!(Path.join(backup_dir, file), encrypted)
      end)
    end

    backup_dir
  end

  @doc """
  Corrupts a byte at the specified position in a binary.
  """
  def corrupt_byte(binary, position) do
    <<prefix::binary-size(position), byte::8, suffix::binary>> = binary
    corrupted_byte = rem(byte + 1, 256)
    <<prefix::binary, corrupted_byte::8, suffix::binary>>
  end

  @doc """
  Generates a mock encrypted backup file.
  """
  def mock_encrypted_file(path, data \\ "test data") do
    alias TamanduaServer.Backup.Encryptor

    {:ok, encrypted, metadata} = Encryptor.encrypt(data)
    File.write!(path, encrypted)

    {path, metadata}
  end
end
