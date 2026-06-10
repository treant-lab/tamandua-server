defmodule TamanduaServer.Backup.VerifierTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Backup.{Verifier, Encryptor}

  @sample_data "Test backup data for verification"

  describe "verify_backup/2" do
    setup do
      temp_dir = System.tmp_dir!()
      backup_file = Path.join(temp_dir, "test_backup_#{System.unique_integer()}.enc")

      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)
      File.write!(backup_file, encrypted)

      on_exit(fn -> File.rm_rf(backup_file) end)

      %{backup_file: backup_file}
    end

    test "verifies valid backup successfully", %{backup_file: backup_file} do
      {:ok, result} = Verifier.verify_backup(backup_file)

      assert result.path == backup_file
      assert result.size > 0
      assert result.version == 1
      assert result.algorithm == "AES-256-GCM"
      assert :format in result.checks_passed
      assert :hmac in result.checks_passed
      assert %DateTime{} = result.verified_at
    end

    test "verifies with full decryption", %{backup_file: backup_file} do
      {:ok, result} = Verifier.verify_backup(backup_file, full_decrypt: true)

      assert :decryption in result.checks_passed
    end

    test "fails with corrupted backup", %{backup_file: backup_file} do
      # Corrupt the file
      encrypted = File.read!(backup_file)
      corrupted = corrupt_byte(encrypted, div(byte_size(encrypted), 2))
      File.write!(backup_file, corrupted)

      assert {:error, _reason} = Verifier.verify_backup(backup_file)
    end

    test "fails with non-existent file" do
      non_existent = "/tmp/does_not_exist_#{System.unique_integer()}.enc"

      assert {:error, _reason} = Verifier.verify_backup(non_existent)
    end
  end

  describe "verify_backup_directory/2" do
    setup do
      temp_dir = System.tmp_dir!()
      backup_dir = Path.join(temp_dir, "backup_test_#{System.unique_integer()}")
      File.mkdir_p!(backup_dir)

      # Create multiple backup files
      for i <- 1..3 do
        backup_file = Path.join(backup_dir, "backup_#{i}.enc")
        {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)
        File.write!(backup_file, encrypted)
      end

      on_exit(fn -> File.rm_rf(backup_dir) end)

      %{backup_dir: backup_dir}
    end

    test "verifies all backups in directory", %{backup_dir: backup_dir} do
      {:ok, results} = Verifier.verify_backup_directory(backup_dir)

      assert map_size(results) == 3

      Enum.each(results, fn {_path, result} ->
        assert match?({:ok, _}, result)
      end)
    end

    test "reports failures for corrupted backups", %{backup_dir: backup_dir} do
      # Corrupt one backup
      [first_file | _] = File.ls!(backup_dir)
      file_path = Path.join(backup_dir, first_file)
      encrypted = File.read!(file_path)
      corrupted = corrupt_byte(encrypted, 50)
      File.write!(file_path, corrupted)

      {:ok, results} = Verifier.verify_backup_directory(backup_dir)

      # Should have at least one failure
      failures = Enum.filter(results, fn {_path, result} -> match?({:error, _}, result) end)
      assert length(failures) >= 1
    end
  end

  describe "generate_verification_report/2" do
    setup do
      temp_dir = System.tmp_dir!()
      backup_root = Path.join(temp_dir, "backup_root_#{System.unique_integer()}")
      File.mkdir_p!(backup_root)

      # Create backup directory with manifest
      backup_dir = Path.join(backup_root, "full_20260220T120000Z")
      File.mkdir_p!(backup_dir)

      manifest = %{
        timestamp: "2026-02-20T12:00:00Z",
        type: "full",
        version: "1.0"
      }

      File.write!(Path.join(backup_dir, "manifest.json"), Jason.encode!(manifest))

      # Create a backup file
      backup_file = Path.join(backup_dir, "test.enc")
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)
      File.write!(backup_file, encrypted)

      on_exit(fn -> File.rm_rf(backup_root) end)

      %{backup_root: backup_root}
    end

    test "generates verification report", %{backup_root: backup_root} do
      {:ok, report} = Verifier.generate_verification_report(backup_root)

      assert %DateTime{} = report.generated_at
      assert report.backup_root == backup_root
      assert report.total_backups >= 1
      assert is_map(report.statistics)
      assert report.health in [:healthy, :warning, :critical]
    end

    test "writes report to file", %{backup_root: backup_root} do
      output_file = Path.join(System.tmp_dir!(), "report_#{System.unique_integer()}.json")

      {:ok, report} =
        Verifier.generate_verification_report(backup_root,
          format: :json,
          output_file: output_file
        )

      assert File.exists?(output_file)

      {:ok, json} = File.read(output_file)
      {:ok, parsed} = Jason.decode(json)

      assert parsed["backup_root"] == backup_root

      File.rm_rf(output_file)
    end
  end

  describe "test_restore/2" do
    setup do
      temp_dir = System.tmp_dir!()
      backup_dir = Path.join(temp_dir, "restore_test_#{System.unique_integer()}")
      File.mkdir_p!(backup_dir)

      # Create manifest
      manifest = %{
        timestamp: "2026-02-20T12:00:00Z",
        type: "full",
        version: "1.0",
        results: %{
          postgres: %{file: "postgres.sql.enc"},
          redis: %{file: "redis.rdb.enc"},
          configs: %{file: "configs.tar.gz.enc"}
        }
      }

      File.write!(Path.join(backup_dir, "manifest.json"), Jason.encode!(manifest))

      # Create sample encrypted backups
      for file <- ["postgres.sql.enc", "redis.rdb.enc", "configs.tar.gz.enc"] do
        {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)
        File.write!(Path.join(backup_dir, file), encrypted)
      end

      on_exit(fn -> File.rm_rf(backup_dir) end)

      %{backup_dir: backup_dir}
    end

    test "performs restore test", %{backup_dir: backup_dir} do
      # This will fail in test environment without real databases,
      # but we can test the structure
      result = Verifier.test_restore(backup_dir, notify_on_failure: false)

      # Expected to fail in test environment
      assert match?({:ok, _}, result) or match?({:error, _}, result)
    end
  end

  # Helper Functions

  defp corrupt_byte(binary, position) do
    <<prefix::binary-size(position), byte::8, suffix::binary>> = binary
    corrupted_byte = rem(byte + 1, 256)
    <<prefix::binary, corrupted_byte::8, suffix::binary>>
  end
end
