defmodule TamanduaServer.NativeTest do
  use ExUnit.Case, async: true
  alias TamanduaServer.Native

  @moduletag :native

  describe "YARA scanning" do
    @simple_rule """
    rule test_rule {
      strings:
        $a = "malware"
        $b = "virus"
      condition:
        $a or $b
    }
    """

    test "compile_rules/1 compiles valid YARA rules" do
      assert {:ok, _resource} = Native.compile_rules(@simple_rule)
    end

    test "compile_rules/1 returns error for invalid rules" do
      invalid_rule = "rule invalid { condition: invalid_syntax }"
      assert {:error, _message} = Native.compile_rules(invalid_rule)
    end

    test "scan_bytes/2 detects malware patterns" do
      {:ok, rules} = Native.compile_rules(@simple_rule)
      data = "This file contains malware code"

      {:ok, matches} = Native.scan_bytes(rules, data)
      assert length(matches) > 0
      assert Enum.any?(matches, fn m -> m.rule == "test_rule" end)
    end

    test "scan_bytes/2 returns empty list for clean data" do
      {:ok, rules} = Native.compile_rules(@simple_rule)
      data = "This is a clean file"

      {:ok, matches} = Native.scan_bytes(rules, data)
      assert matches == []
    end

    test "scan_file/2 scans file successfully" do
      # Create temp file
      temp_file = Path.join(System.tmp_dir!(), "test_yara_#{:rand.uniform(10000)}.txt")
      File.write!(temp_file, "This contains malware pattern")

      try do
        {:ok, rules} = Native.compile_rules(@simple_rule)
        {:ok, matches} = Native.scan_file(rules, temp_file)
        assert length(matches) > 0
      after
        File.rm(temp_file)
      end
    end

    test "scan_file/2 returns error for non-existent file" do
      {:ok, rules} = Native.compile_rules(@simple_rule)
      assert {:error, _} = Native.scan_file(rules, "/nonexistent/file.txt")
    end
  end

  describe "hashing functions" do
    @test_data "hello world"
    @expected_sha256 "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    @expected_sha1 "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    @expected_md5 "5eb63bbbe01eeed093cb22bb8f5acdc3"

    test "sha256/1 calculates correct hash" do
      {:ok, hash} = Native.sha256(@test_data)
      assert hash == @expected_sha256
    end

    test "sha1/1 calculates correct hash" do
      {:ok, hash} = Native.sha1(@test_data)
      assert hash == @expected_sha1
    end

    test "md5/1 calculates correct hash" do
      {:ok, hash} = Native.md5(@test_data)
      assert hash == @expected_md5
    end

    test "sha256_file/1 hashes file correctly" do
      temp_file = Path.join(System.tmp_dir!(), "test_hash_#{:rand.uniform(10000)}.txt")
      File.write!(temp_file, @test_data)

      try do
        {:ok, hash} = Native.sha256_file(temp_file)
        assert hash == @expected_sha256
      after
        File.rm(temp_file)
      end
    end

    test "multi_hash/1 calculates all hashes efficiently" do
      {:ok, {sha256, sha1, md5, size}} = Native.multi_hash(@test_data)

      assert sha256 == @expected_sha256
      assert sha1 == @expected_sha1
      assert md5 == @expected_md5
      assert size == byte_size(@test_data)
    end

    test "multi_hash_file/1 calculates all hashes from file" do
      temp_file = Path.join(System.tmp_dir!(), "test_multihash_#{:rand.uniform(10000)}.txt")
      File.write!(temp_file, @test_data)

      try do
        {:ok, {sha256, sha1, md5, size}} = Native.multi_hash_file(temp_file)

        assert sha256 == @expected_sha256
        assert sha1 == @expected_sha1
        assert md5 == @expected_md5
        assert size == byte_size(@test_data)
      after
        File.rm(temp_file)
      end
    end

    test "ssdeep/1 calculates fuzzy hash" do
      assert {:ok, _hash} = Native.ssdeep(@test_data)
    end
  end

  describe "entropy analysis" do
    test "calculate/1 returns 0.0 for uniform data" do
      data = String.duplicate("a", 1000)
      {:ok, entropy} = Native.calculate(data)
      assert entropy == 0.0
    end

    test "calculate/1 returns high entropy for random data" do
      data = :crypto.strong_rand_bytes(1000)
      {:ok, entropy} = Native.calculate(data)
      assert entropy > 7.0
    end

    test "calculate_file/1 analyzes file entropy" do
      temp_file = Path.join(System.tmp_dir!(), "test_entropy_#{:rand.uniform(10000)}.bin")
      data = :crypto.strong_rand_bytes(1000)
      File.write!(temp_file, data)

      try do
        {:ok, entropy} = Native.calculate_file(temp_file)
        assert entropy > 7.0
      after
        File.rm(temp_file)
      end
    end

    test "calculate_sections/2 analyzes data in sections" do
      data = :crypto.strong_rand_bytes(1000)
      {:ok, entropies} = Native.calculate_sections(data, 100)

      assert length(entropies) == 10
      assert Enum.all?(entropies, fn e -> e > 0.0 and e <= 8.0 end)
    end

    test "detect_packed/1 detects high entropy (packed) data" do
      packed_data = :crypto.strong_rand_bytes(10000)
      {:ok, is_packed} = Native.detect_packed(packed_data)
      assert is_packed == true
    end

    test "detect_packed/1 returns false for low entropy data" do
      normal_data = String.duplicate("hello world ", 1000)
      {:ok, is_packed} = Native.detect_packed(normal_data)
      assert is_packed == false
    end

    test "analyze_file/1 provides comprehensive analysis" do
      temp_file = Path.join(System.tmp_dir!(), "test_analyze_#{:rand.uniform(10000)}.bin")
      data = :crypto.strong_rand_bytes(10000)
      File.write!(temp_file, data)

      try do
        {:ok, analysis} = Native.analyze_file(temp_file)

        assert analysis.entropy > 7.0
        assert analysis.is_packed == true
        assert analysis.file_size == 10000
        assert is_list(analysis.high_entropy_regions)
      after
        File.rm(temp_file)
      end
    end
  end

  describe "Sigma rules" do
    @valid_sigma """
    id: test-rule-001
    title: Test Rule
    description: A test rule for unit tests
    level: high
    logsource:
      product: windows
      service: security
    detection:
      selection:
        EventID: 4688
        CommandLine: "*cmd.exe*"
      condition: selection
    """

    test "parse_rule/1 parses valid Sigma rule" do
      {:ok, rule} = Native.parse_rule(@valid_sigma)

      assert rule.id == "test-rule-001"
      assert rule.title == "Test Rule"
      assert rule.level == "high"
      assert rule.logsource.product == "windows"
    end

    test "parse_rule/1 returns error for invalid YAML" do
      invalid = "invalid: yaml: structure: bad"
      assert {:error, _} = Native.parse_rule(invalid)
    end

    test "validate_rule/1 validates correct rules" do
      assert {:ok, true} = Native.validate_rule(@valid_sigma)
    end

    test "validate_rule/1 rejects invalid rules" do
      invalid = "title: Missing required fields"
      assert {:error, _} = Native.validate_rule(invalid)
    end

    test "compile_rules_batch/1 compiles multiple rules" do
      rule1 = @valid_sigma

      rule2 = """
      id: test-rule-002
      title: Another Rule
      level: medium
      logsource:
        product: linux
      detection:
        selection:
          command: bash
        condition: selection
      """

      {:ok, rules} = Native.compile_rules_batch([rule1, rule2])
      assert length(rules) == 2
    end
  end

  describe "IOC matching" do
    test "match_ip/2 matches exact IP" do
      assert {:ok, true} = Native.match_ip("192.168.1.1", "192.168.1.1")
      assert {:ok, false} = Native.match_ip("192.168.1.1", "192.168.1.2")
    end

    test "match_ip/2 matches CIDR range" do
      assert {:ok, true} = Native.match_ip("192.168.1.50", "192.168.1.0/24")
      assert {:ok, false} = Native.match_ip("192.168.2.50", "192.168.1.0/24")
    end

    test "match_domain/2 matches exact domain" do
      assert {:ok, true} = Native.match_domain("evil.com", "evil.com")
      assert {:ok, false} = Native.match_domain("good.com", "evil.com")
    end

    test "match_domain/2 matches wildcard subdomain" do
      assert {:ok, true} = Native.match_domain("sub.evil.com", "*.evil.com")
      assert {:ok, true} = Native.match_domain("deep.sub.evil.com", "*.evil.com")
      assert {:ok, false} = Native.match_domain("evil.com", "*.evil.com")
    end

    test "match_hash/2 matches hashes case-insensitively" do
      hash1 = "abc123def456"
      hash2 = "ABC123DEF456"

      assert {:ok, true} = Native.match_hash(hash1, hash2)
      assert {:ok, true} = Native.match_hash(hash2, hash1)
    end

    test "extract_iocs/1 extracts IP addresses" do
      text = "Connect to 192.168.1.1 and 10.0.0.1"
      {:ok, iocs} = Native.extract_iocs(text)

      assert "192.168.1.1" in iocs.ips
      assert "10.0.0.1" in iocs.ips
    end

    test "extract_iocs/1 extracts domains" do
      text = "Visit evil.com or malware.net"
      {:ok, iocs} = Native.extract_iocs(text)

      assert "evil.com" in iocs.domains
      assert "malware.net" in iocs.domains
    end

    test "extract_iocs/1 extracts URLs" do
      text = "Download from http://evil.com/malware.exe"
      {:ok, iocs} = Native.extract_iocs(text)

      assert length(iocs.urls) > 0
      assert Enum.any?(iocs.urls, &String.contains?(&1, "evil.com"))
    end

    test "extract_iocs/1 extracts hashes" do
      md5 = "5d41402abc4b2a76b9719d911017c592"
      sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      text = "MD5: #{md5} SHA256: #{sha256}"

      {:ok, iocs} = Native.extract_iocs(text)

      assert md5 in iocs.hashes
      assert sha256 in iocs.hashes
    end

    test "match_iocs_batch/3 matches multiple IOCs" do
      values = ["192.168.1.1", "192.168.1.50", "10.0.0.1"]
      iocs = ["192.168.1.0/24", "172.16.0.0/12"]

      {:ok, matches} = Native.match_iocs_batch(values, iocs, "ip")

      # Should match 192.168.1.1 and 192.168.1.50 but not 10.0.0.1
      assert length(matches) == 2
    end
  end

  describe "performance benchmarks" do
    @tag :benchmark
    test "multi_hash is faster than individual hashes" do
      data = :crypto.strong_rand_bytes(1_000_000) # 1 MB

      # Time multi_hash
      {multi_time, {:ok, _}} = :timer.tc(fn -> Native.multi_hash(data) end)

      # Time individual hashes
      {individual_time, _} =
        :timer.tc(fn ->
          {:ok, _} = Native.sha256(data)
          {:ok, _} = Native.sha1(data)
          {:ok, _} = Native.md5(data)
        end)

      # Multi-hash should be faster (reads data once vs three times)
      assert multi_time < individual_time
    end

    @tag :benchmark
    test "entropy calculation performance" do
      data = :crypto.strong_rand_bytes(10_000_000) # 10 MB

      {time, {:ok, _entropy}} = :timer.tc(fn -> Native.calculate(data) end)

      # Should complete in reasonable time (< 100ms for 10MB)
      assert time < 100_000
    end
  end

  describe "error handling" do
    test "handles invalid file paths gracefully" do
      assert {:error, _} = Native.sha256_file("/nonexistent/file")
      assert {:error, _} = Native.calculate_file("/nonexistent/file")
      assert {:error, _} = Native.multi_hash_file("/nonexistent/file")
      assert {:error, _} = Native.analyze_file("/nonexistent/file")
    end

    test "handles invalid IP addresses" do
      assert {:error, _} = Native.match_ip("invalid", "192.168.1.1")
      assert {:error, _} = Native.match_ip("192.168.1.1", "invalid")
    end

    test "handles invalid CIDR notation" do
      assert {:error, _} = Native.match_ip("192.168.1.1", "192.168.1.0/invalid")
      assert {:error, _} = Native.match_ip("192.168.1.1", "192.168.1.0/33")
    end

    test "handles empty data gracefully" do
      assert {:ok, 0.0} = Native.calculate("")
      assert {:ok, false} = Native.detect_packed("")
    end
  end
end
