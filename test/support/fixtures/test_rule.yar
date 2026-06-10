rule test_malware {
  meta:
    description = "Test YARA rule for E2E tests"
    author = "Tamandua Test Suite"
    date = "2024-01-01"

  strings:
    $str1 = "malware_signature"
    $str2 = "suspicious_pattern"

  condition:
    any of them
}
