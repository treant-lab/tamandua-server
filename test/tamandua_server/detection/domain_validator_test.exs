defmodule TamanduaServer.Detection.DomainValidatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.DomainValidator

  @moduletag :detection

  @trusted_domains [
    "microsoft.com",
    "google.com",
    "github.com",
    "amazon.com",
    "cloudflare.com"
  ]

  describe "normalize/1" do
    test "lowercases domain" do
      assert {:ok, "microsoft.com"} = DomainValidator.normalize("MICROSOFT.COM")
      assert {:ok, "google.com"} = DomainValidator.normalize("GoOgLe.CoM")
    end

    test "trims whitespace" do
      assert {:ok, "example.com"} = DomainValidator.normalize("  example.com  ")
    end

    test "handles pure ASCII domains" do
      assert {:ok, "example.com"} = DomainValidator.normalize("example.com")
      assert {:ok, "sub.domain.example.com"} = DomainValidator.normalize("sub.domain.example.com")
    end

    test "detects IDN punycode domains" do
      # Already punycode
      {:ok, normalized, flag} = DomainValidator.normalize("xn--n3h.com")
      assert flag in [:idn, :idn_homoglyph_detected]
      assert normalized == "xn--n3h.com"
    end

    test "returns error for empty domain" do
      assert {:error, :empty_domain} = DomainValidator.normalize("")
      assert {:error, :empty_domain} = DomainValidator.normalize("   ")
    end

    test "returns error for overly long domain" do
      long_domain = String.duplicate("a", 254) <> ".com"
      assert {:error, :domain_too_long} = DomainValidator.normalize(long_domain)
    end

    test "returns error for invalid input types" do
      assert {:error, :invalid_input} = DomainValidator.normalize(nil)
      assert {:error, :invalid_input} = DomainValidator.normalize(123)
    end
  end

  describe "trusted?/2" do
    test "matches exact trusted domain" do
      assert DomainValidator.trusted?("microsoft.com", @trusted_domains)
      assert DomainValidator.trusted?("google.com", @trusted_domains)
    end

    test "matches subdomain of trusted domain" do
      assert DomainValidator.trusted?("login.microsoft.com", @trusted_domains)
      assert DomainValidator.trusted?("mail.google.com", @trusted_domains)
      assert DomainValidator.trusted?("deep.sub.github.com", @trusted_domains)
    end

    test "case insensitive matching" do
      assert DomainValidator.trusted?("MICROSOFT.COM", @trusted_domains)
      assert DomainValidator.trusted?("Login.MICROSOFT.com", @trusted_domains)
    end

    test "does not match domain that ends with but is not subdomain of trusted" do
      # notmicrosoft.com should NOT be trusted (it's a different domain)
      refute DomainValidator.trusted?("notmicrosoft.com", @trusted_domains)
      refute DomainValidator.trusted?("evilmicrosoft.com", @trusted_domains)
    end

    test "does not match when trusted domain is subdomain of attacker domain" do
      # microsoft.com.evil.com is a subdomain of evil.com, not microsoft.com
      refute DomainValidator.trusted?("microsoft.com.evil.com", @trusted_domains)
      refute DomainValidator.trusted?("login.microsoft.com.attacker.org", @trusted_domains)
    end

    test "does not match unrelated domains" do
      refute DomainValidator.trusted?("evil.com", @trusted_domains)
      refute DomainValidator.trusted?("malware.org", @trusted_domains)
    end

    test "handles empty trusted list" do
      refute DomainValidator.trusted?("microsoft.com", [])
    end
  end

  describe "detect_typosquat/3" do
    test "detects single character transposition" do
      result = DomainValidator.detect_typosquat("mircosoft.com", @trusted_domains)
      assert {:typosquat, "microsoft.com", distance} = result
      assert distance <= 2
    end

    test "detects single character addition" do
      result = DomainValidator.detect_typosquat("microsoftt.com", @trusted_domains)
      assert {:typosquat, "microsoft.com", 1} = result
    end

    test "detects single character deletion" do
      result = DomainValidator.detect_typosquat("micosoft.com", @trusted_domains)
      assert {:typosquat, "microsoft.com", distance} = result
      assert distance <= 2
    end

    test "detects single character substitution" do
      result = DomainValidator.detect_typosquat("micr0soft.com", @trusted_domains)
      assert {:typosquat, "microsoft.com", 1} = result
    end

    test "returns nil for exact match" do
      assert is_nil(DomainValidator.detect_typosquat("microsoft.com", @trusted_domains))
    end

    test "returns nil for completely different domain" do
      assert is_nil(DomainValidator.detect_typosquat("totallyunrelated.com", @trusted_domains))
    end

    test "respects max_distance parameter" do
      # With default max_distance=2, should detect
      result = DomainValidator.detect_typosquat("mircosoft.com", @trusted_domains, 2)
      assert {:typosquat, _, _} = result

      # With max_distance=0, should not detect
      assert is_nil(DomainValidator.detect_typosquat("mircosoft.com", @trusted_domains, 0))
    end
  end

  describe "detect_homoglyph_spoof/2" do
    test "detects Cyrillic 'a' substitution" do
      # Using Cyrillic 'а' (U+0430) instead of Latin 'a'
      domain = "micros\u0430ft.com"  # Cyrillic а
      result = DomainValidator.detect_homoglyph_spoof(domain, @trusted_domains)
      assert {:homoglyph_spoof, "microsoft.com", chars} = result
      assert "\u0430" in chars
    end

    test "detects Cyrillic 'o' substitution" do
      # Using Cyrillic 'о' (U+043E) instead of Latin 'o'
      domain = "micr\u043Esoft.com"  # Cyrillic о
      result = DomainValidator.detect_homoglyph_spoof(domain, @trusted_domains)
      assert {:homoglyph_spoof, "microsoft.com", chars} = result
      assert "\u043E" in chars
    end

    test "returns nil for legitimate domain" do
      assert is_nil(DomainValidator.detect_homoglyph_spoof("microsoft.com", @trusted_domains))
    end

    test "returns nil for domain not targeting trusted domains" do
      domain = "r\u0430ndom.com"  # Cyrillic а in "random" - not targeting trusted domains
      assert is_nil(DomainValidator.detect_homoglyph_spoof(domain, @trusted_domains))
    end
  end

  describe "extract_registered_domain/1" do
    test "extracts registered domain from subdomain" do
      assert "example.com" = DomainValidator.extract_registered_domain("sub.example.com")
      assert "example.com" = DomainValidator.extract_registered_domain("deep.sub.example.com")
    end

    test "returns domain as-is when already registered domain" do
      assert "example.com" = DomainValidator.extract_registered_domain("example.com")
    end

    test "handles two-part TLDs" do
      assert "example.co.uk" = DomainValidator.extract_registered_domain("sub.example.co.uk")
      assert "example.com.au" = DomainValidator.extract_registered_domain("www.example.com.au")
    end

    test "handles single-label input" do
      assert "localhost" = DomainValidator.extract_registered_domain("localhost")
    end
  end

  describe "levenshtein_distance/2" do
    test "returns 0 for identical strings" do
      assert 0 = DomainValidator.levenshtein_distance("microsoft", "microsoft")
    end

    test "counts single insertion" do
      assert 1 = DomainValidator.levenshtein_distance("microsoft", "microsoftt")
    end

    test "counts single deletion" do
      assert 1 = DomainValidator.levenshtein_distance("microsoft", "micosoft")
    end

    test "counts single substitution" do
      assert 1 = DomainValidator.levenshtein_distance("microsoft", "micr0soft")
    end

    test "counts transposition as 2 operations" do
      # Transposition requires delete + insert, so distance is 2
      assert 2 = DomainValidator.levenshtein_distance("microsoft", "mircosoft")
    end

    test "handles empty strings" do
      assert 5 = DomainValidator.levenshtein_distance("", "hello")
      assert 5 = DomainValidator.levenshtein_distance("hello", "")
      assert 0 = DomainValidator.levenshtein_distance("", "")
    end
  end

  describe "integration: full validation workflow" do
    test "validates and detects various attack types" do
      # Test normal trusted domain
      assert DomainValidator.trusted?("login.microsoft.com", @trusted_domains)

      # Test typosquatting attempt
      {:typosquat, target, _} = DomainValidator.detect_typosquat("mircosoft.com", @trusted_domains)
      assert target == "microsoft.com"

      # Test that attacker subdomain attack fails
      refute DomainValidator.trusted?("microsoft.com.evil.com", @trusted_domains)

      # Test that suffix attack fails
      refute DomainValidator.trusted?("evilmicrosoft.com", @trusted_domains)
    end

    test "handles real-world phishing domain patterns" do
      # Common phishing patterns
      refute DomainValidator.trusted?("microsoft-login.com", @trusted_domains)
      refute DomainValidator.trusted?("login-microsoft.com", @trusted_domains)
      refute DomainValidator.trusted?("microsoft.secure-login.com", @trusted_domains)
      refute DomainValidator.trusted?("microsft.com", @trusted_domains)  # Missing 'o'

      # These should be caught as typosquats
      assert {:typosquat, _, _} = DomainValidator.detect_typosquat("microsft.com", @trusted_domains)
      assert {:typosquat, _, _} = DomainValidator.detect_typosquat("microsooft.com", @trusted_domains)
    end
  end
end
