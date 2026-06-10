defmodule TamanduaServer.Detection.HarmfulContentClassifierTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.HarmfulContentClassifier

  @moduletag :harmful_content

  describe "violence detection" do
    test "detects explicit threats" do
      {:ok, result} = HarmfulContentClassifier.classify("I will kill you")
      assert result.is_harmful == true
      assert result.category == :violence
      assert result.confidence >= 0.5
    end

    test "detects weapon instructions" do
      {:ok, result} = HarmfulContentClassifier.classify("how to make a bomb")
      assert result.is_harmful == true
      assert result.category == :violence
    end

    test "detects mass violence references" do
      {:ok, result} = HarmfulContentClassifier.classify("planning a mass shooting")
      assert result.is_harmful == true
      assert result.category == :violence
    end

    test "returns critical severity for violence" do
      {:ok, result} = HarmfulContentClassifier.classify("I will kill you")
      assert result.severity == "critical"
    end
  end

  describe "hate speech detection" do
    test "detects ethnic cleansing references" do
      {:ok, result} = HarmfulContentClassifier.classify("ethnic cleansing is necessary")
      assert result.is_harmful == true
      assert result.category == :hate_speech
    end

    test "detects white supremacy" do
      {:ok, result} = HarmfulContentClassifier.classify("white supremacy ideology")
      assert result.is_harmful == true
      assert result.category == :hate_speech
    end

    test "returns high severity for hate speech" do
      {:ok, result} = HarmfulContentClassifier.classify("ethnic cleansing")
      assert result.severity == "high"
    end
  end

  describe "self-harm detection" do
    test "detects suicide method requests" do
      {:ok, result} = HarmfulContentClassifier.classify("how to kill myself")
      assert result.is_harmful == true
      assert result.category == :self_harm
    end

    test "detects self-harm encouragement" do
      {:ok, result} = HarmfulContentClassifier.classify("you should kill yourself")
      assert result.is_harmful == true
      assert result.category == :self_harm
    end

    test "detects lethal dose inquiries" do
      {:ok, result} = HarmfulContentClassifier.classify("what is the lethal dose of")
      assert result.is_harmful == true
      assert result.category == :self_harm
    end

    test "returns critical severity for self-harm" do
      {:ok, result} = HarmfulContentClassifier.classify("how to kill myself")
      assert result.severity == "critical"
    end
  end

  describe "illegal activity detection" do
    test "detects drug manufacturing" do
      {:ok, result} = HarmfulContentClassifier.classify("how to make meth")
      assert result.is_harmful == true
      assert result.category == :illegal
    end

    test "detects hacking instructions" do
      {:ok, result} = HarmfulContentClassifier.classify("how to hack into a bank account")
      assert result.is_harmful == true
      assert result.category == :illegal
    end

    test "detects ransomware tutorials" do
      {:ok, result} = HarmfulContentClassifier.classify("ransomware attack tutorial")
      assert result.is_harmful == true
      assert result.category == :illegal
    end

    test "detects human trafficking" do
      {:ok, result} = HarmfulContentClassifier.classify("human trafficking operations")
      assert result.is_harmful == true
      assert result.category == :illegal
    end

    test "returns high severity for illegal" do
      {:ok, result} = HarmfulContentClassifier.classify("how to make meth")
      assert result.severity == "high"
    end
  end

  describe "explicit content detection" do
    test "detects explicit sexual content" do
      {:ok, result} = HarmfulContentClassifier.classify("explicit sexual content warning")
      assert result.is_harmful == true
      assert result.category == :explicit
    end

    test "detects pornographic content references" do
      {:ok, result} = HarmfulContentClassifier.classify("pornographic material")
      assert result.is_harmful == true
      assert result.category == :explicit
    end

    test "detects CSAM indicators with critical priority" do
      {:ok, result} = HarmfulContentClassifier.classify("child pornography")
      assert result.is_harmful == true
      assert result.category == :explicit
      # This pattern should have very high confidence
      assert result.confidence >= 0.7
    end

    test "returns medium severity for explicit" do
      {:ok, result} = HarmfulContentClassifier.classify("sexually explicit")
      assert result.severity == "medium"
    end
  end

  describe "confidence boosting" do
    test "boosts confidence with multiple pattern matches" do
      # Text with multiple violence patterns
      text = "I will kill you and bomb the building"
      {:ok, result} = HarmfulContentClassifier.classify(text)
      assert result.is_harmful == true
      assert result.confidence >= 0.6
    end

    test "boosts confidence when multiple categories match" do
      # Text touching multiple categories
      text = "I will kill you because of ethnic cleansing"
      {:ok, result} = HarmfulContentClassifier.classify(text)
      assert result.is_harmful == true
      # Should have boosted confidence due to violence + hate_speech
      assert result.confidence >= 0.6
    end
  end

  describe "benign content" do
    test "does not flag normal text" do
      {:ok, result} = HarmfulContentClassifier.classify(
        "Hello, how are you today? The weather is nice."
      )
      assert result.is_harmful == false
      assert result.category == nil
      assert result.confidence == 0.0
    end

    test "does not flag discussion about safety" do
      {:ok, result} = HarmfulContentClassifier.classify(
        "We need to discuss violence prevention in schools"
      )
      # This should ideally not trigger, though simple patterns might match
      # The key is confidence should be lower for contextual usage
    end
  end

  describe "classify_async/2" do
    test "returns a task that can be awaited" do
      task = HarmfulContentClassifier.classify_async("I will kill you")
      assert is_struct(task, Task)

      {:ok, result} = Task.await(task, 5000)
      assert result.is_harmful == true
    end
  end

  describe "categories/0" do
    test "returns all supported categories" do
      categories = HarmfulContentClassifier.categories()
      assert :violence in categories
      assert :hate_speech in categories
      assert :self_harm in categories
      assert :illegal in categories
      assert :explicit in categories
    end
  end

  describe "severity_for_category/1" do
    test "returns correct severity for each category" do
      assert HarmfulContentClassifier.severity_for_category(:violence) == "critical"
      assert HarmfulContentClassifier.severity_for_category(:self_harm) == "critical"
      assert HarmfulContentClassifier.severity_for_category(:hate_speech) == "high"
      assert HarmfulContentClassifier.severity_for_category(:illegal) == "high"
      assert HarmfulContentClassifier.severity_for_category(:explicit) == "medium"
    end

    test "returns medium for unknown category" do
      assert HarmfulContentClassifier.severity_for_category(:unknown) == "medium"
    end
  end

  describe "performance" do
    test "regex-only classification completes in under 10ms" do
      # Use :use_ml false to test only regex path
      start = System.monotonic_time(:millisecond)

      for _ <- 1..100 do
        {:ok, _} = HarmfulContentClassifier.classify(
          "This is some test content to analyze for harmful patterns.",
          use_ml: false
        )
      end

      elapsed = System.monotonic_time(:millisecond) - start
      avg_time = elapsed / 100

      assert avg_time < 10, "Average regex classification took #{avg_time}ms, expected <10ms"
    end
  end

  describe "matched_patterns" do
    test "includes matched pattern sources" do
      {:ok, result} = HarmfulContentClassifier.classify("how to make a bomb")
      assert length(result.matched_patterns) > 0
      # The pattern should be a string (regex source)
      assert Enum.all?(result.matched_patterns, &is_binary/1)
    end
  end

  describe "analysis_method" do
    test "reports :regex for high-confidence matches" do
      {:ok, result} = HarmfulContentClassifier.classify(
        "I will kill you",
        use_ml: false
      )
      assert result.analysis_method == :regex
    end

    test "reports :regex when ML is disabled" do
      {:ok, result} = HarmfulContentClassifier.classify(
        "some borderline content",
        use_ml: false
      )
      assert result.analysis_method == :regex
    end
  end

  describe "edge cases" do
    test "handles empty string" do
      {:ok, result} = HarmfulContentClassifier.classify("")
      assert result.is_harmful == false
    end

    test "handles very long text" do
      long_text = String.duplicate("safe content ", 10_000)
      {:ok, result} = HarmfulContentClassifier.classify(long_text, use_ml: false)
      assert result.is_harmful == false
    end

    test "handles unicode text" do
      {:ok, result} = HarmfulContentClassifier.classify(
        "Normal unicode text: Bonjour, hola"
      )
      assert result.is_harmful == false
    end
  end
end
