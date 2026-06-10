defmodule TamanduaServer.Detection.TyposquattingAnalyzerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Detection.TyposquattingAnalyzer

  setup do
    # Initialize ETS tables with test data
    TyposquattingAnalyzer.init()
    :ok
  end

  describe "check_typosquatting/2" do
    test "detects Levenshtein distance 1 typosquatting (lodas -> lodash)" do
      result = TyposquattingAnalyzer.check_typosquatting("npm", "lodas")

      assert {:typosquatting, info} = result
      assert "lodash" in info.similar_to
      assert info.detection_method in ["levenshtein", "both"]
    end

    test "detects keyboard-adjacent character swap (l0dash -> lodash)" do
      result = TyposquattingAnalyzer.check_typosquatting("npm", "l0dash")

      assert {:typosquatting, info} = result
      assert "lodash" in info.similar_to
      assert info.detection_method in ["keyboard_adjacent", "both"]
    end

    test "detects keyboard-adjacent 5->S swap (expre55 -> express)" do
      result = TyposquattingAnalyzer.check_typosquatting("npm", "expre55")

      assert {:typosquatting, info} = result
      assert "express" in info.similar_to
    end

    test "exact match returns :ok (lodash is not a typosquat)" do
      result = TyposquattingAnalyzer.check_typosquatting("npm", "lodash")

      assert result == :ok
    end

    test "unique name with no similar packages returns :ok" do
      result = TyposquattingAnalyzer.check_typosquatting("npm", "totally-unique-package-name-xyz")

      assert result == :ok
    end

    test "detects typosquatting in PyPI (requets -> requests)" do
      result = TyposquattingAnalyzer.check_typosquatting("pypi", "requets")

      assert {:typosquatting, info} = result
      assert "requests" in info.similar_to
    end

    test "Levenshtein distance > 2 does not trigger alert" do
      # "xyz" has distance 3+ from "lodash"
      result = TyposquattingAnalyzer.check_typosquatting("npm", "xyz")

      assert result == :ok
    end

    test "namespace stripping works (@company/lodash compares to lodash)" do
      result = TyposquattingAnalyzer.check_typosquatting("npm", "@company/lodash")

      # Should return :ok because "lodash" exactly matches
      assert result == :ok
    end

    test "namespace with typosquat (@company/lodas)" do
      result = TyposquattingAnalyzer.check_typosquatting("npm", "@company/lodas")

      assert {:typosquatting, info} = result
      assert "lodash" in info.similar_to
    end
  end

  describe "keyboard_adjacent?/2" do
    test "detects 1->l substitution" do
      assert TyposquattingAnalyzer.keyboard_adjacent?("1odash", "lodash") == true
    end

    test "detects 0->O substitution" do
      assert TyposquattingAnalyzer.keyboard_adjacent?("l0dash", "lodash") == true
    end

    test "detects 5->S substitution" do
      assert TyposquattingAnalyzer.keyboard_adjacent?("expre55", "express") == true
    end

    test "detects I->l substitution" do
      assert TyposquattingAnalyzer.keyboard_adjacent?("Iodash", "lodash") == true
    end

    test "returns false for non-adjacent characters" do
      assert TyposquattingAnalyzer.keyboard_adjacent?("lodash", "xyz") == false
    end
  end

  describe "load_popular_packages/1" do
    test "loads packages from npm.txt" do
      packages = TyposquattingAnalyzer.load_popular_packages("npm")

      assert MapSet.member?(packages, "lodash")
      assert MapSet.member?(packages, "express")
      assert MapSet.member?(packages, "react")
      assert MapSet.size(packages) >= 100
    end

    test "loads packages from pypi.txt" do
      packages = TyposquattingAnalyzer.load_popular_packages("pypi")

      assert MapSet.member?(packages, "requests")
      assert MapSet.member?(packages, "numpy")
      assert MapSet.member?(packages, "pandas")
      assert MapSet.size(packages) >= 100
    end

    test "loads packages from cargo.txt" do
      packages = TyposquattingAnalyzer.load_popular_packages("cargo")

      assert MapSet.member?(packages, "serde")
      assert MapSet.member?(packages, "tokio")
      assert MapSet.size(packages) >= 100
    end

    test "returns empty MapSet for unknown ecosystem" do
      packages = TyposquattingAnalyzer.load_popular_packages("unknown")

      assert MapSet.size(packages) == 0
    end
  end

  describe "strip_namespace/1" do
    test "removes @scope/ prefix from npm packages" do
      assert TyposquattingAnalyzer.strip_namespace("@company/lodash") == "lodash"
      assert TyposquattingAnalyzer.strip_namespace("@babel/core") == "core"
    end

    test "leaves non-scoped packages unchanged" do
      assert TyposquattingAnalyzer.strip_namespace("lodash") == "lodash"
      assert TyposquattingAnalyzer.strip_namespace("express") == "express"
    end
  end
end
