defmodule TamanduaServer.Detection.FpPresetTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.PresetResolver

  @yaml_path Path.join([__DIR__, "..", "..", "..", "..", "..", "config", "detection_thresholds.yml"])

  setup_all do
    {:ok, raw} = File.read(Path.expand(@yaml_path))
    {:ok, config} = YamlElixir.read_from_string(raw)
    presets = Map.fetch!(config, "presets")
    {:ok, presets: presets}
  end

  @expected %{
    "soc-enterprise" => %{
      "threat_alert_threshold" => 0.60,
      "threat_critical_threshold" => 0.85,
      "risk_alert_threshold" => 60,
      "suppression_occurrence_threshold" => 10
    },
    "mssp" => %{
      "threat_alert_threshold" => 0.75,
      "threat_critical_threshold" => 0.90,
      "risk_alert_threshold" => 75,
      "suppression_occurrence_threshold" => 5
    },
    "mid-market" => %{
      "threat_alert_threshold" => 0.85,
      "threat_critical_threshold" => 0.95,
      "risk_alert_threshold" => 85,
      "suppression_occurrence_threshold" => 3
    }
  }

  describe "presets load from committed YAML" do
    test "the three named presets exist and default is mid-market", %{presets: presets} do
      assert Map.has_key?(presets, "soc-enterprise")
      assert Map.has_key?(presets, "mssp")
      assert Map.has_key?(presets, "mid-market")
      assert presets["default"] == "mid-market"
      assert Enum.sort(PresetResolver.preset_names()) ==
               Enum.sort(["soc-enterprise", "mssp", "mid-market"])
    end

    test "the four live knobs are the only preset knobs (baseline scale is reserved, not shipped)" do
      assert Enum.sort(PresetResolver.knob_keys()) ==
               Enum.sort([
                 "threat_alert_threshold",
                 "threat_critical_threshold",
                 "risk_alert_threshold",
                 "suppression_occurrence_threshold"
               ])

      refute "baseline_confidence_reduction_scale" in PresetResolver.knob_keys()
    end

    test "no preset declares the reserved baseline_confidence_reduction_scale knob", %{presets: presets} do
      for name <- ["soc-enterprise", "mssp", "mid-market"] do
        refute Map.has_key?(presets[name], "baseline_confidence_reduction_scale")
      end
    end
  end

  describe "each preset validates (known keys, in-range values)" do
    for name <- ["soc-enterprise", "mssp", "mid-market"] do
      test "#{name} has only known knobs, all in range", %{presets: presets} do
        knobs = Map.take(presets[unquote(name)], PresetResolver.knob_keys())
        assert PresetResolver.validate_preset(unquote(name), knobs) == :ok
      end
    end

    test "validation rejects an unknown knob key" do
      assert {:error, {:unknown_knobs, ["bogus"]}} =
               PresetResolver.validate_preset("mssp", %{"bogus" => 1})
    end

    test "validation rejects an out-of-range value" do
      assert {:error, {:out_of_range, "threat_alert_threshold", _, _}} =
               PresetResolver.validate_preset("mssp", %{"threat_alert_threshold" => 0.10})
    end
  end

  describe "each preset resolves to the expected threshold set" do
    for {name, expected} <- @expected do
      test "#{name} resolves to expected knobs", %{presets: presets} do
        settings = %{"fp_preset" => unquote(name)}
        assert {:ok, unquote(name), :org, knobs} =
                 PresetResolver.resolve_preset(presets, settings)

        for {k, v} <- unquote(Macro.escape(expected)) do
          assert knobs[k] == v, "#{unquote(name)}.#{k} expected #{v}, got #{inspect(knobs[k])}"
        end
      end
    end

    test "presets are monotonic: enterprise most sensitive -> mid-market most conservative", %{presets: presets} do
      tat = fn n -> presets[n]["threat_alert_threshold"] end
      assert tat.("soc-enterprise") < tat.("mssp")
      assert tat.("mssp") < tat.("mid-market")
    end
  end

  describe "resolution order" do
    test "org setting wins over global default", %{presets: presets} do
      settings = %{"fp_preset" => "soc-enterprise"}
      assert {:ok, "soc-enterprise", :org, _} =
               PresetResolver.resolve_preset(presets, settings, "mssp")
    end

    test "global default used when org setting absent/blank", %{presets: presets} do
      assert {:ok, "mssp", :global, _} =
               PresetResolver.resolve_preset(presets, %{}, "mssp")

      assert {:ok, "mssp", :global, _} =
               PresetResolver.resolve_preset(presets, %{"fp_preset" => ""}, "mssp")
    end

    test "mid-market fallback when neither org nor global is valid", %{presets: presets} do
      assert {:ok, "mid-market", :fallback, _} =
               PresetResolver.resolve_preset(presets, nil, nil)

      assert {:ok, "mid-market", :fallback, _} =
               PresetResolver.resolve_preset(presets, %{"fp_preset" => "nonsense"}, "also-bad")
    end

    test "unknown org value falls through (does not raise)", %{presets: presets} do
      assert {:ok, "mssp", :global, _} =
               PresetResolver.resolve_preset(presets, %{"fp_preset" => "nope"}, "mssp")
    end
  end

  describe "license-tier suggestions (suggestion only)" do
    test "tier maps to suggested preset" do
      assert PresetResolver.suggested_for_tier(:enterprise) == "soc-enterprise"
      assert PresetResolver.suggested_for_tier(:pro) == "mssp"
      assert PresetResolver.suggested_for_tier(:trial) == "mid-market"
      assert PresetResolver.suggested_for_tier(:unknown) == "mid-market"
    end

    test "explicit org setting overrides the tier suggestion", %{presets: presets} do
      # tier would suggest mid-market (trial), but explicit setting wins
      settings = %{"fp_preset" => "soc-enterprise"}
      assert {:ok, "soc-enterprise", :org, _} =
               PresetResolver.resolve_preset(presets, settings, "mid-market")
    end
  end
end
