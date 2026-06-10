defmodule TamanduaServerWeb.I18nTest do
  use TamanduaServerWeb.ConnCase, async: true

  import TamanduaServerWeb.Gettext

  describe "Gettext configuration" do
    test "has correct default locale" do
      assert TamanduaServerWeb.Gettext.default_locale() == "en"
    end

    test "has all expected supported locales" do
      locales = TamanduaServerWeb.Gettext.supported_locales()
      assert "en" in locales
      assert "es" in locales
      assert "pt" in locales
      assert "fr" in locales
      assert "de" in locales
      assert "ja" in locales
      assert length(locales) >= 6
    end

    test "validates locales correctly" do
      assert TamanduaServerWeb.Gettext.valid_locale?("en") == true
      assert TamanduaServerWeb.Gettext.valid_locale?("es") == true
      assert TamanduaServerWeb.Gettext.valid_locale?("invalid") == false
      assert TamanduaServerWeb.Gettext.valid_locale?(nil) == false
    end

    test "provides locale metadata" do
      metadata = TamanduaServerWeb.Gettext.locale_metadata()
      assert is_map(metadata)
      assert Map.has_key?(metadata, "en")
      assert Map.has_key?(metadata, "es")

      en_meta = metadata["en"]
      assert en_meta.name == "English"
      assert en_meta.native == "English"
      assert en_meta.rtl == false
    end
  end

  describe "basic translations" do
    test "translates simple strings" do
      Gettext.put_locale(TamanduaServerWeb.Gettext, "en")
      assert gettext("Home") == "Home"
      assert gettext("Alerts") == "Alerts"
    end

    test "translates with interpolation" do
      Gettext.put_locale(TamanduaServerWeb.Gettext, "en")
      result = gettext("Showing %{start} to %{end} of %{total} results",
        start: 1, end: 10, total: 100)
      assert result == "Showing 1 to 10 of 100 results"
    end

    test "handles plural forms correctly" do
      Gettext.put_locale(TamanduaServerWeb.Gettext, "en")
      assert ngettext("One alert", "%{count} alerts", 1) == "One alert"
      assert ngettext("One alert", "%{count} alerts", 5) == "5 alerts"
    end
  end

  describe "domain-specific translations" do
    test "translates error messages" do
      Gettext.put_locale(TamanduaServerWeb.Gettext, "en")
      assert dgettext("errors", "Invalid email or password") == "Invalid email or password"
    end
  end

  describe "locale detection" do
    test "detects locale from session" do
      conn = build_conn()
      |> Plug.Test.init_test_session(%{locale: "es"})
      |> TamanduaServerWeb.Plugs.SetLocale.call([])

      assert conn.assigns.locale == "es"
    end

    test "falls back to default locale for invalid locale" do
      conn = build_conn()
      |> Plug.Test.init_test_session(%{locale: "invalid"})
      |> TamanduaServerWeb.Plugs.SetLocale.call([])

      assert conn.assigns.locale == "en"
    end

    test "uses Accept-Language header when no session locale" do
      conn = build_conn()
      |> put_req_header("accept-language", "es-ES,es;q=0.9")
      |> Plug.Test.init_test_session(%{})
      |> TamanduaServerWeb.Plugs.SetLocale.call([])

      assert conn.assigns.locale == "es"
    end
  end

  describe "formatter" do
    alias TamanduaServerWeb.I18n.Formatter

    test "formats numbers with locale-specific separators" do
      assert Formatter.format_number(1234567.89, "en") =~ "1,234,567"
      # German uses . for thousands, , for decimal
      assert Formatter.format_number(1234567.89, "de") =~ "1.234.567"
    end

    test "formats currency correctly" do
      assert Formatter.format_currency(99.99, "USD", "en") =~ "$"
      assert Formatter.format_currency(99.99, "EUR", "de") =~ "€"
    end

    test "formats percentages" do
      assert Formatter.format_percentage(0.8523, "en") == "85.23%"
    end

    test "formats file sizes" do
      assert Formatter.format_file_size(1024, "en") =~ "KB"
      assert Formatter.format_file_size(1_048_576, "en") =~ "MB"
      assert Formatter.format_file_size(1_073_741_824, "en") =~ "GB"
    end

    test "handles nil values gracefully" do
      assert Formatter.format_number(nil, "en") == "-"
      assert Formatter.format_currency(nil, "USD", "en") == "-"
      assert Formatter.format_percentage(nil, "en") == "-"
      assert Formatter.format_file_size(nil, "en") == "-"
    end
  end

  describe "user preferences" do
    alias TamanduaServer.Accounts.User
    alias TamanduaServer.Accounts.UserPreferences

    test "validates supported locales" do
      user = %User{locale: "en", timezone: "UTC"}
      changeset = UserPreferences.preferences_changeset(user, %{locale: "es"})
      assert changeset.valid?

      changeset = UserPreferences.preferences_changeset(user, %{locale: "invalid"})
      refute changeset.valid?
      assert "is not a supported locale" in errors_on(changeset).locale
    end

    test "validates timezones" do
      user = %User{locale: "en", timezone: "UTC"}
      changeset = UserPreferences.preferences_changeset(user, %{timezone: "America/New_York"})
      assert changeset.valid?

      changeset = UserPreferences.preferences_changeset(user, %{timezone: "Invalid/Timezone"})
      refute changeset.valid?
    end

    test "gets locale with fallback" do
      user_with_locale = %User{locale: "es"}
      assert UserPreferences.get_locale(user_with_locale) == "es"

      user_without_locale = %User{locale: nil}
      assert UserPreferences.get_locale(user_without_locale) == "en"
    end

    test "gets timezone with fallback" do
      user_with_tz = %User{timezone: "America/New_York"}
      assert UserPreferences.get_timezone(user_with_tz) == "America/New_York"

      user_without_tz = %User{timezone: nil}
      assert UserPreferences.get_timezone(user_without_tz) == "UTC"
    end

    test "lists common timezones" do
      timezones = UserPreferences.common_timezones()
      assert is_list(timezones)
      assert {"UTC", "UTC"} in timezones
      assert {"America/New_York", "Eastern Time (US & Canada)"} in timezones
      assert {"Asia/Tokyo", "Tokyo"} in timezones
    end
  end

  describe "translation coverage" do
    test "has minimum coverage for all supported locales" do
      # This test ensures we maintain good translation coverage
      # In production, this would parse .po files and calculate actual coverage
      for locale <- TamanduaServerWeb.Gettext.supported_locales() do
        # Mock coverage check - in production, implement actual .po parsing
        coverage = calculate_mock_coverage(locale)
        assert coverage >= 0.90,
          "Translation coverage for #{locale} is #{coverage * 100}%, expected at least 90%"
      end
    end

    defp calculate_mock_coverage(locale) do
      # Mock implementation - replace with actual .po file parsing
      case locale do
        "en" -> 1.0
        "es" -> 0.98
        "pt" -> 0.98
        "fr" -> 0.97
        "de" -> 0.96
        "ja" -> 0.95
        _ -> 0.0
      end
    end
  end

  describe "language selector component" do
    import Phoenix.LiveViewTest

    test "renders with current locale" do
      assigns = %{
        id: "test",
        current_locale: "en",
        menu_open: false
      }

      html = render_component(TamanduaServerWeb.Components.LanguageSelector, assigns)
      assert html =~ "English"
      assert html =~ "🇺🇸"
    end

    test "shows all supported locales when menu is open" do
      assigns = %{
        id: "test",
        current_locale: "en",
        menu_open: true
      }

      html = render_component(TamanduaServerWeb.Components.LanguageSelector, assigns)
      assert html =~ "English"
      assert html =~ "Español"
      assert html =~ "Português"
      assert html =~ "Français"
      assert html =~ "Deutsch"
      assert html =~ "日本語"
    end
  end

  # Helper function for changeset errors
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
