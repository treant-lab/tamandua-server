defmodule TamanduaServerWeb.Gettext do
  @moduledoc """
  A module providing Internationalization with a gettext-based API.

  By default, the gettext backend looks for translations in the
  "priv/gettext" directory of the :tamandua_server application.

  ## Usage

  Import this module to use gettext functions in your modules:

      import TamanduaServerWeb.Gettext

  Then you can use the following functions:

    * `gettext/1` - Translates a string
    * `dgettext/2` - Translates a string from a specific domain
    * `ngettext/3` - Translates a plural string
    * `dngettext/4` - Translates a plural string from a specific domain
    * `pgettext/2` - Translates a string with context
    * `dpgettext/3` - Translates a string with context from a specific domain

  ## Examples

      gettext("Hello world")
      dgettext("errors", "Invalid email")
      ngettext("One alert", "%{count} alerts", count)
      pgettext("navigation", "Home")

  ## Supported Locales

  - en (English) - Default
  - es (Spanish - Español)
  - pt (Portuguese - Português)
  - fr (French - Français)
  - de (German - Deutsch)
  - ja (Japanese - 日本語)
  """
  use Gettext, otp_app: :tamandua_server

  @doc """
  Returns the list of supported locales.
  """
  def supported_locales do
    ["en", "es", "pt", "fr", "de", "ja"]
  end

  @doc """
  Returns locale metadata including name and native name.
  """
  def locale_metadata do
    %{
      "en" => %{name: "English", native: "English", rtl: false},
      "es" => %{name: "Spanish", native: "Español", rtl: false},
      "pt" => %{name: "Portuguese", native: "Português", rtl: false},
      "fr" => %{name: "French", native: "Français", rtl: false},
      "de" => %{name: "German", native: "Deutsch", rtl: false},
      "ja" => %{name: "Japanese", native: "日本語", rtl: false}
    }
  end

  @doc """
  Validates if a locale is supported.
  """
  def valid_locale?(locale) when is_binary(locale) do
    locale in supported_locales()
  end

  def valid_locale?(_), do: false

  @doc """
  Returns the default locale.
  """
  def default_locale, do: "en"
end
