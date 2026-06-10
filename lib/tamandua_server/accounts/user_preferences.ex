defmodule TamanduaServer.Accounts.UserPreferences do
  @moduledoc """
  Manages user preferences including locale, timezone, and other personalization settings.
  """

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Repo

  @doc """
  Updates user preferences including locale and timezone.

  ## Examples

      iex> update_preferences(user, %{locale: "es", timezone: "Europe/Madrid"})
      {:ok, %User{locale: "es", timezone: "Europe/Madrid"}}

      iex> update_preferences(user, %{locale: "invalid"})
      {:error, %Ecto.Changeset{}}
  """
  def update_preferences(%User{} = user, attrs) do
    user
    |> preferences_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Returns a changeset for user preferences.
  """
  def preferences_changeset(%User{} = user, attrs) do
    user
    |> Ecto.Changeset.cast(attrs, [:locale, :timezone])
    |> validate_locale()
    |> validate_timezone()
  end

  @doc """
  Sets the user's locale preference.

  ## Examples

      iex> set_locale(user, "es")
      {:ok, %User{locale: "es"}}
  """
  def set_locale(%User{} = user, locale) when is_binary(locale) do
    update_preferences(user, %{locale: locale})
  end

  @doc """
  Sets the user's timezone preference.

  ## Examples

      iex> set_timezone(user, "America/New_York")
      {:ok, %User{timezone: "America/New_York"}}
  """
  def set_timezone(%User{} = user, timezone) when is_binary(timezone) do
    update_preferences(user, %{timezone: timezone})
  end

  @doc """
  Gets the user's locale, falling back to default if not set.
  """
  def get_locale(%User{locale: locale}) when is_binary(locale) and locale != "" do
    locale
  end

  def get_locale(_user) do
    TamanduaServerWeb.Gettext.default_locale()
  end

  @doc """
  Gets the user's timezone, falling back to UTC if not set.
  """
  def get_timezone(%User{timezone: timezone}) when is_binary(timezone) and timezone != "" do
    timezone
  end

  def get_timezone(_user) do
    "UTC"
  end

  @doc """
  Returns a list of supported locales.
  """
  def supported_locales do
    TamanduaServerWeb.Gettext.supported_locales()
  end

  @doc """
  Returns a list of common timezones.
  """
  def common_timezones do
    [
      # Americas
      {"UTC", "UTC"},
      {"America/New_York", "Eastern Time (US & Canada)"},
      {"America/Chicago", "Central Time (US & Canada)"},
      {"America/Denver", "Mountain Time (US & Canada)"},
      {"America/Los_Angeles", "Pacific Time (US & Canada)"},
      {"America/Anchorage", "Alaska"},
      {"Pacific/Honolulu", "Hawaii"},
      {"America/Toronto", "Toronto"},
      {"America/Mexico_City", "Mexico City"},
      {"America/Sao_Paulo", "Brasilia"},
      {"America/Argentina/Buenos_Aires", "Buenos Aires"},

      # Europe
      {"Europe/London", "London"},
      {"Europe/Paris", "Paris"},
      {"Europe/Berlin", "Berlin"},
      {"Europe/Madrid", "Madrid"},
      {"Europe/Rome", "Rome"},
      {"Europe/Amsterdam", "Amsterdam"},
      {"Europe/Brussels", "Brussels"},
      {"Europe/Stockholm", "Stockholm"},
      {"Europe/Moscow", "Moscow"},
      {"Europe/Istanbul", "Istanbul"},

      # Asia
      {"Asia/Dubai", "Dubai"},
      {"Asia/Karachi", "Karachi"},
      {"Asia/Kolkata", "Mumbai, Kolkata"},
      {"Asia/Bangkok", "Bangkok"},
      {"Asia/Singapore", "Singapore"},
      {"Asia/Hong_Kong", "Hong Kong"},
      {"Asia/Shanghai", "Beijing, Shanghai"},
      {"Asia/Tokyo", "Tokyo"},
      {"Asia/Seoul", "Seoul"},

      # Oceania
      {"Australia/Sydney", "Sydney"},
      {"Australia/Melbourne", "Melbourne"},
      {"Australia/Brisbane", "Brisbane"},
      {"Australia/Perth", "Perth"},
      {"Pacific/Auckland", "Auckland"},

      # Africa
      {"Africa/Cairo", "Cairo"},
      {"Africa/Johannesburg", "Johannesburg"},
      {"Africa/Lagos", "Lagos"},
      {"Africa/Nairobi", "Nairobi"}
    ]
  end

  @doc """
  Returns all available timezones.
  """
  def all_timezones do
    Timex.timezones()
    |> Enum.map(fn tz -> {tz, tz} end)
    |> Enum.sort()
  end

  # Private validation functions

  defp validate_locale(changeset) do
    locale = Ecto.Changeset.get_field(changeset, :locale)

    if locale && !TamanduaServerWeb.Gettext.valid_locale?(locale) do
      Ecto.Changeset.add_error(
        changeset,
        :locale,
        "is not a supported locale. Supported locales: #{Enum.join(supported_locales(), ", ")}"
      )
    else
      changeset
    end
  end

  defp validate_timezone(changeset) do
    timezone = Ecto.Changeset.get_field(changeset, :timezone)

    if timezone && !valid_timezone?(timezone) do
      Ecto.Changeset.add_error(
        changeset,
        :timezone,
        "is not a valid timezone"
      )
    else
      changeset
    end
  end

  defp valid_timezone?(timezone) do
    timezone in Timex.timezones()
  end
end
