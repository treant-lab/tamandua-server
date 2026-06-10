defmodule TamanduaServer.WallabyConfig do
  @moduledoc """
  Wallaby configuration for E2E tests.

  This module provides configuration and setup for Wallaby browser automation.
  """

  use Wallaby.DSL

  @doc """
  Default capabilities for Chrome headless mode.
  """
  def chrome_capabilities do
    %{
      chromeOptions: %{
        args: [
          "--headless",
          "--disable-gpu",
          "--no-sandbox",
          "--disable-dev-shm-usage",
          "--disable-extensions",
          "--disable-background-networking",
          "--disable-sync",
          "--disable-translate",
          "--hide-scrollbars",
          "--metrics-recording-only",
          "--mute-audio",
          "--no-first-run",
          "--safebrowsing-disable-auto-update",
          "--window-size=1920,1080"
        ]
      }
    }
  end

  @doc """
  Capabilities for visible browser (useful for debugging).
  """
  def chrome_visible_capabilities do
    %{
      chromeOptions: %{
        args: [
          "--disable-gpu",
          "--no-sandbox",
          "--window-size=1920,1080"
        ]
      }
    }
  end

  @doc """
  Firefox capabilities for headless mode.
  """
  def firefox_capabilities do
    %{
      "moz:firefoxOptions" => %{
        args: [
          "-headless"
        ]
      }
    }
  end

  @doc """
  Get capabilities based on environment variable.
  Set WALLABY_BROWSER=visible to see the browser during tests.
  """
  def get_capabilities do
    case System.get_env("WALLABY_BROWSER") do
      "visible" -> chrome_visible_capabilities()
      "firefox" -> firefox_capabilities()
      _ -> chrome_capabilities()
    end
  end

  @doc """
  Configure Wallaby screenshot directory.
  """
  def screenshot_dir do
    Path.join([File.cwd!(), "tmp", "screenshots"])
  end

  @doc """
  Setup screenshot directory before tests.
  """
  def setup_screenshot_dir do
    File.mkdir_p!(screenshot_dir())
  end
end
