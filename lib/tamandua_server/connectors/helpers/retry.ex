defmodule TamanduaServer.Connectors.Helpers.Retry do
  @moduledoc """
  Retry logic with exponential backoff for connectors.

  Provides configurable retry behavior with jitter and max attempts.
  """

  require Logger

  @doc """
  Execute function with retry logic.

  ## Options:
  - `:max_attempts` - Maximum retry attempts (default: 3)
  - `:base_delay` - Base delay in milliseconds (default: 1000)
  - `:max_delay` - Maximum delay in milliseconds (default: 30000)
  - `:jitter` - Add random jitter to delay (default: true)
  - `:retry_on` - List of error patterns to retry on (default: all)

  ## Example:
      Retry.with_backoff(fn ->
        HTTP.get("https://api.example.com")
      end, max_attempts: 5, base_delay: 2000)
  """
  def with_backoff(func, opts \\ []) do
    max_attempts = Keyword.get(opts, :max_attempts, 3)
    base_delay = Keyword.get(opts, :base_delay, 1000)
    max_delay = Keyword.get(opts, :max_delay, 30_000)
    jitter = Keyword.get(opts, :jitter, true)
    retry_on = Keyword.get(opts, :retry_on, :all)

    do_retry(func, 1, max_attempts, base_delay, max_delay, jitter, retry_on)
  end

  defp do_retry(func, attempt, max_attempts, base_delay, max_delay, jitter, retry_on) do
    case func.() do
      {:ok, _} = success ->
        success

      {:error, reason} = error ->
        if attempt < max_attempts && should_retry?(reason, retry_on) do
          delay = calculate_delay(attempt, base_delay, max_delay, jitter)
          Logger.warning(
            "[Retry] Attempt #{attempt}/#{max_attempts} failed: #{inspect(reason)}. " <>
            "Retrying in #{delay}ms"
          )
          Process.sleep(delay)
          do_retry(func, attempt + 1, max_attempts, base_delay, max_delay, jitter, retry_on)
        else
          Logger.error(
            "[Retry] Failed after #{attempt} attempts: #{inspect(reason)}"
          )
          error
        end
    end
  end

  defp calculate_delay(attempt, base_delay, max_delay, jitter) do
    # Exponential backoff: base_delay * 2^(attempt - 1)
    delay = base_delay * :math.pow(2, attempt - 1)
    delay = min(delay, max_delay)

    if jitter do
      # Add random jitter ±25%
      jitter_amount = delay * 0.25
      delay + :rand.uniform(trunc(jitter_amount * 2)) - trunc(jitter_amount)
    else
      trunc(delay)
    end
  end

  defp should_retry?(_reason, :all), do: true
  defp should_retry?(reason, retry_patterns) when is_list(retry_patterns) do
    Enum.any?(retry_patterns, fn pattern ->
      match_pattern?(reason, pattern)
    end)
  end

  defp match_pattern?(reason, pattern) when is_atom(pattern) do
    reason == pattern
  end

  defp match_pattern?({tag, _}, {pattern_tag, _}) do
    tag == pattern_tag
  end

  defp match_pattern?(_, _), do: false
end
