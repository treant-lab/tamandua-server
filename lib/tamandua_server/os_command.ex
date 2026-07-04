defmodule TamanduaServer.OSCommand do
  @moduledoc """
  Safe wrapper for external command execution.

  `System.cmd/3` does not invoke a shell, so shell metacharacters are not
  command-injection by themselves. The real risks are PATH hijacking, unexpected
  executables, NUL/control arguments, long-running commands, and unsafe archive
  extraction. This module centralizes those guardrails.
  """

  require Logger

  @allowed_commands %{
    "openssl" => ["/usr/bin/openssl", "/usr/local/bin/openssl", "/bin/openssl"],
    "pg_dump" => ["/usr/bin/pg_dump", "/usr/local/bin/pg_dump"],
    "psql" => ["/usr/bin/psql", "/usr/local/bin/psql"],
    "createdb" => ["/usr/bin/createdb", "/usr/local/bin/createdb"],
    "dropdb" => ["/usr/bin/dropdb", "/usr/local/bin/dropdb"],
    "tar" => ["/bin/tar", "/usr/bin/tar", "/usr/local/bin/tar"],
    "git" => ["/usr/bin/git", "/usr/local/bin/git"],
    "trivy" => ["/usr/bin/trivy", "/usr/local/bin/trivy"],
    "yara" => ["/usr/bin/yara", "/usr/local/bin/yara"],
    "yarac" => ["/usr/bin/yarac", "/usr/local/bin/yarac"]
  }

  @safe_path "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  @default_timeout 5_000

  @type command_result :: {binary(), non_neg_integer()} | {:error, term()}

  @doc """
  Runs an allowlisted command without invoking a shell.
  """
  @spec run(String.t(), [String.t()], keyword()) :: command_result()
  def run(command, args, opts \\ []) when is_binary(command) and is_list(args) do
    with :ok <- validate_command(command),
         :ok <- validate_args(args),
         {:ok, executable} <- resolve_executable(command) do
      opts =
        opts
        |> Keyword.update(:env, [{"PATH", @safe_path}], &[{"PATH", @safe_path} | &1])
        |> Keyword.put_new(:stderr_to_stdout, true)

      run_with_timeout(executable, args, opts)
    end
  end

  defp run_with_timeout(executable, args, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    task =
      Task.async(fn ->
        System.cmd(executable, args, opts)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} ->
        result

      nil ->
        Logger.warning("Allowed command timed out", executable: executable, timeout_ms: timeout)
        {:error, :timeout}
    end
  end

  @doc """
  Verifies archive member paths before extraction.

  Rejects absolute paths, parent traversal, Windows drive paths and NUL bytes.
  """
  @spec validate_tar_members(Path.t(), :tar | :tgz) :: :ok | {:error, term()}
  def validate_tar_members(archive_path, compression \\ :tar) do
    list_flag =
      case compression do
        :tgz -> "-tzf"
        :tar -> "-tf"
      end

    case run("tar", [list_flag, archive_path]) do
      {output, 0} ->
        output
        |> String.split("\n", trim: true)
        |> Enum.find(&unsafe_archive_member?/1)
        |> case do
          nil -> :ok
          member -> {:error, {:unsafe_archive_member, member}}
        end

      {output, code} ->
        {:error, {:tar_list_failed, code, output}}

      {:error, _} = error ->
        error
    end
  end

  defp validate_command(command) do
    if Map.has_key?(@allowed_commands, command) do
      :ok
    else
      {:error, {:command_not_allowed, command}}
    end
  end

  defp validate_args(args) do
    if Enum.all?(args, &valid_arg?/1) do
      :ok
    else
      {:error, :invalid_command_argument}
    end
  end

  defp valid_arg?(arg) when is_binary(arg), do: not String.contains?(arg, <<0>>)
  defp valid_arg?(_), do: false

  defp resolve_executable(command) do
    @allowed_commands
    |> Map.fetch!(command)
    |> Enum.find(&File.regular?/1)
    |> case do
      nil ->
        Logger.warning("Allowed command executable not found", command: command)
        {:error, {:executable_not_found, command}}

      path ->
        {:ok, path}
    end
  end

  defp unsafe_archive_member?(member) do
    normalized = String.replace(member, "\\", "/")

    String.starts_with?(normalized, "/") or
      String.contains?(normalized, <<0>>) or
      String.contains?(normalized, "../") or
      normalized == ".." or
      String.starts_with?(normalized, "../") or
      Regex.match?(~r/^[A-Za-z]:\//, normalized)
  end
end
