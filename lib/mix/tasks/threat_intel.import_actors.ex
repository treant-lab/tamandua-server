defmodule Mix.Tasks.ThreatIntel.ImportActors do
  @moduledoc """
  Import threat actor profiles from JSON files.

  ## Usage

      mix threat_intel.import_actors
      mix threat_intel.import_actors --source mitre
      mix threat_intel.import_actors --file /path/to/actors.json

  ## Options

    * `--source` - Import from a specific source (mitre, all)
    * `--file` - Import from a specific JSON file
    * `--overwrite` - Overwrite existing actors (default: false)
  """

  use Mix.Task
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.ThreatIntel.ThreatActor

  @shortdoc "Import threat actor profiles from JSON files"

  @default_files [
    "priv/threat_actors/mitre_groups.json",
    "priv/threat_actors/additional_groups.json",
    "priv/threat_actors/extended_groups.json",
    "priv/threat_actors/comprehensive_groups.json"
  ]

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, _, _} = OptionParser.parse(args,
      strict: [source: :string, file: :string, overwrite: :boolean],
      aliases: [s: :source, f: :file, o: :overwrite]
    )

    overwrite = Keyword.get(opts, :overwrite, false)

    files = cond do
      file_path = Keyword.get(opts, :file) ->
        [file_path]

      source = Keyword.get(opts, :source) ->
        get_files_for_source(source)

      true ->
        @default_files
    end

    Mix.shell().info("Importing threat actors from #{length(files)} file(s)...")

    stats = %{
      imported: 0,
      updated: 0,
      skipped: 0,
      errors: 0
    }

    stats = Enum.reduce(files, stats, fn file, acc ->
      import_file(file, overwrite, acc)
    end)

    Mix.shell().info("\n=== Import Summary ===")
    Mix.shell().info("Imported: #{stats.imported}")
    Mix.shell().info("Updated: #{stats.updated}")
    Mix.shell().info("Skipped: #{stats.skipped}")
    Mix.shell().info("Errors: #{stats.errors}")
    Mix.shell().info("======================")
  end

  defp get_files_for_source("mitre"), do: ["priv/threat_actors/mitre_groups.json"]
  defp get_files_for_source("all"), do: @default_files
  defp get_files_for_source(source) do
    Mix.shell().error("Unknown source: #{source}")
    []
  end

  defp import_file(file_path, overwrite, stats) do
    full_path = Path.join(File.cwd!(), "apps/tamandua_server/#{file_path}")

    if not File.exists?(full_path) do
      Mix.shell().error("File not found: #{full_path}")
      Map.update!(stats, :errors, &(&1 + 1))
    else
      Mix.shell().info("Importing from #{file_path}...")

      case File.read(full_path) do
        {:ok, content} ->
          case Jason.decode(content) do
            {:ok, actors} when is_list(actors) ->
              import_actors(actors, overwrite, stats)

            {:ok, _} ->
              Mix.shell().error("Invalid JSON format: expected array of actors")
              Map.update!(stats, :errors, &(&1 + 1))

            {:error, reason} ->
              Mix.shell().error("JSON decode error: #{inspect(reason)}")
              Map.update!(stats, :errors, &(&1 + 1))
          end

        {:error, reason} ->
          Mix.shell().error("File read error: #{inspect(reason)}")
          Map.update!(stats, :errors, &(&1 + 1))
      end
    end
  end

  defp import_actors(actors, overwrite, stats) do
    Enum.reduce(actors, stats, fn actor_data, acc ->
      import_actor(actor_data, overwrite, acc)
    end)
  end

  defp import_actor(actor_data, overwrite, stats) do
    name = actor_data["name"]

    if is_nil(name) do
      Mix.shell().error("Skipping actor with no name: #{inspect(actor_data)}")
      Map.update!(stats, :errors, &(&1 + 1))
    else
      # Check if actor already exists
      existing = ThreatActor.get_by_name(name)

      cond do
        is_nil(existing) ->
          # Create new actor
          case create_actor(actor_data) do
            {:ok, _actor} ->
              Mix.shell().info("  [+] Created: #{name}")
              Map.update!(stats, :imported, &(&1 + 1))

            {:error, changeset} ->
              Mix.shell().error("  [!] Failed to create #{name}: #{inspect(changeset.errors)}")
              Map.update!(stats, :errors, &(&1 + 1))
          end

        overwrite ->
          # Update existing actor
          case update_actor(existing, actor_data) do
            {:ok, _actor} ->
              Mix.shell().info("  [~] Updated: #{name}")
              Map.update!(stats, :updated, &(&1 + 1))

            {:error, changeset} ->
              Mix.shell().error("  [!] Failed to update #{name}: #{inspect(changeset.errors)}")
              Map.update!(stats, :errors, &(&1 + 1))
          end

        true ->
          Mix.shell().info("  [-] Skipped (exists): #{name}")
          Map.update!(stats, :skipped, &(&1 + 1))
      end
    end
  end

  defp create_actor(data) do
    attrs = prepare_attrs(data)
    ThreatActor.create(attrs)
  end

  defp update_actor(actor, data) do
    attrs = prepare_attrs(data)
    ThreatActor.update(actor, attrs)
  end

  defp prepare_attrs(data) do
    %{
      name: data["name"],
      description: data["description"],
      aliases: data["aliases"] || [],
      motivation: data["motivation"],
      sophistication: data["sophistication"],
      resource_level: data["resource_level"],
      origin_country: data["origin_country"],
      target_countries: data["target_countries"] || [],
      target_sectors: data["target_sectors"] || [],
      target_regions: data["target_regions"] || [],
      ttps: data["ttps"] || [],
      primary_tactics: data["primary_tactics"] || [],
      known_malware: data["known_malware"] || [],
      known_tools: data["known_tools"] || [],
      first_seen: parse_datetime(data["first_seen"]),
      last_seen: parse_datetime(data["last_seen"]),
      active: data["active"] || true,
      source: data["source"] || "manual",
      external_refs: data["external_refs"] || [],
      metadata: data["metadata"] || %{}
    }
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> dt
      {:error, _} -> nil
    end
  end
  defp parse_datetime(_), do: nil
end
