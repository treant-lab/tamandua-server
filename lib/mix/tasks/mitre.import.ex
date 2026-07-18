defmodule Mix.Tasks.Mitre.Import do
  @moduledoc """
  Import MITRE ATT&CK data from STIX bundle.

  ## Usage

      # Import from default location (priv/mitre/enterprise-attack.json)
      mix mitre.import

      # Import from specific file
      mix mitre.import --source path/to/stix.json

      # Force re-import (replace existing data)
      mix mitre.import --force

      # Download latest from GitHub then import
      mix mitre.import --download

  ## Options

    * `--source` - Path to STIX JSON file or URL
    * `--force` - Force re-import even if data exists
    * `--download` - Download latest from MITRE CTI repository first

  ## Examples

      # Download and import latest
      mix mitre.import --download --force

      # Import custom data
      mix mitre.import --source priv/mitre/custom-techniques.json
  """

  use Mix.Task

  alias TamanduaServer.Mitre.AttackFramework

  @shortdoc "Import MITRE ATT&CK data"

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, _args, _} = OptionParser.parse(args,
      switches: [source: :string, force: :boolean, download: :boolean],
      aliases: [s: :source, f: :force, d: :download]
    )

    source = Keyword.get(opts, :source, "priv/mitre/enterprise-attack.json")
    force = Keyword.get(opts, :force, false)
    download = Keyword.get(opts, :download, false)

    if download do
      Mix.shell().info("Downloading latest MITRE ATT&CK data from GitHub...")

      case AttackFramework.download_latest_stix() do
        {:ok, path} ->
          Mix.shell().info("✓ Downloaded to #{path}")
          _source = path

        {:error, reason} ->
          Mix.shell().error("✗ Download failed: #{inspect(reason)}")
          exit(:shutdown)
      end
    end

    Mix.shell().info("Importing MITRE ATT&CK data from #{source}...")

    case AttackFramework.import_attack_data(source: source, force: force) do
      {:ok, :already_imported} ->
        Mix.shell().info("ℹ Data already imported. Use --force to re-import.")

      {:ok, stats} ->
        Mix.shell().info("✓ Import completed successfully!")
        Mix.shell().info("  - Techniques: #{stats.techniques}")
        Mix.shell().info("  - Threat Actors: #{stats.actors}")

      {:error, :file_not_found} ->
        Mix.shell().error("✗ File not found: #{source}")
        Mix.shell().info("\nTo download the latest data:")
        Mix.shell().info("  mix mitre.import --download")
        exit(:shutdown)

      {:error, reason} ->
        Mix.shell().error("✗ Import failed: #{inspect(reason)}")
        exit(:shutdown)
    end
  end
end
