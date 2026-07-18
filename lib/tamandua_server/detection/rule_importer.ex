defmodule TamanduaServer.Detection.RuleImporter do
  @moduledoc """
  Orchestrates rule import operations from various sources.
  Handles files, directories, GitHub repos, and URLs.
  """

  alias TamanduaServer.Detection
  alias TamanduaServer.Detection.{
    RuleImportJob,
    RuleValidator,
    RuleVersion,
    IOC
  }
  alias TamanduaServer.Repo

  import Ecto.Query
  require Logger

  @doc """
  Start a rule import job.
  Returns {:ok, job} or {:error, reason}.
  """
  def start_import(attrs) do
    changeset = RuleImportJob.changeset(%RuleImportJob{}, attrs)

    with {:ok, job} <- Repo.insert(changeset) do
      # Process asynchronously using Oban or Task
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        process_import(job)
      end)

      {:ok, job}
    end
  end

  @doc """
  Process an import job.
  """
  def process_import(%RuleImportJob{} = job) do
    job = job |> Repo.preload([:organization, :user])

    Logger.info("Starting import job #{job.id} for #{job.type} rules from #{job.source_type}")

    job
    |> RuleImportJob.mark_started()
    |> Repo.update!()

    result = case job.source_type do
      "file" -> import_from_file(job)
      "directory" -> import_from_directory(job)
      "github" -> import_from_github(job)
      "url" -> import_from_url(job)
      _ -> {:error, "Unknown source type: #{job.source_type}"}
    end

    case result do
      {:ok, stats} ->
        job
        |> RuleImportJob.update_progress(stats)
        |> RuleImportJob.mark_completed()
        |> Repo.update!()

        Logger.info("Import job #{job.id} completed: #{stats.imported_rules} imported, #{stats.skipped_rules} skipped, #{stats.failed_rules} failed")

      {:error, reason} ->
        error_msg = error_to_string(reason)

        job
        |> RuleImportJob.mark_failed(error_msg)
        |> Repo.update!()

        Logger.error("Import job #{job.id} failed: #{error_msg}")
    end
  end

  @doc """
  Import rules from file content.
  """
  def import_from_content(content, job_or_attrs) do
    job = ensure_job(job_or_attrs)

    case job.type do
      "yara" -> import_yara_content(content, job)
      "sigma" -> import_sigma_content(content, job)
      "ioc" -> import_ioc_content(content, job)
      _ -> {:error, "Unknown rule type: #{job.type}"}
    end
  end

  # --- Private Functions ---

  defp import_from_file(%RuleImportJob{metadata: %{"file_path" => path}} = job) do
    case File.read(path) do
      {:ok, content} ->
        import_from_content(content, job)

      {:error, reason} ->
        {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  defp import_from_file(_job) do
    {:error, "No file_path provided in job metadata"}
  end

  defp import_from_directory(%RuleImportJob{metadata: %{"directory_path" => dir_path}} = job) do
    extension = case job.type do
      "yara" -> ".yar"
      "sigma" -> ".yml"
      "ioc" -> ".json"
      _ -> "*"
    end

    pattern = Path.join(dir_path, "**/*#{extension}")

    files = Path.wildcard(pattern)

    if Enum.empty?(files) do
      {:error, "No #{job.type} files found in directory"}
    else
      import_multiple_files(files, job)
    end
  end

  defp import_from_directory(_job) do
    {:error, "No directory_path provided in job metadata"}
  end

  defp import_from_github(%RuleImportJob{source_url: url} = job) when is_binary(url) do
    with {:ok, repo_info} <- parse_github_url(url),
         {:ok, files} <- fetch_github_repo_files(repo_info, job) do
      import_multiple_files(files, job)
    end
  end

  defp import_from_github(_job) do
    {:error, "No GitHub URL provided"}
  end

  defp import_from_url(%RuleImportJob{source_url: url} = job) when is_binary(url) do
    case fetch_url_content(url) do
      {:ok, content} ->
        import_from_content(content, job)

      {:error, reason} ->
        {:error, "Failed to fetch URL: #{inspect(reason)}"}
    end
  end

  defp import_from_url(_job) do
    {:error, "No URL provided"}
  end

  defp import_multiple_files(files, job) do
    total = length(files)

    job
    |> RuleImportJob.update_progress(%{total_rules: total})
    |> Repo.update!()

    results =
      Enum.reduce(files, %{imported: 0, skipped: 0, failed: 0}, fn file, acc ->
        case File.read(file) do
          {:ok, content} ->
            case import_single_rule(content, job) do
              {:ok, _rule} ->
                %{acc | imported: acc.imported + 1}

              {:skipped, _reason} ->
                %{acc | skipped: acc.skipped + 1}

              {:error, reason} ->
                Logger.warning("Failed to import #{file}: #{inspect(reason)}")
                %{acc | failed: acc.failed + 1}
            end

          {:error, reason} ->
            Logger.warning("Failed to read #{file}: #{inspect(reason)}")
            %{acc | failed: acc.failed + 1}
        end
      end)

    {:ok,
     %{
       total_rules: total,
       imported_rules: results.imported,
       skipped_rules: results.skipped,
       failed_rules: results.failed
     }}
  end

  defp import_yara_content(content, job) do
    # Split content by "rule " to handle multiple rules in one file
    rules = String.split(content, ~r/(?=^rule\s+)/m)
    |> Enum.filter(&String.contains?(&1, "rule "))

    if Enum.empty?(rules) do
      {:error, "No YARA rules found in content"}
    else
      import_yara_rules(rules, job)
    end
  end

  defp import_yara_rules(rules, job) do
    total = length(rules)

    job
    |> RuleImportJob.update_progress(%{total_rules: total})
    |> Repo.update!()

    results =
      Enum.reduce(rules, %{imported: 0, skipped: 0, failed: 0}, fn rule_content, acc ->
        case import_single_rule(rule_content, job) do
          {:ok, _rule} ->
            %{acc | imported: acc.imported + 1}

          {:skipped, _reason} ->
            %{acc | skipped: acc.skipped + 1}

          {:error, _reason} ->
            %{acc | failed: acc.failed + 1}
        end
      end)

    {:ok,
     %{
       total_rules: total,
       imported_rules: results.imported,
       skipped_rules: results.skipped,
       failed_rules: results.failed
     }}
  end

  defp import_sigma_content(content, job) do
    import_single_rule(content, job)
    |> case do
      {:ok, _rule} ->
        {:ok, %{total_rules: 1, imported_rules: 1, skipped_rules: 0, failed_rules: 0}}

      {:skipped, _reason} ->
        {:ok, %{total_rules: 1, imported_rules: 0, skipped_rules: 1, failed_rules: 0}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp import_ioc_content(content, job) do
    case parse_ioc_format(content, job.metadata["format"] || "json") do
      {:ok, iocs} when is_list(iocs) ->
        import_iocs(iocs, job)

      {:ok, ioc} when is_map(ioc) ->
        import_iocs([ioc], job)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp import_iocs(iocs, job) do
    total = length(iocs)

    job
    |> RuleImportJob.update_progress(%{total_rules: total})
    |> Repo.update!()

    results =
      Enum.reduce(iocs, %{imported: 0, skipped: 0, failed: 0}, fn ioc_data, acc ->
        case import_single_ioc(ioc_data, job) do
          {:ok, _ioc} ->
            %{acc | imported: acc.imported + 1}

          {:skipped, _reason} ->
            %{acc | skipped: acc.skipped + 1}

          {:error, _reason} ->
            %{acc | failed: acc.failed + 1}
        end
      end)

    {:ok,
     %{
       total_rules: total,
       imported_rules: results.imported,
       skipped_rules: results.skipped,
       failed_rules: results.failed
     }}
  end

  defp import_single_rule(content, %RuleImportJob{type: "yara"} = job) do
    with {:ok, metadata} <- RuleValidator.validate_yara(content),
         {:ok, existing} <- RuleValidator.check_duplicate(:yara, metadata.name, job.organization_id),
         {:ok, rule} <- handle_yara_conflict(existing, content, metadata, job) do
      # Create version snapshot
      create_version_snapshot(rule, :yara, job.user_id, "Imported from #{job.source_type}")
      {:ok, rule}
    else
      {:skipped, reason} -> {:skipped, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  defp import_single_rule(content, %RuleImportJob{type: "sigma"} = job) do
    with {:ok, parsed} <- RuleValidator.validate_sigma(content),
         {:ok, existing} <- RuleValidator.check_duplicate(:sigma, parsed.name, job.organization_id),
         {:ok, rule} <- handle_sigma_conflict(existing, parsed, job) do
      # Create version snapshot
      create_version_snapshot(rule, :sigma, job.user_id, "Imported from #{job.source_type}")
      {:ok, rule}
    else
      {:skipped, reason} -> {:skipped, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  defp import_single_ioc(ioc_data, job) do
    with {:ok, normalized} <- RuleValidator.validate_ioc(ioc_data),
         {:ok, existing} <- RuleValidator.check_duplicate(:ioc, {normalized.type, normalized.value}, job.organization_id),
         {:ok, ioc} <- handle_ioc_conflict(existing, normalized, job) do
      {:ok, ioc}
    else
      {:skipped, reason} -> {:skipped, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  defp handle_yara_conflict(nil, content, metadata, job) do
    # No conflict, create new rule
    attrs = %{
      name: metadata.name,
      source: content,
      description: metadata.description,
      author: metadata.author,
      tags: metadata.tags,
      organization_id: job.organization_id,
      enabled: true
    }

    Detection.create_yara_rule(attrs)
  end

  defp handle_yara_conflict(existing, _content, _metadata, %{conflict_resolution: "skip"}) do
    {:skipped, "Rule already exists: #{existing.name}"}
  end

  defp handle_yara_conflict(existing, content, metadata, %{conflict_resolution: "overwrite"}) do
    attrs = %{
      source: content,
      description: metadata.description || existing.description,
      author: metadata.author || existing.author,
      tags: metadata.tags || existing.tags
    }

    Detection.update_yara_rule(existing, attrs)
  end

  defp handle_yara_conflict(existing, content, metadata, %{conflict_resolution: "rename"}) do
    # Find unique name
    new_name = find_unique_name(existing.name, :yara, existing.organization_id)

    attrs = %{
      name: new_name,
      source: content,
      description: metadata.description,
      author: metadata.author,
      tags: metadata.tags,
      organization_id: existing.organization_id,
      enabled: true
    }

    Detection.create_yara_rule(attrs)
  end

  defp handle_sigma_conflict(nil, parsed, job) do
    # No conflict, create new rule
    attrs = Map.put(parsed, :organization_id, job.organization_id)
    Detection.create_sigma_rule(attrs)
  end

  defp handle_sigma_conflict(existing, _parsed, %{conflict_resolution: "skip"}) do
    {:skipped, "Rule already exists: #{existing.name}"}
  end

  defp handle_sigma_conflict(existing, parsed, %{conflict_resolution: "overwrite"}) do
    Detection.update_sigma_rule(existing, parsed)
  end

  defp handle_sigma_conflict(existing, parsed, %{conflict_resolution: "rename"}) do
    new_name = find_unique_name(existing.name, :sigma, existing.organization_id)

    attrs =
      parsed
      |> Map.put(:name, new_name)
      |> Map.put(:organization_id, existing.organization_id)

    Detection.create_sigma_rule(attrs)
  end

  defp handle_ioc_conflict(nil, normalized, job) do
    attrs = Map.put(normalized, :organization_id, job.organization_id)

    %IOC{}
    |> IOC.changeset(attrs)
    |> Repo.insert()
  end

  defp handle_ioc_conflict(existing, _normalized, %{conflict_resolution: "skip"}) do
    {:skipped, "IOC already exists: #{existing.type} - #{existing.value}"}
  end

  defp handle_ioc_conflict(existing, normalized, %{conflict_resolution: "overwrite"}) do
    existing
    |> IOC.changeset(normalized)
    |> Repo.update()
  end

  defp handle_ioc_conflict(existing, _normalized, %{conflict_resolution: "rename"}) do
    # For IOCs, we can't really rename, so just skip
    {:skipped, "IOC already exists and cannot be renamed: #{existing.type} - #{existing.value}"}
  end

  defp find_unique_name(base_name, rule_type, org_id, suffix \\ 1) do
    new_name = "#{base_name}_#{suffix}"

    case RuleValidator.check_duplicate(rule_type, new_name, org_id) do
      {:ok, nil} -> new_name
      {:ok, _existing} -> find_unique_name(base_name, rule_type, org_id, suffix + 1)
    end
  end

  defp create_version_snapshot(rule, rule_type, user_id, change_summary) do
    # Get current version number
    version_number =
      from(v in RuleVersion,
        where: v.rule_type == ^to_string(rule_type) and v.rule_id == ^rule.id,
        select: max(v.version)
      )
      |> Repo.one()
      |> case do
        nil -> 1
        num -> num + 1
      end

    version = RuleVersion.from_rule(rule, rule_type, user_id, change_summary)

    version
    |> RuleVersion.changeset(%{version: version_number})
    |> Repo.insert()
  end

  defp parse_github_url(url) do
    # Parse GitHub URL: https://github.com/owner/repo or https://github.com/owner/repo/tree/branch/path
    regex = ~r{github\.com/([^/]+)/([^/]+)(?:/tree/([^/]+)(/.*)?)?}

    case Regex.run(regex, url) do
      [_, owner, repo | rest] ->
        branch = Enum.at(rest, 0) || "main"
        path = Enum.at(rest, 1) || ""

        {:ok, %{owner: owner, repo: String.replace_suffix(repo, ".git", ""), branch: branch, path: path}}

      _ ->
        {:error, "Invalid GitHub URL format"}
    end
  end

  defp fetch_github_repo_files(repo_info, job) do
    # Use GitHub API to fetch repository contents
    api_url = "https://api.github.com/repos/#{repo_info.owner}/#{repo_info.repo}/contents#{repo_info.path}?ref=#{repo_info.branch}"

    case fetch_json_api(api_url) do
      {:ok, items} when is_list(items) ->
        # Filter for relevant files
        extension = case job.type do
          "yara" -> ".yar"
          "sigma" -> ".yml"
          "ioc" -> ".json"
          _ -> ""
        end

        files =
          items
          |> Enum.filter(&(&1["type"] == "file" && String.ends_with?(&1["name"], extension)))
          |> Enum.map(& &1["download_url"])

        # Download file contents
        downloaded =
          Enum.map(files, fn url ->
            case fetch_url_content(url) do
              {:ok, content} ->
                # Write to temp file
                temp_path = Path.join(System.tmp_dir!(), "tamandua_import_#{:rand.uniform(999999)}")
                File.write!(temp_path, content)
                temp_path

              _ ->
                nil
            end
          end)
          |> Enum.filter(&(!is_nil(&1)))

        {:ok, downloaded}

      {:ok, item} when is_map(item) ->
        # Single file - check type inside body since Access.get not allowed in guards
        if item["type"] == "file" do
          case fetch_url_content(item["download_url"]) do
            {:ok, content} ->
              temp_path = Path.join(System.tmp_dir!(), "tamandua_import_#{:rand.uniform(999999)}")
              File.write!(temp_path, content)
              {:ok, [temp_path]}

            error ->
              error
          end
        else
          {:error, :not_a_file}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_json_api(url) do
    headers = [
      {"Accept", "application/vnd.github.v3+json"},
      {"User-Agent", "Tamandua-EDR"}
    ]

    case Req.get(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status}} ->
        {:error, "GitHub API returned status #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_url_content(url) do
    case Req.get(url) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_ioc_format(content, "json") do
    case Jason.decode(content) do
      {:ok, data} -> {:ok, data}
      {:error, reason} -> {:error, "Invalid JSON: #{inspect(reason)}"}
    end
  end

  defp parse_ioc_format(content, "csv") do
    # Simple CSV parsing for IOCs
    lines = String.split(content, "\n", trim: true)

    case lines do
      [header | rows] ->
        headers = String.split(header, ",") |> Enum.map(&String.trim/1)

        iocs =
          Enum.map(rows, fn row ->
            values = String.split(row, ",") |> Enum.map(&String.trim/1)
            Enum.zip(headers, values) |> Map.new()
          end)

        {:ok, iocs}

      _ ->
        {:error, "Invalid CSV format"}
    end
  end

  defp parse_ioc_format(_content, "stix") do
    # TODO: Implement STIX 2.1 parser
    {:error, "STIX format not yet supported"}
  end

  defp parse_ioc_format(_content, format) do
    {:error, "Unsupported IOC format: #{format}"}
  end

  defp ensure_job(%RuleImportJob{} = job), do: job
  defp ensure_job(attrs) when is_map(attrs) do
    struct(RuleImportJob, attrs)
  end

  defp error_to_string(error) when is_binary(error), do: error
  defp error_to_string(error), do: inspect(error)
end
