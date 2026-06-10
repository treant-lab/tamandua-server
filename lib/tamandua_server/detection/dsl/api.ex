defmodule TamanduaServer.Detection.DSL.API do
  @moduledoc """
  Public API for managing DSL detections.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.{DslDetection, DSL}

  @doc """
  Create a new DSL detection.
  """
  @spec create_detection(map()) :: {:ok, DslDetection.t()} | {:error, Ecto.Changeset.t()}
  def create_detection(attrs) do
    %DslDetection{}
    |> DslDetection.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, detection} = result ->
        # Load into runtime
        reload_detection(detection.id)
        result

      error ->
        error
    end
  end

  @doc """
  Update an existing DSL detection.
  """
  @spec update_detection(String.t(), map()) :: {:ok, DslDetection.t()} | {:error, Ecto.Changeset.t() | :not_found}
  def update_detection(id, attrs) do
    case Repo.get(DslDetection, id) do
      nil ->
        {:error, :not_found}

      detection ->
        detection
        |> DslDetection.changeset(Map.put(attrs, :version, detection.version + 1))
        |> Repo.update()
        |> case do
          {:ok, updated} = result ->
            # Reload into runtime
            reload_detection(updated.id)
            result

          error ->
            error
        end
    end
  end

  @doc """
  Delete a DSL detection.
  """
  @spec delete_detection(String.t()) :: {:ok, DslDetection.t()} | {:error, :not_found}
  def delete_detection(id) do
    case Repo.get(DslDetection, id) do
      nil ->
        {:error, :not_found}

      detection ->
        # Unload from runtime
        DSL.Runtime.unload_detection(detection.name)

        Repo.delete(detection)
    end
  end

  @doc """
  Get a DSL detection by ID.
  """
  @spec get_detection(String.t()) :: DslDetection.t() | nil
  def get_detection(id) do
    Repo.get(DslDetection, id)
  end

  @doc """
  Get a DSL detection by name.
  """
  @spec get_detection_by_name(String.t()) :: DslDetection.t() | nil
  def get_detection_by_name(name) do
    Repo.get_by(DslDetection, name: name)
  end

  @doc """
  List all DSL detections.
  """
  @spec list_detections(keyword()) :: [DslDetection.t()]
  def list_detections(opts \\ []) do
    query = from(d in DslDetection)

    query =
      if opts[:enabled_only] do
        where(query, [d], d.enabled == true)
      else
        query
      end

    query =
      if opts[:severity] do
        where(query, [d], d.severity == ^opts[:severity])
      else
        query
      end

    query =
      if opts[:tag] do
        where(query, [d], ^opts[:tag] in d.tags)
      else
        query
      end

    query
    |> order_by([d], desc: d.inserted_at)
    |> Repo.all()
  end

  @doc """
  Search detections by name or description.
  """
  @spec search_detections(String.t()) :: [DslDetection.t()]
  def search_detections(query_string) do
    pattern = "%#{query_string}%"

    from(d in DslDetection,
      where: ilike(d.name, ^pattern) or ilike(d.description, ^pattern),
      order_by: [desc: d.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Enable or disable a detection.
  """
  @spec toggle_detection(String.t(), boolean()) :: {:ok, DslDetection.t()} | {:error, :not_found}
  def toggle_detection(id, enabled) do
    case Repo.get(DslDetection, id) do
      nil ->
        {:error, :not_found}

      detection ->
        detection
        |> DslDetection.changeset(%{enabled: enabled})
        |> Repo.update()
        |> case do
          {:ok, updated} = result ->
            if enabled do
              reload_detection(updated.id)
            else
              DSL.Runtime.unload_detection(updated.name)
            end

            result

          error ->
            error
        end
    end
  end

  @doc """
  Reload all enabled detections into runtime.
  """
  @spec reload_all() :: {:ok, integer()}
  def reload_all do
    detections = list_detections(enabled_only: true)

    sources = Enum.map(detections, & &1.source)

    case DSL.Runtime.load_detections(sources) do
      {:ok, names} ->
        Logger.info("[DSL API] Reloaded #{length(names)} detections")
        {:ok, length(names)}

      {:error, reason} ->
        Logger.error("[DSL API] Failed to reload detections: #{reason}")
        {:error, reason}
    end
  end

  @doc """
  Reload a single detection into runtime.
  """
  @spec reload_detection(String.t()) :: :ok | {:error, term()}
  def reload_detection(id) do
    case Repo.get(DslDetection, id) do
      nil ->
        {:error, :not_found}

      %{enabled: false} ->
        {:error, :disabled}

      detection ->
        case DSL.Runtime.load_detection(detection.source) do
          {:ok, _name} ->
            :ok

          {:error, reason} ->
            Logger.error("[DSL API] Failed to reload detection #{id}: #{reason}")
            {:error, reason}
        end
    end
  end

  @doc """
  Increment trigger count for a detection.
  """
  @spec record_trigger(String.t()) :: :ok
  def record_trigger(name) do
    from(d in DslDetection,
      where: d.name == ^name,
      update: [
        inc: [trigger_count: 1],
        set: [last_triggered_at: ^DateTime.utc_now()]
      ]
    )
    |> Repo.update_all([])

    :ok
  end

  @doc """
  Get detection statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    total = Repo.aggregate(DslDetection, :count)
    enabled = from(d in DslDetection, where: d.enabled == true) |> Repo.aggregate(:count)

    by_severity =
      from(d in DslDetection,
        where: d.enabled == true,
        group_by: d.severity,
        select: {d.severity, count(d.id)}
      )
      |> Repo.all()
      |> Map.new()

    total_triggers =
      from(d in DslDetection, select: sum(d.trigger_count))
      |> Repo.one()
      || 0

    runtime_stats = DSL.Runtime.get_stats()

    %{
      total_detections: total,
      enabled_detections: enabled,
      by_severity: by_severity,
      total_triggers: total_triggers,
      runtime: runtime_stats
    }
  end

  @doc """
  Export detection to DSL source.
  """
  @spec export_detection(String.t()) :: {:ok, String.t()} | {:error, :not_found}
  def export_detection(id) do
    case Repo.get(DslDetection, id) do
      nil -> {:error, :not_found}
      detection -> {:ok, detection.source}
    end
  end

  @doc """
  Import detections from DSL sources.
  """
  @spec import_detections([String.t()], keyword()) :: {:ok, [DslDetection.t()]} | {:error, term()}
  def import_detections(sources, opts \\ []) do
    created_by = Keyword.get(opts, :created_by, "system")

    results =
      Enum.map(sources, fn source ->
        create_detection(%{source: source, created_by: created_by})
      end)

    errors = Enum.filter(results, &match?({:error, _}, &1))

    if Enum.empty?(errors) do
      detections = Enum.map(results, fn {:ok, d} -> d end)
      {:ok, detections}
    else
      {:error, "Failed to import some detections"}
    end
  end

  @doc """
  Validate DSL source without saving.
  """
  @spec validate_source(String.t()) :: :ok | {:error, String.t()}
  def validate_source(source) do
    with {:ok, ast} <- DSL.Parser.parse(source),
         {:ok, _compiled} <- DSL.Compiler.compile(ast) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get detection templates.
  """
  @spec get_templates() :: %{String.t() => String.t()}
  def get_templates do
    %{
      "lateral_movement" => """
      detection lateral_movement {
        name: "Lateral Movement via PsExec"
        description: "Detects PsExec-based lateral movement across multiple hosts"
        severity: high
        mitre: ["T1021.002", "T1570"]

        sequence within 5m {
          event e1: process_create {
            where: process.name = "psexec.exe" OR process.name = "psexec64.exe"
            capture: initiator_host, user, target
          }

          event e2: network_connect {
            where: dst_port = 445 AND src_host = e1.initiator_host
            capture: target_host
          }

          event e3: process_create {
            where: parent.name = "services.exe" AND host = e2.target_host
            capture: spawned_process
          }
        }

        aggregation {
          count(distinct e2.target_host) > 3 within 1h -> escalate to critical
          count(*) > 10 within 30m -> create_alert "Mass lateral movement detected"
        }
      }
      """,
      "credential_dumping" => """
      detection credential_dumping {
        name: "Credential Dumping with LSASS Access"
        description: "Detects suspicious access to LSASS process memory"
        severity: critical
        mitre: ["T1003.001"]

        sequence within 2m {
          event e1: process_create {
            where: process.name matches /procdump|mimikatz|comsvcs/
            capture: process_path, pid
          }

          event e2: file_write {
            where: path contains "lsass" AND path endswith ".dmp"
            capture: dump_path
          }
        }

        aggregation {
          count(*) > 1 within 10m -> escalate to critical
        }
      }
      """,
      "ransomware_behavior" => """
      detection ransomware_behavior {
        name: "Ransomware File Encryption Pattern"
        description: "Detects rapid file modifications typical of ransomware"
        severity: critical
        mitre: ["T1486"]

        sequence within 30s {
          event e1: file_write {
            where: path endswith ".encrypted" OR path endswith ".locked"
            capture: process_name, file_count
          }
        }

        aggregation {
          count(*) > 50 within 1m -> escalate to critical
          stddev(file_count) > 10 within 5m -> create_alert "Unusual file modification pattern"
        }
      }
      """,
      "c2_beaconing" => """
      detection c2_beaconing {
        name: "Command and Control Beaconing"
        description: "Detects periodic network connections indicating C2 beaconing"
        severity: high
        mitre: ["T1071", "T1573"]

        sequence within 1h {
          event e1: network_connect {
            where: protocol = "tcp" AND remote_port in [443, 80, 8080]
            capture: remote_ip, local_process
          }
        }

        aggregation {
          count(*) > 20 within 1h -> create_alert "Potential C2 beaconing detected"
          stddev(timestamp) < 5 within 1h -> escalate to high
        }
      }
      """,
      "privilege_escalation" => """
      detection privilege_escalation {
        name: "Privilege Escalation via Token Manipulation"
        description: "Detects suspicious token manipulation for privilege escalation"
        severity: high
        mitre: ["T1134"]

        sequence within 5m {
          event e1: process_create {
            where: is_elevated = false
            capture: pid, user
          }

          event e2: process_create {
            where: ppid = e1.pid AND is_elevated = true
            capture: escalated_process
          }
        }

        aggregation {
          count(*) > 2 within 15m -> escalate to critical
        }
      }
      """
    }
  end
end
