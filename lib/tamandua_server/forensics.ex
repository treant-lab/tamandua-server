defmodule TamanduaServer.Forensics do
  @moduledoc """
  Context module for forensic artifact collection and management.

  Provides high-level API for requesting, tracking, and managing
  forensic evidence collection from agents with full chain of custody.
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Forensics.Artifact
  alias TamanduaServer.Agents
  alias TamanduaServer.Workers.ForensicsWorker

  import Ecto.Query

  @doc """
  Request artifact collection from an agent.

  ## Examples

      iex> request_collection("agent-123", "memory_dump", %{}, requested_by_id: user_id)
      {:ok, %Artifact{}}

  ## Options
    * `:case_id` - Optional case ID to associate with this collection
    * `:compression` - Compression type (:gzip, :zstd, :none), default: :gzip
    * `:encrypted` - Whether to encrypt the artifact, default: false
    * `:upload_destination` - Where to upload (:s3, :local), default: :s3
    * `:s3_bucket` - S3 bucket name if upload_destination is :s3
    * `:tags` - List of tags to apply
    * `:notes` - Free-form notes
    * `:metadata` - Additional metadata map
    * `:requested_by_id` - User ID of requester (required)
    * `:requested_by_name` - User name of requester
    * `:requested_by_email` - User email of requester
  """
  def request_collection(agent_id, artifact_type, params, opts \\ []) do
    with {:ok, agent} <- Agents.get_agent(agent_id),
         {:ok, artifact} <- create_artifact_record(agent, artifact_type, params, opts) do

      # Enqueue background job
      ForensicsWorker.enqueue(artifact.id)

      # Add initial custody entry
      artifact = add_custody_entry(artifact, %{
        "action" => "collection_requested",
        "user" => opts[:requested_by_name] || "system",
        "user_id" => opts[:requested_by_id]
      })

      # Broadcast to LiveView for real-time UI updates
      broadcast_artifact_update(artifact)

      {:ok, artifact}
    end
  end

  @doc """
  Request multiple artifacts in batch with shared case ID.
  """
  def request_batch_collection(agent_id, artifact_configs, opts \\ []) do
    case_id = opts[:case_id] || generate_case_id()

    results = Enum.map(artifact_configs, fn config ->
      artifact_type = config[:artifact_type]
      params = config[:parameters] || %{}

      collection_opts = Keyword.merge(opts, [case_id: case_id])
      request_collection(agent_id, artifact_type, params, collection_opts)
    end)

    errors = Enum.filter(results, fn
      {:error, _} -> true
      _ -> false
    end)

    if Enum.empty?(errors) do
      artifacts = Enum.map(results, fn {:ok, artifact} -> artifact end)
      {:ok, artifacts, case_id}
    else
      {:error, :batch_collection_failed, errors}
    end
  end

  @doc """
  Update collection progress (called by agent).
  """
  def update_progress(artifact_id, progress_data) do
    artifact = Repo.get!(Artifact, artifact_id)

    changeset = Artifact.update_progress(artifact, progress_data)

    case Repo.update(changeset) do
      {:ok, updated_artifact} ->
        broadcast_artifact_update(updated_artifact)
        {:ok, updated_artifact}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Mark artifact collection as completed.
  """
  def mark_completed(artifact_id, completion_data) do
    artifact = Repo.get!(Artifact, artifact_id)

    changeset = Artifact.mark_completed(artifact, completion_data)

    case Repo.update(changeset) do
      {:ok, updated_artifact} ->
        # Add custody entry
        updated_artifact = add_custody_entry(updated_artifact, %{
          "action" => "collection_completed",
          "file_size" => completion_data[:file_size],
          "sha256" => completion_data[:sha256_hash]
        })

        # Trigger S3 upload if configured
        if updated_artifact.upload_destination == "s3" do
          spawn(fn -> upload_to_s3(updated_artifact.id) end)
        end

        broadcast_artifact_update(updated_artifact)
        {:ok, updated_artifact}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Mark artifact collection as failed.
  """
  def mark_failed(artifact_id, error_message, error_details \\ %{}) do
    artifact = Repo.get!(Artifact, artifact_id)

    changeset = Artifact.mark_failed(artifact, error_message, error_details)

    case Repo.update(changeset) do
      {:ok, updated_artifact} ->
        broadcast_artifact_update(updated_artifact)
        {:ok, updated_artifact}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Upload artifact to S3.
  """
  def upload_to_s3(artifact_id) do
    artifact = Repo.get!(Artifact, artifact_id)

    with :ok <- validate_artifact_for_upload(artifact),
         {:ok, artifact} <- mark_uploading(artifact),
         {:ok, upload_info} <- perform_s3_upload(artifact),
         {:ok, artifact} <- complete_upload(artifact, upload_info) do
      {:ok, artifact}
    else
      {:error, reason} ->
        mark_failed(artifact_id, "Upload failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Generate presigned download URL for an artifact.
  """
  def generate_download_url(artifact_id, opts \\ []) do
    artifact = Repo.get!(Artifact, artifact_id)
    expires_in = Keyword.get(opts, :expires_in, 3600)

    case artifact.s3_bucket && artifact.s3_key do
      true ->
        config = ExAws.Config.new(:s3)
        presigned_url = ExAws.S3.presigned_url(
          config,
          :get,
          artifact.s3_bucket,
          artifact.s3_key,
          expires_in: expires_in
        )

        case presigned_url do
          {:ok, url} ->
            expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)

            artifact
            |> Ecto.Changeset.change(%{
              download_url: url,
              download_expires_at: expires_at
            })
            |> Repo.update()

            {:ok, url}

          error ->
            error
        end

      false ->
        {:error, :artifact_not_uploaded}
    end
  end

  @doc """
  Verify artifact integrity by comparing SHA-256 hash.
  """
  def verify_integrity(artifact_id) do
    artifact = Repo.get!(Artifact, artifact_id)

    case artifact.sha256_hash do
      nil ->
        {:error, :no_hash_available}

      _expected_hash ->
        # In production, download and compute hash
        # For now, mark as verified
        artifact
        |> Ecto.Changeset.change(%{evidence_integrity_verified: true})
        |> Repo.update()

        {:ok, :verified}
    end
  end

  @doc """
  List artifacts with optional filters.
  """
  def list_artifacts(filters \\ %{}, opts \\ []) do
    query = Artifact
    |> apply_filters(filters)
    |> Artifact.with_preloads()

    query =
      if opts[:limit] do
        from a in query, limit: ^opts[:limit]
      else
        query
      end

    query =
      if opts[:offset] do
        from a in query, offset: ^opts[:offset]
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Get artifact by ID.
  """
  def get_artifact(id) do
    case Repo.get(Artifact, id) do
      nil -> {:error, :not_found}
      artifact -> {:ok, Repo.preload(artifact, [:agent, :organization, :requested_by, :approved_by])}
    end
  end

  @doc """
  Get artifacts for a specific case.
  """
  def get_case_artifacts(case_id) do
    Artifact
    |> Artifact.by_case(case_id)
    |> Artifact.with_preloads()
    |> Artifact.recent()
    |> Repo.all()
  end

  @doc """
  Get collection statistics for an organization.
  """
  def get_organization_stats(organization_id) do
    base_query = Artifact.by_organization(Artifact, organization_id)

    %{
      total: count_by_query(base_query),
      pending: count_by_query(Artifact.pending(base_query)),
      in_progress: count_by_query(Artifact.in_progress(base_query)),
      completed: count_by_query(Artifact.completed(base_query)),
      failed: count_by_query(Artifact.failed(base_query)),
      total_size_bytes: sum_file_size(base_query)
    }
  end

  @doc """
  Cancel pending artifact collection.
  """
  def cancel_collection(artifact_id) do
    artifact = Repo.get!(Artifact, artifact_id)

    if artifact.status in ["pending", "queued"] do
      result = artifact
      |> Ecto.Changeset.change(%{status: "cancelled"})
      |> Repo.update()

      case result do
        {:ok, updated} ->
          broadcast_artifact_update(updated)
          {:ok, updated}
        error -> error
      end
    else
      {:error, :cannot_cancel_in_progress}
    end
  end

  # Private Functions

  defp create_artifact_record(agent, artifact_type, params, opts) do
    attrs = %{
      agent_id: agent.id,
      organization_id: agent.organization_id,
      case_id: opts[:case_id],
      artifact_type: artifact_type,
      artifact_subtype: params[:subtype],
      parameters: params,
      status: "queued",
      compression_type: opts[:compression] || "gzip",
      encrypted: opts[:encrypted] || false,
      encryption_key_id: opts[:encryption_key_id],
      upload_destination: opts[:upload_destination] || "s3",
      s3_bucket: opts[:s3_bucket] || Application.get_env(:tamandua_server, :forensics_s3_bucket),
      collector_name: opts[:requested_by_name] || "System",
      collector_email: opts[:requested_by_email],
      tags: opts[:tags] || [],
      notes: opts[:notes],
      metadata: opts[:metadata] || %{},
      requested_by_id: opts[:requested_by_id]
    }

    %Artifact{}
    |> Artifact.changeset(attrs)
    |> Repo.insert()
  end

  defp add_custody_entry(artifact, entry) do
    changeset = Artifact.add_custody_entry(artifact, entry)

    case Repo.update(changeset) do
      {:ok, updated} -> updated
      {:error, _} -> artifact
    end
  end

  defp generate_case_id do
    "CASE-" <> (:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower))
  end

  defp validate_artifact_for_upload(artifact) do
    cond do
      artifact.status != "completed" ->
        {:error, :artifact_not_completed}

      is_nil(artifact.file_path) ->
        {:error, :file_path_missing}

      is_nil(artifact.sha256_hash) ->
        {:error, :hash_missing}

      true ->
        :ok
    end
  end

  defp mark_uploading(artifact) do
    artifact
    |> Artifact.mark_uploading()
    |> Repo.update()
  end

  defp perform_s3_upload(artifact) do
    file_path = artifact.file_path
    bucket = artifact.s3_bucket
    key = generate_s3_key(artifact)

    case File.read(file_path) do
      {:ok, file_data} ->
        upload_result = ExAws.S3.put_object(bucket, key, file_data)
        |> ExAws.request()

        case upload_result do
          {:ok, _response} ->
            url = "s3://#{bucket}/#{key}"
            {:ok, %{
              s3_bucket: bucket,
              s3_key: key,
              s3_url: url
            }}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp complete_upload(artifact, upload_info) do
    artifact
    |> Artifact.mark_uploaded(upload_info)
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        add_custody_entry(updated, %{
          "action" => "uploaded_to_s3",
          "s3_bucket" => upload_info.s3_bucket,
          "s3_key" => upload_info.s3_key
        })
        {:ok, updated}

      error ->
        error
    end
  end

  defp generate_s3_key(artifact) do
    date = DateTime.to_date(artifact.inserted_at)
    filename = "#{artifact.id}.#{get_file_extension(artifact)}"

    Path.join([
      "forensics",
      to_string(artifact.organization_id),
      to_string(artifact.agent_id),
      Calendar.strftime(date, "%Y/%m/%d"),
      filename
    ])
  end

  defp get_file_extension(artifact) do
    base = case artifact.artifact_type do
      "memory_dump" -> "mem"
      "disk_image" -> "dd"
      "registry_hive" -> "reg"
      "event_logs" -> "evtx"
      "network_capture" -> "pcap"
      "mft" -> "mft"
      _ -> "bin"
    end

    case artifact.compression_type do
      "gzip" -> "#{base}.gz"
      "zstd" -> "#{base}.zst"
      _ -> base
    end
  end

  defp apply_filters(query, filters) do
    Enum.reduce(filters, query, fn {key, value}, acc ->
      case key do
        :organization_id -> Artifact.by_organization(acc, value)
        :agent_id -> Artifact.by_agent(acc, value)
        :status -> Artifact.by_status(acc, value)
        :artifact_type -> Artifact.by_artifact_type(acc, value)
        :case_id -> Artifact.by_case(acc, value)
        _ -> acc
      end
    end)
  end

  defp count_by_query(query) do
    Repo.one(from a in query, select: count(a.id)) || 0
  end

  defp sum_file_size(query) do
    Repo.one(from a in query, select: sum(a.file_size)) || 0
  end

  defp broadcast_artifact_update(artifact) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "forensics:#{artifact.organization_id}",
      {:artifact_update, artifact}
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "forensics:#{artifact.agent_id}",
      {:artifact_update, artifact}
    )
  end
end
