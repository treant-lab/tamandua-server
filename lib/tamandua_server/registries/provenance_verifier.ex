defmodule TamanduaServer.Registries.ProvenanceVerifier do
  @moduledoc """
  SLSA-style provenance chain verification.

  Provides cryptographic verification of model provenance chains,
  SLSA Build Level computation, and provenance entry management.

  All operations call the Python ML service provenance endpoints.

  ## SLSA Levels

  - L0: No provenance
  - L1: Attestation exists (provenance documented)
  - L2: Signed attestation (cryptographically signed)
  - L3: Hardened build (isolated builder, verified inputs)

  ## Example

      iex> ProvenanceVerifier.verify_chain(model_id)
      {:ok, %{valid: true, slsa_level: "SLSA Build L2", entry_count: 5}}

      iex> ProvenanceVerifier.add_entry(model_id, "training_completed", %{accuracy: 0.95})
      {:ok, %{entry_id: "uuid", entry_hash: "sha256:...", signature: "..."}}
  """

  require Logger

  alias TamanduaServer.Registries.{ModelProvenance, ProvenanceEntry}
  alias TamanduaServer.Repo

  import Ecto.Query

  @default_ml_service_url "http://localhost:8000"
  @timeout 30_000

  @valid_event_types ~w(
    training_started dataset_loaded checkpoint_saved training_completed
    model_converted model_published model_deployed scan_completed
  )

  # ---------------------------------------------------------------------------
  # Type Definitions
  # ---------------------------------------------------------------------------

  @type provenance_entry :: %{
    entry_id: String.t(),
    event_type: String.t(),
    timestamp: String.t(),
    previous_hash: String.t() | nil,
    subject: map(),
    builder: map(),
    metadata: map(),
    materials: [map()]
  }

  @type signed_entry :: %{
    entry: provenance_entry(),
    entry_hash: String.t(),
    signature: String.t() | nil,
    signer_public_key: String.t() | nil
  }

  @type verification_result :: %{
    valid: boolean(),
    slsa_level: String.t(),
    entry_count: integer(),
    issues: [String.t()],
    verified_at: String.t()
  }

  @type slsa_level :: %{
    level: integer(),
    name: String.t(),
    description: String.t(),
    requirements_met: [String.t()],
    requirements_missing: [String.t()]
  }

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Verify the entire provenance chain for a model.

  Fetches all provenance entries for the model and verifies:
  - Hash chain integrity
  - Signature validity
  - Entry ordering

  ## Parameters

    * `model_id` - UUID or identifier of the model

  ## Returns

    * `{:ok, verification_result()}` - Verification completed
    * `{:error, reason}` - Verification failed

  ## Example

      iex> ProvenanceVerifier.verify_chain("model-123")
      {:ok, %{valid: true, slsa_level: "SLSA Build L2"}}
  """
  @spec verify_chain(String.t()) :: {:ok, verification_result()} | {:error, String.t()}
  def verify_chain(model_id) when is_binary(model_id) do
    # Get entries from database
    case get_chain(model_id) do
      {:ok, %{entries: entries}} when length(entries) > 0 ->
        # Call ML service to verify
        verify_entries(entries)

      {:ok, %{entries: []}} ->
        {:ok, %{
          valid: true,
          slsa_level: "SLSA Build L0",
          entry_count: 0,
          issues: [],
          verified_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Compute the SLSA Build Level for a model's provenance.

  ## Parameters

    * `model_id` - UUID or identifier of the model

  ## Returns

    * `{:ok, slsa_level()}` - SLSA level computed
    * `{:error, reason}` - Computation failed

  ## Example

      iex> ProvenanceVerifier.compute_slsa_level("model-123")
      {:ok, %{level: 2, name: "SLSA Build L2", description: "Signed attestation"}}
  """
  @spec compute_slsa_level(String.t()) :: {:ok, slsa_level()} | {:error, String.t()}
  def compute_slsa_level(model_id) when is_binary(model_id) do
    case verify_chain(model_id) do
      {:ok, result} ->
        # Parse SLSA level from result
        level = parse_slsa_level(result.slsa_level)
        {:ok, level}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get the full provenance chain for a model.

  ## Parameters

    * `model_id` - UUID or identifier of the model

  ## Returns

    * `{:ok, %{entries: [...], slsa_level: "...", entry_count: N}}`
    * `{:error, reason}`
  """
  @spec get_chain(String.t()) :: {:ok, map()} | {:error, String.t()}
  def get_chain(model_id) when is_binary(model_id) do
    # Try to get from database first
    case get_entries_from_db(model_id) do
      {:ok, entries} ->
        {:ok, %{
          entries: entries,
          slsa_level: compute_level_from_entries(entries),
          entry_count: length(entries)
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Add a new provenance entry for a model.

  Creates and signs a new provenance entry, linking it to the
  previous entry in the chain.

  ## Parameters

    * `model_id` - UUID or identifier of the model
    * `event_type` - Type of event (training_started, model_published, etc.)
    * `metadata` - Additional context for the event
    * `opts` - Options:
      * `:subject` - Model subject info {name, digest}
      * `:builder` - Builder info {id, version}
      * `:materials` - Input materials [{uri, digest}, ...]

  ## Returns

    * `{:ok, signed_entry()}` - Entry created and signed
    * `{:error, reason}` - Creation failed

  ## Example

      iex> ProvenanceVerifier.add_entry("model-123", "training_completed", %{accuracy: 0.95})
      {:ok, %{entry_id: "uuid", entry_hash: "sha256:...", signature: "..."}}
  """
  @spec add_entry(String.t(), String.t(), map(), keyword()) :: {:ok, signed_entry()} | {:error, String.t()}
  def add_entry(model_id, event_type, metadata, opts \\ []) do
    unless event_type in @valid_event_types do
      {:error, "Invalid event_type. Must be one of: #{Enum.join(@valid_event_types, ", ")}"}
    else
      # Get previous hash from last entry
      previous_hash = get_last_entry_hash(model_id)

      # Create entry via ML service
      case create_entry_via_ml(event_type, metadata, previous_hash, opts) do
        {:ok, signed_entry} ->
          # Store in database
          save_entry_to_db(model_id, signed_entry)
          {:ok, signed_entry}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Private: ML Service Communication
  # ---------------------------------------------------------------------------

  defp verify_entries(entries) do
    url = "#{ml_service_url()}/api/v1/security/provenance/verify"

    body = %{"entries" => entries}

    case Req.post(url,
      json: body,
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, parse_verification_result(response)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "ML service request failed: #{inspect(reason)}"}
    end
  end

  defp create_entry_via_ml(event_type, metadata, previous_hash, opts) do
    url = "#{ml_service_url()}/api/v1/security/provenance/create-entry"

    body = %{
      "event_type" => event_type,
      "metadata" => metadata,
      "subject" => Keyword.get(opts, :subject, %{"name" => "model"}),
      "builder" => Keyword.get(opts, :builder),
      "materials" => Keyword.get(opts, :materials),
      "previous_hash" => previous_hash
    }

    case Req.post(url,
      json: body,
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, parse_signed_entry(response)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "ML service request failed: #{inspect(reason)}"}
    end
  end

  # ---------------------------------------------------------------------------
  # Private: Database Operations
  # ---------------------------------------------------------------------------

  defp get_entries_from_db(model_id) do
    try do
      # Find model provenance record
      case Repo.get_by(ModelProvenance, model_id: model_id) do
        nil ->
          {:ok, []}

        provenance ->
          entries =
            from(e in ProvenanceEntry,
              where: e.model_provenance_id == ^provenance.id,
              order_by: [asc: e.inserted_at]
            )
            |> Repo.all()
            |> Enum.map(&entry_to_map/1)

          {:ok, entries}
      end
    rescue
      e ->
        Logger.warning("[ProvenanceVerifier] Database error: #{inspect(e)}")
        {:ok, []}  # Return empty on error for graceful degradation
    end
  end

  defp save_entry_to_db(model_id, signed_entry) do
    try do
      # Find or create model provenance record
      provenance = find_or_create_provenance(model_id)

      # Insert entry
      attrs = %{
        model_provenance_id: provenance.id,
        event_type: signed_entry.entry.event_type,
        previous_hash: signed_entry.entry.previous_hash,
        entry_hash: signed_entry.entry_hash,
        signature: signed_entry.signature,
        signer_public_key: signed_entry.signer_public_key,
        subject: signed_entry.entry.subject,
        builder: signed_entry.entry.builder || %{},
        materials: signed_entry.entry.materials || [],
        metadata: signed_entry.entry.metadata || %{}
      }

      %ProvenanceEntry{}
      |> ProvenanceEntry.changeset(attrs)
      |> Repo.insert()

      :ok
    rescue
      e ->
        Logger.warning("[ProvenanceVerifier] Failed to save entry: #{inspect(e)}")
        :ok  # Non-fatal, continue
    end
  end

  defp get_last_entry_hash(model_id) do
    case get_entries_from_db(model_id) do
      {:ok, entries} when length(entries) > 0 ->
        List.last(entries)[:entry_hash]

      _ ->
        nil
    end
  end

  defp find_or_create_provenance(model_id) do
    case Repo.get_by(ModelProvenance, model_id: model_id) do
      nil ->
        {:ok, provenance} =
          %ModelProvenance{}
          |> ModelProvenance.changeset(%{model_id: model_id, status: "active"})
          |> Repo.insert()

        provenance

      existing ->
        existing
    end
  end

  defp entry_to_map(%ProvenanceEntry{} = entry) do
    %{
      entry: %{
        entry_id: entry.id,
        event_type: entry.event_type,
        timestamp: entry.inserted_at |> DateTime.to_iso8601(),
        previous_hash: entry.previous_hash,
        subject: entry.subject || %{},
        builder: entry.builder || %{},
        metadata: entry.metadata || %{},
        materials: entry.materials || []
      },
      entry_hash: entry.entry_hash,
      signature: entry.signature,
      signer_public_key: entry.signer_public_key
    }
  end

  # ---------------------------------------------------------------------------
  # Private: Parsing
  # ---------------------------------------------------------------------------

  defp parse_verification_result(response) when is_map(response) do
    %{
      valid: response["valid"] || false,
      slsa_level: response["slsa_level"] || "SLSA Build L0",
      entry_count: response["entry_count"] || 0,
      issues: response["issues"] || [],
      verified_at: response["verified_at"] || DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  defp parse_verification_result(_), do: %{valid: false, slsa_level: "SLSA Build L0"}

  defp parse_signed_entry(response) when is_map(response) do
    entry = response["entry"] || %{}

    %{
      entry: %{
        entry_id: entry["entry_id"] || "",
        event_type: entry["event_type"] || "",
        timestamp: entry["timestamp"] || "",
        previous_hash: entry["previous_hash"],
        subject: entry["subject"] || %{},
        builder: entry["builder"] || %{},
        metadata: entry["metadata"] || %{},
        materials: entry["materials"] || []
      },
      entry_hash: response["entry_hash"] || "",
      signature: response["signature"],
      signer_public_key: response["signer_public_key"]
    }
  end

  defp parse_signed_entry(_), do: %{entry: %{}, entry_hash: "", signature: nil}

  defp parse_slsa_level(level_name) when is_binary(level_name) do
    level = case level_name do
      "SLSA Build L0" -> 0
      "SLSA Build L1" -> 1
      "SLSA Build L2" -> 2
      "SLSA Build L3" -> 3
      _ -> 0
    end

    description = case level do
      0 -> "No provenance"
      1 -> "Attestation exists"
      2 -> "Signed attestation"
      3 -> "Hardened build"
    end

    %{
      level: level,
      name: level_name,
      description: description,
      requirements_met: [],
      requirements_missing: []
    }
  end

  defp parse_slsa_level(_), do: %{level: 0, name: "SLSA Build L0", description: "No provenance"}

  defp compute_level_from_entries([]), do: "SLSA Build L0"
  defp compute_level_from_entries(entries) do
    all_signed = Enum.all?(entries, fn e ->
      e[:signature] != nil
    end)

    if all_signed, do: "SLSA Build L2", else: "SLSA Build L1"
  end

  defp ml_service_url do
    Application.get_env(:tamandua_server, :ml_service_url, @default_ml_service_url)
  end

  defp extract_error_message(body, status) when is_map(body) do
    body["detail"] || body["error"] || body["message"] || "HTTP #{status}"
  end

  defp extract_error_message(body, _status) when is_binary(body), do: body
  defp extract_error_message(_, status), do: "HTTP #{status}"
end
