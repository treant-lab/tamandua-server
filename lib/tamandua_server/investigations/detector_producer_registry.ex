defmodule TamanduaServer.Investigations.DetectorProducerRegistry do
  @moduledoc "Governed tenant registry used only to authorize detector observation claims."

  import Ecto.Query

  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Investigations.DetectorProducerAttestation
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @immutable_fields ~w(producer_id detector_id detector_type detector_version source revision artifact_sha256 input_schema_sha256 allowed_evidence_classes allowed_claim_scopes expires_at)a

  def attest(organization_id, actor_id, attrs) when is_binary(organization_id) and is_map(attrs) do
    now = DateTime.utc_now()

    attrs =
      attrs
      |> stringify_keys()
      |> Map.put("organization_id", organization_id)
      |> Map.put("attested_by_id", actor_id)
      |> Map.put("attested_at", now)
      |> Map.put("status", "active")
      |> Map.put("attestation_sha256", attestation_hash(organization_id, attrs))

    MultiTenant.with_organization(organization_id, fn ->
      with {:ok, _actor} <- authorize_actor(Repo, organization_id, actor_id) do
        %DetectorProducerAttestation{}
        |> DetectorProducerAttestation.create_changeset(attrs)
        |> Repo.insert()
      end
    end)
  end

  def list(organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      Repo.all(
        from(a in DetectorProducerAttestation,
          where: a.organization_id == ^organization_id,
          order_by: [desc: a.attested_at],
          limit: 200
        )
      )
    end)
  end

  def revoke(organization_id, id, actor_id) do
    MultiTenant.with_organization(organization_id, fn ->
      with {:ok, _actor} <- authorize_actor(Repo, organization_id, actor_id) do
        case Repo.get_by(DetectorProducerAttestation, id: id, organization_id: organization_id) do
          nil -> {:error, :not_found}
          record -> Repo.update(Ecto.Changeset.change(record, status: "revoked", revoked_at: DateTime.utc_now()))
        end
      end
    end)
  end

  def authorize(organization_id, id, envelope) do
    MultiTenant.with_organization(organization_id, fn ->
      authorize_scoped(Repo, organization_id, id, envelope)
    end)
  end

  @doc false
  def authorize_scoped(repo, organization_id, id, envelope) do
    case repo.get_by(DetectorProducerAttestation, id: id, organization_id: organization_id) do
      nil -> {:error, :producer_attestation_not_found}
      record -> authorize_record(record, envelope, DateTime.utc_now())
    end
  end

  @doc false
  def authorize_many_scoped(repo, organization_id, ids, envelope)
      when is_list(ids) and is_map(envelope) do
    observations = envelope["observations"] || []

    cond do
      length(ids) != length(observations) ->
        {:error, {:unauthorized_detector_claim, ["one producer attestation is required per observation"]}}

      Enum.uniq(ids) != ids ->
        {:error, {:unauthorized_detector_claim, ["producer attestation ids must be unique"]}}

      true ->
        ids
        |> Enum.zip(observations)
        |> Enum.reduce_while({:ok, []}, fn {id, observation}, {:ok, records} ->
          observation_envelope = Map.put(envelope, "observations", [observation])

          case authorize_scoped(repo, organization_id, id, observation_envelope) do
            {:ok, record} -> {:cont, {:ok, [record | records]}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)
        |> case do
          {:ok, records} -> {:ok, Enum.reverse(records)}
          error -> error
        end
    end
  end

  def serialize(record) do
    Map.take(record, [
      :id,
      :producer_id,
      :detector_id,
      :detector_type,
      :detector_version,
      :source,
      :revision,
      :artifact_sha256,
      :input_schema_sha256,
      :allowed_evidence_classes,
      :allowed_claim_scopes,
      :attestation_sha256,
      :status,
      :attested_at,
      :expires_at,
      :revoked_at
    ])
  end

  defp authorize_record(%{status: status}, _envelope, _now) when status != "active",
    do: {:error, :producer_attestation_inactive}

  defp authorize_record(record, envelope, now) do
    if record.expires_at && DateTime.compare(record.expires_at, now) in [:lt, :eq] do
      {:error, :producer_attestation_expired}
    else
      authorize_active_record(record, envelope)
    end
  end

  defp authorize_active_record(record, envelope) do
    context = envelope["validation_context"]
    observations = envelope["observations"] || []
    input_contract = envelope["input_contract"] || %{}

    errors =
      []
      |> require(context["evidence_class"] in record.allowed_evidence_classes, "evidence_class is not authorized by producer attestation")
      |> require(context["claim_scope"] in record.allowed_claim_scopes, "claim_scope is not authorized by producer attestation")
      |> require(input_contract["schema_sha256"] == record.input_schema_sha256, "input contract schema hash is not attested")
      |> require(length(observations) == 1, "one producer attestation authorizes exactly one detector observation")
      |> authorize_observation(List.first(observations), record)

    if errors == [], do: {:ok, record}, else: {:error, {:unauthorized_detector_claim, Enum.reverse(errors)}}
  end

  defp authorize_observation(errors, observation, record) when is_map(observation) do
    provenance = observation["provenance"] || %{}

    errors
    |> require(observation["detector_id"] == record.detector_id, "detector_id is not attested")
    |> require(observation["detector_type"] == record.detector_type, "detector_type is not attested")
    |> require(observation["detector_version"] == record.detector_version, "detector_version is not attested")
    |> require(provenance["source"] == record.source, "producer source is not attested")
    |> require(provenance["revision"] == record.revision, "producer revision is not attested")
    |> require(provenance["artifact_sha256"] == record.artifact_sha256, "detector artifact hash is not attested")
  end

  defp authorize_observation(errors, _observation, _record), do: ["detector observation is missing" | errors]

  defp attestation_hash(organization_id, attrs) do
    normalized =
      @immutable_fields
      |> Enum.map(fn field -> {Atom.to_string(field), attrs[Atom.to_string(field)] || attrs[field]} end)
      |> Map.new()
      |> Map.put("organization_id", organization_id)

    normalized
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp require(errors, true, _message), do: errors
  defp require(errors, false, message), do: [message | errors]
  defp stringify_keys(map), do: Map.new(map, fn {key, value} -> {to_string(key), value} end)

  defp authorize_actor(repo, organization_id, actor_id) when is_binary(actor_id) do
    case repo.get_by(User, id: actor_id, organization_id: organization_id) do
      %User{} = actor ->
        if Accounts.user_can?(actor, :system_settings),
          do: {:ok, actor},
          else: {:error, :unauthorized}

      nil ->
        {:error, :unauthorized}
    end
  end

  defp authorize_actor(_repo, _organization_id, _actor_id), do: {:error, :unauthorized}
end
