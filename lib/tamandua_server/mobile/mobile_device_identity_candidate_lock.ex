defmodule TamanduaServer.Mobile.MobileDeviceIdentityCandidateLock do
  @moduledoc false

  alias TamanduaServer.Repo

  @lock_domain "tamandua.mobile.device-key-lock/v1"
  @key_id_format ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/

  @spec lock_keys(Ecto.UUID.t(), String.t() | [String.t()]) ::
          :ok | {:error, :invalid_candidate_key_ids}
  def lock_keys(organization_id, candidate_ids) when is_binary(organization_id) do
    with {:ok, candidate_ids} <- normalize(candidate_ids) do
      Enum.each(candidate_ids, fn candidate_id ->
        <<first::signed-32, second::signed-32, _::binary>> =
          :crypto.hash(
            :sha256,
            @lock_domain <> <<0>> <> organization_id <> <<0>> <> candidate_id
          )

        Repo.query!("SELECT pg_advisory_xact_lock($1, $2)", [first, second])
      end)

      :ok
    end
  end

  def lock_keys(_organization_id, _candidate_ids), do: {:error, :invalid_candidate_key_ids}

  defp normalize(candidate_id) when is_binary(candidate_id), do: normalize([candidate_id])

  defp normalize(candidate_ids) when is_list(candidate_ids) do
    if candidate_ids != [] and Enum.all?(candidate_ids, &canonical_key_id?/1) do
      {:ok, candidate_ids |> Enum.uniq() |> Enum.sort()}
    else
      {:error, :invalid_candidate_key_ids}
    end
  end

  defp normalize(_candidate_ids), do: {:error, :invalid_candidate_key_ids}

  defp canonical_key_id?(candidate_id) when is_binary(candidate_id),
    do: Regex.match?(@key_id_format, candidate_id)

  defp canonical_key_id?(_candidate_id), do: false
end
