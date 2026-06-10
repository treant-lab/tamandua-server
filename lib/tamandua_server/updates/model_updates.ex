defmodule TamanduaServer.Updates.ModelUpdates do
  @moduledoc """
  Minimal backend flow for model/rule hot updates consumed by the agent
  `ModelUpdater`.

  The agent currently expects:

  - `POST /api/v1/updates/models/check?platform=...&agent_id=...`
  - Request body with current asset SHA-256 values
  - `204 No Content` when nothing should be updated
  - `200` with `%{assets: [...], signature: ...}` when updates are available

  This module keeps the contract coherent even when the deployment does not yet
  publish model assets. In that case it safely returns `:up_to_date`.
  """

  require Logger

  @type asset_spec :: %{
          asset_type: String.t(),
          filename: String.t()
        }

  @asset_specs [
    %{asset_type: "onnx_smell", filename: "malware_smell.onnx"},
    %{asset_type: "onnx_transformer", filename: "byte_transformer.onnx"},
    %{asset_type: "onnx_ensemble", filename: "ensemble.onnx"},
    %{asset_type: "onnx_features", filename: "malware_features.onnx"},
    %{asset_type: "yara_rules", filename: "yara_bundle.tar.gz"},
    %{asset_type: "sigma_rules", filename: "sigma_bundle.tar.gz"},
    %{asset_type: "ioc_list", filename: "iocs.json"}
  ]

  @current_version_keys %{
    "onnx_smell" => "smell_sha256",
    "onnx_transformer" => "transformer_sha256",
    "onnx_ensemble" => "ensemble_sha256",
    "onnx_features" => "features_sha256",
    "yara_rules" => "yara_sha256",
    "sigma_rules" => "sigma_sha256",
    "ioc_list" => "ioc_sha256"
  }

  @doc """
  Returns a signed manifest when at least one published asset differs from the
  hashes reported by the agent. Returns `:up_to_date` when:

  - no publish directory is configured/found
  - no publishable assets exist
  - signing is not configured
  - agent is already aligned with the published assets
  """
  @spec check_for_updates(map(), keyword()) :: {:ok, map()} | :up_to_date | {:error, term()}
  def check_for_updates(current_versions, opts \\ []) when is_map(current_versions) do
    with {:ok, publish_dir} <- resolve_publish_dir(),
         {:ok, private_key} <- signing_private_key(),
         assets when is_list(assets) <- build_candidate_assets(publish_dir, current_versions, opts),
         false <- Enum.empty?(assets),
         {:ok, signature} <- sign_manifest_assets(assets, private_key) do
      {:ok, %{assets: assets, signature: signature}}
    else
      :no_publish_dir ->
        Logger.debug("[ModelUpdates] No published model/rule asset directory found")
        :up_to_date

      {:error, :signing_not_configured} ->
        Logger.warning("[ModelUpdates] Signing key not configured; suppressing model updates")
        :up_to_date

      [] ->
        :up_to_date

      true ->
        :up_to_date

      {:error, reason} = error ->
        Logger.error("[ModelUpdates] Failed to build model update manifest: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Resolves a published asset by type/version for direct download.
  """
  @spec fetch_downloadable_asset(String.t(), String.t()) ::
          {:ok, %{path: Path.t(), filename: String.t(), size: non_neg_integer()}}
          | {:error, :not_found | term()}
  def fetch_downloadable_asset(asset_type, version) do
    with {:ok, publish_dir} <- resolve_publish_dir(),
         {:ok, spec} <- asset_spec(asset_type),
         path <- Path.join(publish_dir, spec.filename),
         true <- File.exists?(path),
         {:ok, sha256} <- sha256_hex(path),
         true <- asset_version(sha256) == version,
         {:ok, stat} <- File.stat(path) do
      {:ok, %{path: path, filename: spec.filename, size: stat.size}}
    else
      false -> {:error, :not_found}
      :no_publish_dir -> {:error, :not_found}
      {:error, _} = error -> error
    end
  end

  defp build_candidate_assets(publish_dir, current_versions, opts) do
    base_url = Keyword.fetch!(opts, :base_url)

    Enum.reduce(@asset_specs, [], fn spec, acc ->
      path = Path.join(publish_dir, spec.filename)

      case build_asset_entry(spec, path, current_versions, base_url) do
        {:ok, nil} -> acc
        {:ok, entry} -> [entry | acc]
        {:error, reason} ->
          Logger.warning(
            "[ModelUpdates] Skipping #{spec.asset_type} from #{path}: #{inspect(reason)}"
          )

          acc
      end
    end)
    |> Enum.reverse()
  end

  defp build_asset_entry(spec, path, current_versions, base_url) do
    if File.exists?(path) do
      with {:ok, sha256} <- sha256_hex(path),
           {:ok, stat} <- File.stat(path) do
        current_sha = Map.get(current_versions, Map.fetch!(@current_version_keys, spec.asset_type), "")

        if normalize_sha(current_sha) == sha256 do
          {:ok, nil}
        else
          version = asset_version(sha256)

          {:ok,
           %{
             asset_type: spec.asset_type,
             version: version,
             sha256: sha256,
             download_url: "#{base_url}/download/#{spec.asset_type}/#{version}",
             size: stat.size
           }}
        end
      end
    else
      {:ok, nil}
    end
  end

  defp resolve_publish_dir do
    candidates =
      [
        System.get_env("TAMANDUA_MODEL_UPDATE_DIR"),
        Application.get_env(:tamandua_server, :model_update_dir),
        Path.expand("../tamandua_ml/models/latest", File.cwd!()),
        Path.expand("../tamandua_ml/models", File.cwd!()),
        Path.expand("../../tamandua_ml/models/latest", File.cwd!()),
        Path.expand("../../tamandua_ml/models", File.cwd!())
      ]
      |> Enum.reject(&is_nil/1)

    case Enum.find(candidates, &File.dir?/1) do
      nil -> :no_publish_dir
      dir -> {:ok, dir}
    end
  end

  defp signing_private_key do
    case System.get_env("TAMANDUA_UPDATE_PRIVATE_KEY") ||
           Application.get_env(:tamandua_server, :update_private_key) do
      nil -> {:error, :signing_not_configured}
      "" -> {:error, :signing_not_configured}
      key -> {:ok, key}
    end
  end

  defp sign_manifest_assets(assets, private_key) do
    canonical_json =
      [assets: Enum.map(assets, &ordered_asset_fields/1)]
      |> Jason.encode!()

    Tamandua.Updates.BinarySigner.sign_data(canonical_json, private_key)
  end

  defp ordered_asset_fields(asset) do
    [
      asset_type: asset.asset_type,
      version: asset.version,
      sha256: asset.sha256,
      download_url: asset.download_url,
      size: asset.size
    ]
  end

  defp asset_spec(asset_type) do
    case Enum.find(@asset_specs, &(&1.asset_type == asset_type)) do
      nil -> {:error, :not_found}
      spec -> {:ok, spec}
    end
  end

  defp sha256_hex(path) do
    case File.read(path) do
      {:ok, data} ->
        {:ok, :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp asset_version(sha256), do: String.slice(sha256, 0, 12)

  defp normalize_sha(nil), do: ""
  defp normalize_sha(sha) when is_binary(sha), do: String.downcase(String.trim(sha))
end
