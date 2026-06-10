defmodule TamanduaServer.Guardian do
  @moduledoc """
  Guardian implementation for TamanduaServer.
  """

  use Guardian, otp_app: :tamandua_server
  require Logger
  alias TamanduaServer.Agents

  def subject_for_token(resource, _claims) do
    # You can use any field from your resource for the subject,
    # often it's the ID.
    {:ok, resource.id}
  end

  def resource_from_claims(claims) do
    if agent_id = claims["sub"] do
      case Agents.get_agent(agent_id) do
        {:ok, agent} -> {:ok, agent}
        {:error, :not_found} -> {:error, :agent_not_found}
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, "No agent_id in claims"}
    end
  end

  # Define specific Guardian pipelines for different types of tokens
  # e.g., for agents, users, etc.
  def after_encode_and_sign(resource, claims, token, _options) do
    Logger.debug("Guardian: Encoded token for resource #{inspect(resource.id)}")
    {:ok, {resource, claims, token}}
  end

  def after_decode_and_verify(resource, claims, token, _options) do
    Logger.debug("Guardian: Decoded token for resource #{inspect(resource.id)}")
    {:ok, {resource, claims, token}}
  end
end
