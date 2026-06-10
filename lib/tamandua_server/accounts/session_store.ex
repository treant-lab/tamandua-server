defmodule TamanduaServer.Accounts.SessionStore do
  @moduledoc """
  ETS-based session token storage.
  This module is started under supervision to ensure the ETS table
  persists across requests.
  """

  use GenServer

  @session_tokens_table :user_session_tokens
  @api_tokens_table :user_api_tokens

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init(_) do
    # Create ETS tables for session and API tokens
    :ets.new(@session_tokens_table, [:set, :public, :named_table])
    :ets.new(@api_tokens_table, [:set, :public, :named_table])
    {:ok, %{}}
  end

  @doc """
  Get the session tokens table name.
  """
  def session_tokens_table, do: @session_tokens_table

  @doc """
  Get the API tokens table name.
  """
  def api_tokens_table, do: @api_tokens_table
end
