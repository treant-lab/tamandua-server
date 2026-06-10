defmodule TamanduaServerWeb.RouterExampleGroups do
  @moduledoc """
  Example router configuration for Agent Groups and Batch Commands.

  Copy the relevant sections to your router.ex file.
  """

  # Add to your existing router.ex:

  # scope "/", TamanduaServerWeb do
  #   pipe_through [:browser, :require_authenticated_user]
  #
  #   # Agent Groups Routes
  #   live "/agent_groups", AgentGroupsLive, :index
  #   live "/agent_groups/:id", AgentGroupsLive, :show
  #
  #   # Batch Commands Routes
  #   live "/batch_commands", BatchCommandsLive, :index
  #   live "/batch_commands/:id", BatchCommandsLive, :show
  #
  #   # Enhanced Agents Route (with group filter support)
  #   live "/agents", AgentsLive, :index
  #   live "/agents/:id", AgentsLive, :show
  # end

  # For API routes (if implementing REST API):

  # scope "/api/v1", TamanduaServerWeb.API do
  #   pipe_through :api
  #
  #   # Agent Groups
  #   resources "/agent_groups", AgentGroupController, except: [:new, :edit] do
  #     post "/members", AgentGroupController, :add_members
  #     delete "/members", AgentGroupController, :remove_members
  #     get "/stats", AgentGroupController, :stats
  #     get "/agents", AgentGroupController, :list_agents
  #   end
  #
  #   # Batch Commands
  #   resources "/batch_commands", BatchCommandController, only: [:index, :show, :create] do
  #     post "/cancel", BatchCommandController, :cancel
  #     get "/results", BatchCommandController, :results
  #   end
  #
  #   # Group Import/Export
  #   post "/agent_groups/import", AgentGroupController, :import
  #   get "/agent_groups/export", AgentGroupController, :export
  #   get "/agent_groups/export/csv", AgentGroupController, :export_csv
  # end
end
