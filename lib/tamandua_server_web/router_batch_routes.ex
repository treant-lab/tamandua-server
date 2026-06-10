defmodule TamanduaServerWeb.Router.BatchRoutes do
  @moduledoc """
  Batch operation routes to be added to the main router.

  Add these routes to the existing `scope "/api/v1"` section in router.ex,
  after the existing alert routes (around line 170).

  ## Installation

  In `lib/tamandua_server_web/router.ex`, add these routes inside the
  `scope "/api/v1", TamanduaServerWeb.API.V1` block:

  ```elixir
  # Batch Operations
  scope "/alerts/batch" do
    post "/close", BatchController, :close_alerts
    post "/assign", BatchController, :assign_alerts
    post "/tag", BatchController, :tag_alerts
    post "/delete", BatchController, :delete_alerts
  end

  scope "/iocs/batch" do
    post "/import", BatchController, :import_iocs
    post "/delete", BatchController, :delete_iocs
    post "/update", BatchController, :update_iocs
  end

  scope "/agents/batch" do
    post "/isolate", BatchController, :isolate_agents
    post "/scan", BatchController, :scan_agents
    post "/collect-forensics", BatchController, :collect_forensics
  end

  # Job status tracking
  get "/jobs/:id", BatchController, :get_job
  ```

  ## GraphQL Schema Integration

  In `lib/tamandua_server_web/graphql/schema.ex`, import the batch mutations:

  ```elixir
  import_types TamanduaServerWeb.GraphQL.Mutations.Batch

  mutation do
    # ... existing mutations ...

    import_fields :batch_mutations
  end
  ```
  """

  # This is a documentation-only module
  # Copy the routes above into router.ex manually
end
