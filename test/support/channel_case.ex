defmodule TamanduaServerWeb.ChannelCase do
  @moduledoc """
  This module defines the test case to be used by
  channel tests.

  Such tests rely on `Phoenix.ChannelTest` and also
  import other functionality to make it easier
  to build common data structures and query the data layer.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use TamanduaServerWeb.ChannelCase, async: true`, although
  this option is not recommended for tests involving access to
  the database.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      # Import conveniences for testing with channels
      import Phoenix.ChannelTest
      import TamanduaServerWeb.ChannelCase
      import TamanduaServer.Factory

      # The default endpoint for testing
      @endpoint TamanduaServerWeb.Endpoint
    end
  end

  setup tags do
    TamanduaServer.DataCase.setup_sandbox(tags)
    :ok
  end
end
