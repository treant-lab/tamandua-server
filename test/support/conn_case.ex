defmodule TamanduaServerWeb.ConnCase do
  @moduledoc """
  Test case for controller tests.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @endpoint TamanduaServerWeb.Endpoint

      import Plug.Conn
      import Phoenix.ConnTest
      import TamanduaServer.Factory
      import TamanduaServerWeb.ConnCase, except: [auth_conn: 1]
    end
  end

  setup tags do
    TamanduaServer.DataCase.setup_sandbox(tags)

    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end

  def auth_conn(token) when is_binary(token) do
    Phoenix.ConnTest.build_conn()
    |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
  end
end
