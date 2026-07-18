defmodule TamanduaServerWeb.Plugs.SystemOperatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServerWeb.Plugs.SystemOperator

  test "only explicit platform operator identities pass" do
    refute SystemOperator.system_operator?(nil)
    refute SystemOperator.system_operator?(%{role: "admin"})
    refute SystemOperator.system_operator?(%{role: "analyst", is_super_admin: false})
    assert SystemOperator.system_operator?(%{role: "super_admin"})
    assert SystemOperator.system_operator?(%{role: "analyst", is_super_admin: true})
  end
end
