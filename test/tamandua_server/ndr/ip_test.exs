defmodule TamanduaServer.NDR.IPTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.NDR.IP

  describe "classification/1" do
    test "classifies IPv6 internal ranges" do
      assert IP.classification("fc00::1") == :unique_local
      assert IP.classification("fe80::1%eth0") == :link_local
      assert IP.classification("::1") == :loopback
    end

    test "classifies IPv4-mapped IPv6 addresses using IPv4 ranges" do
      assert IP.classification("::ffff:192.168.1.10") == :private
      assert IP.classification("::ffff:8.8.8.8") == :public
    end
  end

  describe "canonical/1" do
    test "normalizes bracketed and scoped IPv6 literals" do
      assert IP.canonical("[FE80::1%en0]:443") == "fe80::1"
    end
  end

  describe "sort_key/1" do
    test "uses canonical parsed address order for equivalent IPv6 forms" do
      assert IP.sort_key("2001:db8::1") == IP.sort_key("2001:0DB8:0:0:0:0:0:1")
      assert IP.sort_key("2001:db8::1") < IP.sort_key("2001:db8::2")
    end
  end
end
