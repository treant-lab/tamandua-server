defmodule TamanduaServerWeb.AgentSocketCertChainTest do
  @moduledoc """
  Tests for the in-VM mTLS certificate chain verification
  (:public_key.pkix_path_validation/3) that replaced the previous
  `openssl verify` shell-out, and for the debug agent id resolution.

  Certificates are generated at test time with :public_key.pkix_test_data/1
  (pure OTP, no external openssl dependency, nothing written to disk).

  async: false because the debug_agent_id tests mutate the process
  environment and application config.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias TamanduaServerWeb.AgentChannel
  alias TamanduaServerWeb.AgentSocket

  # Generates a fresh CA hierarchy (self-signed root -> intermediate -> leaf)
  # and returns {leaf_der, ca_bundle_ders}.
  defp gen_chain do
    conf =
      :public_key.pkix_test_data(%{
        root: [{:digest, :sha256}],
        intermediates: [[{:digest, :sha256}]],
        peer: [{:digest, :sha256}]
      })

    {Keyword.fetch!(conf, :cert), Keyword.fetch!(conf, :cacerts)}
  end

  # Generates a chain with no intermediate: leaf signed directly by a
  # self-signed root.
  defp gen_direct_chain do
    conf =
      :public_key.pkix_test_data(%{
        root: [{:digest, :sha256}],
        peer: [{:digest, :sha256}]
      })

    {Keyword.fetch!(conf, :cert), Keyword.fetch!(conf, :cacerts)}
  end

  describe "verify_against_ca/2" do
    test "accepts a leaf chaining through an intermediate to the trusted root" do
      {leaf_der, ca_certs} = gen_chain()

      # Bundle contains root + intermediate, mirroring the production
      # ca_bundle_pem export (root + intermediate CA).
      assert length(ca_certs) >= 2
      assert AgentSocket.verify_against_ca(leaf_der, ca_certs) == true
    end

    test "accepts a leaf signed directly by a self-signed root in the bundle" do
      {leaf_der, ca_certs} = gen_direct_chain()

      assert AgentSocket.verify_against_ca(leaf_der, ca_certs) == true
    end

    test "rejects a leaf issued by a different CA" do
      {_leaf_a, ca_certs_a} = gen_chain()
      {leaf_b, _ca_certs_b} = gen_chain()

      log =
        capture_log(fn ->
          assert AgentSocket.verify_against_ca(leaf_b, ca_certs_a) == false
        end)

      assert log =~ "Certificate path validation failed"
    end

    test "rejects garbage leaf input" do
      {_leaf, ca_certs} = gen_chain()

      capture_log(fn ->
        assert AgentSocket.verify_against_ca(<<"not a certificate">>, ca_certs) == false
      end)
    end

    test "rejects a valid leaf against a garbage CA bundle" do
      {leaf_der, _ca_certs} = gen_chain()

      capture_log(fn ->
        assert AgentSocket.verify_against_ca(leaf_der, [<<0, 1, 2, 3>>]) == false
      end)
    end

    test "rejects an empty CA bundle" do
      {leaf_der, _ca_certs} = gen_chain()

      capture_log(fn ->
        assert AgentSocket.verify_against_ca(leaf_der, []) == false
      end)
    end
  end

  describe "debug_agent_id/0" do
    setup do
      original_env = System.get_env("TAMANDUA_DEBUG_AGENT_ID")
      original_cfg = Application.get_env(:tamandua_server, :debug_agent_id)

      System.delete_env("TAMANDUA_DEBUG_AGENT_ID")
      Application.delete_env(:tamandua_server, :debug_agent_id)

      on_exit(fn ->
        if original_env do
          System.put_env("TAMANDUA_DEBUG_AGENT_ID", original_env)
        else
          System.delete_env("TAMANDUA_DEBUG_AGENT_ID")
        end

        if original_cfg do
          Application.put_env(:tamandua_server, :debug_agent_id, original_cfg)
        else
          Application.delete_env(:tamandua_server, :debug_agent_id)
        end
      end)

      :ok
    end

    test "defaults to nil when env and config are unset (no baked-in id)" do
      assert AgentChannel.debug_agent_id() == nil
    end

    test "resolves from TAMANDUA_DEBUG_AGENT_ID env var" do
      System.put_env("TAMANDUA_DEBUG_AGENT_ID", "11111111-2222-3333-4444-555555555555")
      assert AgentChannel.debug_agent_id() == "11111111-2222-3333-4444-555555555555"
    end

    test "falls back to :debug_agent_id application config" do
      Application.put_env(:tamandua_server, :debug_agent_id, "cfg-agent-id")
      assert AgentChannel.debug_agent_id() == "cfg-agent-id"
    end

    test "treats empty env var as unset" do
      System.put_env("TAMANDUA_DEBUG_AGENT_ID", "")
      assert AgentChannel.debug_agent_id() == nil
    end
  end
end
