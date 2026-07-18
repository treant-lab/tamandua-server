defmodule TamanduaServer.Agentic.WorkflowGeneratorSecurityTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Agentic.WorkflowGenerator
  alias TamanduaServer.Agentic.WorkflowGenerator.WorkflowProposal

  test "legacy proposal APIs fail closed without an organization" do
    assert {:error, :organization_required} =
             WorkflowGenerator.generate_from_investigation(Ecto.UUID.generate())

    assert [] = WorkflowGenerator.list_proposals()
    assert {:error, :organization_required} = WorkflowGenerator.get_proposal(Ecto.UUID.generate())

    assert {:error, :organization_required} =
             WorkflowGenerator.approve_proposal(Ecto.UUID.generate(), Ecto.UUID.generate())

    assert {:error, :organization_required} =
             WorkflowGenerator.modify_and_approve(
               Ecto.UUID.generate(),
               %{},
               Ecto.UUID.generate()
             )

    assert {:error, :organization_required} =
             WorkflowGenerator.reject_proposal(
               Ecto.UUID.generate(),
               Ecto.UUID.generate(),
               "not applicable"
             )
  end

  test "proposal lookup and listing do not cross tenant boundaries" do
    ensure_generator_started()

    proposal_id = Ecto.UUID.generate()
    organization_id = Ecto.UUID.generate()
    other_organization_id = Ecto.UUID.generate()

    proposal = %WorkflowProposal{
      id: proposal_id,
      name: "Tenant-scoped proposal",
      description: "security regression fixture",
      organization_id: organization_id,
      source_investigation_id: Ecto.UUID.generate(),
      status: :proposed,
      created_at: DateTime.utc_now(),
      similarity_hash: "fixture"
    }

    :ets.insert(:workflow_generator_proposals, {proposal_id, proposal})
    on_exit(fn -> :ets.delete(:workflow_generator_proposals, proposal_id) end)

    assert {:ok, ^proposal} = WorkflowGenerator.get_proposal(proposal_id, organization_id)
    assert {:error, :not_found} = WorkflowGenerator.get_proposal(proposal_id, other_organization_id)

    assert Enum.any?(
             WorkflowGenerator.list_proposals(organization_id: organization_id),
             &(&1.id == proposal_id)
           )

    refute Enum.any?(
             WorkflowGenerator.list_proposals(organization_id: other_organization_id),
             &(&1.id == proposal_id)
           )

    assert {:error, :not_found} =
             WorkflowGenerator.reject_proposal(
               proposal_id,
               Ecto.UUID.generate(),
               "cross-tenant attempt",
               other_organization_id
             )
  end

  defp ensure_generator_started do
    case Process.whereis(WorkflowGenerator) do
      nil -> start_supervised!(WorkflowGenerator)
      _pid -> :ok
    end
  end
end
