defmodule TamanduaServer.IocSnapshotDigestTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.IocSnapshotDigest

  @id1 "00000000-0000-0000-0000-000000000001"
  @id2 "00000000-0000-0000-0000-000000000002"

  test "digest is deterministic and binds epoch, counts, bytes, nils and organization" do
    rows = [
      row(@id1, nil, nil),
      row(@id2, "10000000-0000-0000-0000-000000000001", "feed")
    ]

    assert {:ok, digest} = IocSnapshotDigest.sha256(7, 2, 321, rows)
    assert digest == "274d48c9a48c7a4a5613812d7d047b4accf3a51776601f4a71220bd949007a84"
    assert {:ok, ^digest} = IocSnapshotDigest.sha256(7, 2, 321, rows)
    assert {:ok, changed_epoch} = IocSnapshotDigest.sha256(8, 2, 321, rows)
    assert {:ok, changed_bytes} = IocSnapshotDigest.sha256(7, 2, 322, rows)

    assert {:ok, changed_nil} =
             IocSnapshotDigest.sha256(7, 2, 321, [row(@id1, nil, ""), Enum.at(rows, 1)])

    refute digest == changed_epoch
    refute digest == changed_bytes
    refute digest == changed_nil
  end

  test "rejects count mismatch, malformed UUIDs and unordered or duplicate rows" do
    first = row(@id1, nil, nil)
    second = row(@id2, nil, nil)

    assert {:error, :invalid_snapshot} = IocSnapshotDigest.sha256(1, 2, 1, [first])

    assert {:error, :unordered_or_duplicate_id} =
             IocSnapshotDigest.sha256(1, 2, 1, [second, first])

    assert {:error, :unordered_or_duplicate_id} =
             IocSnapshotDigest.sha256(1, 2, 1, [first, first])

    assert {:error, :unordered_or_duplicate_id} =
             IocSnapshotDigest.sha256(1, 1, 1, [%{first | id: "bad"}])
  end

  defp row(id, organization_id, source) do
    %{
      id: id,
      organization_id: organization_id,
      type: "domain",
      value: "evil.test",
      severity: "high",
      description: nil,
      source: source
    }
  end
end
