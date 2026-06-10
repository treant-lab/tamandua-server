defmodule TamanduaServer.Audit.Forwarder do
  @moduledoc """
  Forwards audit logs to external systems (Splunk, S3, syslog, SIEM).
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Audit.{AuditLog, AuditForwarder}
  alias TamanduaServer.Audit.Forwarders.{SplunkForwarder, S3Forwarder, SyslogForwarder, SiemForwarder}

  @doc """
  Forwards an audit log asynchronously to all active forwarders.
  """
  def forward_async(%AuditLog{} = audit_log) do
    forwarders = get_active_forwarders(audit_log.organization_id)
    
    Enum.each(forwarders, fn forwarder ->
      if should_forward?(audit_log, forwarder) do
        Task.start(fn -> forward_to_system(audit_log, forwarder) end)
      end
    end)
  end

  defp get_active_forwarders(organization_id) do
    Repo.all(
      from f in AuditForwarder,
        where: f.organization_id == ^organization_id,
        where: f.is_active == true
    )
  end

  defp should_forward?(audit_log, forwarder) do
    cond do
      forwarder.forward_all -> true
      
      not Enum.empty?(forwarder.filter_actions) and audit_log.action not in forwarder.filter_actions -> false
      
      not Enum.empty?(forwarder.filter_categories) and audit_log.category not in forwarder.filter_categories -> false
      
      not Enum.empty?(forwarder.filter_severity) and audit_log.severity not in forwarder.filter_severity -> false
      
      true -> true
    end
  end

  defp forward_to_system(audit_log, forwarder) do
    result = case forwarder.forwarder_type do
      "splunk" -> SplunkForwarder.forward(audit_log, forwarder.config)
      "s3" -> S3Forwarder.forward(audit_log, forwarder.config)
      "syslog" -> SyslogForwarder.forward(audit_log, forwarder.config)
      "siem" -> SiemForwarder.forward(audit_log, forwarder.config)
      _ -> {:error, "Unknown forwarder type"}
    end

    update_forwarder_stats(forwarder, result)
  end

  defp update_forwarder_stats(forwarder, result) do
    case result do
      {:ok, _} ->
        forwarder
        |> Ecto.Changeset.change(%{
          last_success_at: DateTime.utc_now(),
          total_forwarded: forwarder.total_forwarded + 1,
          consecutive_failures: 0,
          health_status: "healthy"
        })
        |> Repo.update()

      {:error, reason} ->
        consecutive_failures = forwarder.consecutive_failures + 1
        health_status = if consecutive_failures >= 5, do: "down", else: "degraded"

        forwarder
        |> Ecto.Changeset.change(%{
          last_error_at: DateTime.utc_now(),
          last_error_message: inspect(reason),
          total_failed: forwarder.total_failed + 1,
          consecutive_failures: consecutive_failures,
          health_status: health_status
        })
        |> Repo.update()
    end
  end
end

defmodule TamanduaServer.Audit.AuditForwarder do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_forwarders" do
    field :name, :string
    field :forwarder_type, :string
    field :config, :map
    field :filter_actions, {:array, :string}
    field :filter_categories, {:array, :string}
    field :filter_severity, {:array, :string}
    field :forward_all, :boolean
    field :is_active, :boolean
    field :health_status, :string
    field :last_success_at, :utc_datetime_usec
    field :last_error_at, :utc_datetime_usec
    field :last_error_message, :string
    field :consecutive_failures, :integer
    field :total_forwarded, :integer
    field :total_failed, :integer
    field :batch_size, :integer
    field :batch_timeout_ms, :integer

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(forwarder, attrs) do
    forwarder
    |> cast(attrs, [
      :name, :forwarder_type, :config, :organization_id,
      :filter_actions, :filter_categories, :filter_severity,
      :forward_all, :is_active, :batch_size, :batch_timeout_ms
    ])
    |> validate_required([:name, :forwarder_type, :config, :organization_id])
    |> validate_inclusion(:forwarder_type, ~w(splunk s3 syslog siem))
    |> unique_constraint([:organization_id, :name])
  end
end
