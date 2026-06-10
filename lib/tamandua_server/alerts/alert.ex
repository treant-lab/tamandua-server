defmodule TamanduaServer.Alerts.Alert do
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.Tag
  alias TamanduaServer.Alerts.TagAssignment
  alias TamanduaServer.Alerts.SeverityAdjustment
  alias TamanduaServer.Detection.Mitre

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]
  schema "alerts" do
    field :severity, :string
    field :title, :string
    field :description, :string
    field :event_ids, {:array, :binary_id}, default: []
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []
    field :status, :string, default: "new"
    field :resolution_notes, :string
    field :threat_score, :float
    field :enrichment, :map, default: %{}
    field :source_event_id, :binary_id

    # Kubernetes context enrichment.
    # Some lab databases do not have a persisted alerts.k8s_context column yet,
    # so keep the field virtual to avoid SELECTing a missing column while still
    # allowing enrichers/UI code to attach transient context data.
    field :k8s_context, :map, virtual: true

    # Phase 1: Enhanced evidence fields
    field :evidence, :map, default: %{}
    field :process_chain, {:array, :map}, default: []
    field :raw_event, :map
    field :detection_metadata, :map, default: %{}
    field :contributing_events, {:array, :string}, default: []

    # Storyline correlation
    field :storyline_id, :string

    # Alert deduplication fields
    field :occurrence_count, :integer, default: 1
    field :last_seen_at, :utc_datetime_usec
    field :dedup_key, :string

    # Analyst verdict / feedback loop fields
    field :verdict, :string, default: "unconfirmed"
    field :verdict_at, :utc_datetime_usec
    field :verdict_notes, :string
    field :suppression_rule_id, :binary_id

    # Behavioral correlation data
    field :correlation_data, :map, default: %{}

    # Threat attribution fields
    field :attributed_actors, {:array, :string}, default: []
    field :campaign_id, :string
    field :attribution_confidence, :float
    field :attribution_details, :map, default: %{}

    # Workflow fields
    field :workflow_state, :string
    field :previous_state, :string
    field :state_changed_at, :utc_datetime_usec
    field :assigned_at, :utc_datetime_usec
    field :assignment_notes, :string

    # SLA tracking fields
    field :acknowledged_at, :utc_datetime_usec
    field :sla_acknowledge_deadline, :utc_datetime_usec
    field :sla_resolve_deadline, :utc_datetime_usec
    field :sla_acknowledge_breached, :boolean, default: false
    field :sla_resolve_breached, :boolean, default: false
    field :resolved_at, :utc_datetime_usec

    # Escalation fields
    field :escalation_level, :integer, default: 0
    field :escalated_at, :utc_datetime_usec
    field :escalation_reason, :string

    # Severity adjustment fields
    field :original_severity, :string
    field :severity_adjusted, :boolean, default: false
    field :severity_adjusted_at, :utc_datetime_usec

    # ETW tampering detection fields (MITRE T1562.006)
    field :target_function, :string
    field :original_bytes, :binary
    field :patched_bytes, :binary
    field :patch_pattern, :string
    field :target_region, :string

    # Solana blockchain attestation (Hackathon MVP)
    # Stores the transaction signature for tamper-evident audit trail
    field :blockchain_tx_id, :string
    field :blockchain_attested_at, :utc_datetime_usec
    field :incident_hash, :string
    field :manifest_hash, :string
    field :attestation_tlp, :string
    field :attestation_ioc_count, :integer
    field :attestation_ioc_types, {:array, :string}, default: []
    field :attestation_redacted_ioc_count, :integer
    field :attestation_confidence, :float
    field :attestation_threat_class, :string
    field :attestation_malware_family, :string
    field :public_manifest, :map, default: %{}

    # Detection bounty fields
    field :bounty_tx_id, :string
    field :bounty_amount_lamports, :integer
    field :bounty_paid_at, :utc_datetime_usec

    # Rule author for bounty payment
    field :rule_author_pubkey, :string

    # Alert quality contract fields (storage only; populated by a later lane)
    field :rule_version, :string
    field :recommended_response, :string
    field :false_positive_notes, :string

    belongs_to :organization, Organization
    belongs_to :agent, Agent
    belongs_to :assigned_to, User, foreign_key: :assigned_to_id, type: :binary_id
    belongs_to :assigned_by, User, foreign_key: :assigned_by_id, type: :binary_id
    belongs_to :state_changed_by, User, foreign_key: :state_changed_by_id, type: :binary_id
    belongs_to :acknowledged_by, User, foreign_key: :acknowledged_by_id, type: :binary_id
    belongs_to :escalated_to, User, foreign_key: :escalated_to_id, type: :binary_id
    belongs_to :verdict_by, User, foreign_key: :verdict_by_id, type: :binary_id
    belongs_to :severity_adjusted_by, User, foreign_key: :severity_adjusted_by_id, type: :binary_id

    many_to_many :tags, Tag, join_through: TagAssignment
    has_many :severity_adjustments, SeverityAdjustment

    timestamps()
  end

  @doc false
  def changeset(alert, attrs) do
    alert
    |> cast(attrs, [
      :severity,
      :title,
      :description,
      :event_ids,
      :mitre_tactics,
      :mitre_techniques,
      :status,
      :resolution_notes,
      :threat_score,
      :enrichment,
      :source_event_id,
      :organization_id,
      :agent_id,
      :assigned_to_id,
      # Kubernetes context enrichment
      :k8s_context,
      # Phase 1: Enhanced evidence fields
      :evidence,
      :process_chain,
      :raw_event,
      :detection_metadata,
      :contributing_events,
      # Storyline correlation
      :storyline_id,
      # Alert deduplication fields
      :occurrence_count,
      :last_seen_at,
      :dedup_key,
      # Analyst verdict fields
      :verdict,
      :verdict_by_id,
      :verdict_at,
      :verdict_notes,
      :suppression_rule_id,
      # Behavioral correlation data
      :correlation_data,
      # Threat attribution fields
      :attributed_actors,
      :campaign_id,
      :attribution_confidence,
      :attribution_details,
      # Workflow fields
      :workflow_state,
      :previous_state,
      :state_changed_at,
      :state_changed_by_id,
      :assigned_at,
      :assigned_by_id,
      :assignment_notes,
      # SLA tracking fields
      :acknowledged_at,
      :acknowledged_by_id,
      :sla_acknowledge_deadline,
      :sla_resolve_deadline,
      :sla_acknowledge_breached,
      :sla_resolve_breached,
      :resolved_at,
      # Escalation fields
      :escalation_level,
      :escalated_at,
      :escalated_to_id,
      :escalation_reason,
      # ETW tampering fields
      :target_function,
      :original_bytes,
      :patched_bytes,
      :patch_pattern,
      :target_region,
      # Solana blockchain attestation fields
      :blockchain_tx_id,
      :blockchain_attested_at,
      :incident_hash,
      :manifest_hash,
      :attestation_tlp,
      :attestation_ioc_count,
      :attestation_ioc_types,
      :attestation_redacted_ioc_count,
      :attestation_confidence,
      :attestation_threat_class,
      :attestation_malware_family,
      :public_manifest,
      :bounty_tx_id,
      :bounty_amount_lamports,
      :bounty_paid_at,
      :rule_author_pubkey,
      # Alert quality contract fields (storage only; populated by a later lane)
      :rule_version,
      :recommended_response,
      :false_positive_notes
    ])
    |> update_change(:mitre_tactics, &Mitre.normalize_tactics/1)
    |> update_change(:mitre_techniques, &Mitre.normalize_techniques/1)
    |> update_change(:threat_score, &normalize_threat_score/1)
    |> validate_required([:severity, :title])
    |> maybe_resolve_organization_id()
    |> validate_inclusion(:severity, ~w(critical high medium low info))
    |> validate_inclusion(:status, ~w(new investigating resolved false_positive))
    |> validate_inclusion(:verdict, ~w(unconfirmed true_positive false_positive benign suspicious))
    |> validate_inclusion(:patch_pattern, ~w(ret xor_eax_ret jmp_rel32 jmp_abs nop_sled int3_trap ud2 unknown))
    |> validate_inclusion(:target_region, ~w(syscall_stub etw_function ntdll_text kernel32_text amsi_function other))
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:assigned_to_id)
    |> foreign_key_constraint(:assigned_by_id)
    |> foreign_key_constraint(:state_changed_by_id)
    |> foreign_key_constraint(:acknowledged_by_id)
    |> foreign_key_constraint(:escalated_to_id)
    |> foreign_key_constraint(:verdict_by_id)
  end

  # Threat scores are canonically 0.0-1.0 (see Detection.Config thresholds and
  # the dashboard, which renders `threat_score * 100`). Some auxiliary/legacy
  # producers emit a 0-100 value; collapse those into the canonical range and
  # clamp so severity thresholds and the UI stay coherent. Values already in
  # 0.0-1.0 pass through unchanged, so this is idempotent.
  defp normalize_threat_score(score) when is_number(score) do
    scaled = if score > 1.0, do: score / 100, else: score * 1.0
    scaled |> max(0.0) |> min(1.0)
  end

  defp normalize_threat_score(other), do: other

  # If organization_id was not provided but agent_id was, attempt to resolve
  # the organization via the cached OrgLookup. This ensures alerts are always
  # associated with an organization when possible.
  defp maybe_resolve_organization_id(changeset) do
    org_id = get_change(changeset, :organization_id) || get_field(changeset, :organization_id)
    agent_id = get_change(changeset, :agent_id) || get_field(changeset, :agent_id)

    if is_nil(org_id) and not is_nil(agent_id) do
      case TamanduaServer.Agents.OrgLookup.get_org_id(agent_id) do
        nil -> changeset
        resolved_org_id -> put_change(changeset, :organization_id, resolved_org_id)
      end
    else
      changeset
    end
  end
end
