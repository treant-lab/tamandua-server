defmodule TamanduaServer.Detection.ThreatIntelCache do
  @moduledoc """
  Schema for cached threat intelligence data from external feeds.

  This table stores IOCs retrieved from external threat intelligence feeds
  such as Abuse.ch (MalwareBazaar, URLhaus, ThreatFox) and AlienVault OTX.

  The cache is periodically refreshed by the ThreatIntel.Feeds GenServer
  and provides fast lookups during event analysis.

  ## Fields

  - `ioc_type` - Type of indicator: hash, ip, domain, url
  - `ioc_value` - The actual indicator value (normalized/lowercased)
  - `feed_source` - Source feed: malwarebazaar, urlhaus, threatfox, alienvault_otx
  - `threat_type` - Type of threat: malware, botnet_cc, phishing, etc.
  - `malware_family` - Associated malware family if known
  - `confidence` - Confidence score (0.0 to 1.0)
  - `tags` - Array of classification tags
  - `first_seen` - When the IOC was first reported
  - `last_seen` - When the IOC was last seen/updated
  - `raw_data` - Additional data from the feed (JSON)
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "threat_intel_cache" do
    field :ioc_type, :string  # hash, ip, domain, url
    field :ioc_value, :string
    field :feed_source, :string  # malwarebazaar, urlhaus, threatfox, alienvault_otx
    field :threat_type, :string  # malware, botnet_cc, phishing, c2, ransomware, etc.
    field :malware_family, :string
    field :confidence, :float, default: 0.5
    field :tags, {:array, :string}, default: []
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :raw_data, :map, default: %{}

    timestamps()
  end

  @required_fields [:ioc_type, :ioc_value, :feed_source]
  @optional_fields [:threat_type, :malware_family, :confidence, :tags, :first_seen, :last_seen, :raw_data]

  @valid_ioc_types ["hash", "ip", "domain", "url", "unknown"]
  @valid_feed_sources ["malwarebazaar", "urlhaus", "threatfox", "alienvault_otx", "custom"]

  @doc """
  Creates a changeset for a threat intel cache entry.
  """
  def changeset(cache, attrs) do
    cache
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:ioc_type, @valid_ioc_types)
    |> validate_inclusion(:feed_source, @valid_feed_sources)
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint([:ioc_type, :ioc_value, :feed_source])
  end

  @doc """
  Creates a changeset for bulk insert operations.
  """
  def bulk_changeset(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
  end
end
