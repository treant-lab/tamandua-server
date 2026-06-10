defmodule TamanduaServer.ThreatIntel.ThreatActor do
  @moduledoc """
  Ecto schema for threat actors.

  Stores threat actor information from MISP galaxies and other sources:
  - Names and aliases
  - Motivation (financial, espionage, hacktivism)
  - Target sectors and regions
  - TTPs (MITRE ATT&CK techniques)
  - Activity timeline

  ## Usage

      # Create a threat actor
      ThreatActor.changeset(%ThreatActor{}, %{
        name: "APT29",
        aliases: ["Cozy Bear", "The Dukes"],
        motivation: "espionage",
        origin_country: "Russia"
      })

      # Link IOCs to a threat actor
      ThreatActor.add_ioc_link(actor, ioc)
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.ThreatIntel.MISPInstance
  alias TamanduaServer.Detection.IOC

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "threat_actors" do
    field :name, :string
    field :description, :string
    field :aliases, {:array, :string}, default: []

    # Classification
    field :motivation, :string  # financial, espionage, hacktivism, sabotage, unknown
    field :sophistication, :string  # novice, intermediate, advanced, expert
    field :resource_level, :string  # individual, small-group, organization, government

    # Attribution
    field :origin_country, :string
    field :target_countries, {:array, :string}, default: []
    field :target_sectors, {:array, :string}, default: []
    field :target_regions, {:array, :string}, default: []

    # MITRE ATT&CK
    field :ttps, {:array, :string}, default: []
    field :primary_tactics, {:array, :string}, default: []

    # Malware and tools
    field :known_malware, {:array, :string}, default: []
    field :known_tools, {:array, :string}, default: []

    # Activity timeline
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :active, :boolean, default: true

    # Source tracking
    field :source, :string, default: "manual"  # manual, misp, otx, etc.
    field :misp_cluster_uuid, :string
    field :galaxy_type, :string
    field :confidence, :float, default: 0.7

    # External references
    field :external_refs, {:array, :map}, default: []
    field :metadata, :map, default: %{}

    # IOC count (denormalized for performance)
    field :ioc_count, :integer, default: 0

    belongs_to :misp_instance, MISPInstance

    timestamps()
  end

  @required_fields ~w(name)a
  @optional_fields ~w(
    description aliases motivation sophistication resource_level
    origin_country target_countries target_sectors target_regions
    ttps primary_tactics known_malware known_tools
    first_seen last_seen active
    source misp_cluster_uuid galaxy_type confidence
    external_refs metadata ioc_count misp_instance_id
  )a

  @valid_motivations ~w(financial espionage hacktivism sabotage vandalism unknown)
  @valid_sophistication ~w(novice intermediate advanced expert)
  @valid_resource_levels ~w(individual small-group organization government)

  @doc false
  def changeset(actor, attrs) do
    actor
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:motivation, @valid_motivations)
    |> validate_inclusion(:sophistication, @valid_sophistication)
    |> validate_inclusion(:resource_level, @valid_resource_levels)
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint(:misp_cluster_uuid)
    |> foreign_key_constraint(:misp_instance_id)
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  @doc """
  List all threat actors with optional filters.

  ## Options
    - `:motivation` - Filter by motivation type
    - `:active` - Filter by active status
    - `:origin_country` - Filter by origin country
    - `:limit` - Maximum results (default: 50)
    - `:order_by` - Field to order by (default: :name)
  """
  def list(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    order_by = Keyword.get(opts, :order_by, :name)

    base_query =
      from(a in __MODULE__,
        order_by: [asc: ^order_by],
        limit: ^limit
      )

    base_query
    |> apply_filters(opts)
    |> Repo.all()
  end

  defp apply_filters(query, []), do: query

  defp apply_filters(query, [{:motivation, motivation} | rest]) when is_binary(motivation) do
    query
    |> where([a], a.motivation == ^motivation)
    |> apply_filters(rest)
  end

  defp apply_filters(query, [{:active, active} | rest]) when is_boolean(active) do
    query
    |> where([a], a.active == ^active)
    |> apply_filters(rest)
  end

  defp apply_filters(query, [{:origin_country, country} | rest]) when is_binary(country) do
    query
    |> where([a], a.origin_country == ^country)
    |> apply_filters(rest)
  end

  defp apply_filters(query, [{:search, term} | rest]) when is_binary(term) do
    pattern = "%#{term}%"

    query
    |> where([a], ilike(a.name, ^pattern) or fragment("? && ARRAY[?]", a.aliases, ^term))
    |> apply_filters(rest)
  end

  defp apply_filters(query, [_ | rest]), do: apply_filters(query, rest)

  @doc """
  Get a threat actor by ID.
  """
  def get(id), do: Repo.get(__MODULE__, id)

  @doc """
  Get a threat actor by name or alias.
  """
  def get_by_name(name) do
    name_lower = String.downcase(name)

    from(a in __MODULE__,
      where: fragment("LOWER(?) = ?", a.name, ^name_lower) or
             fragment("LOWER(?) = ANY(SELECT LOWER(unnest(?)))", ^name_lower, a.aliases),
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  Get threat actors by TTP.
  """
  def get_by_ttp(technique_id) do
    from(a in __MODULE__,
      where: ^technique_id in a.ttps,
      order_by: [desc: a.last_seen]
    )
    |> Repo.all()
  end

  @doc """
  Create a new threat actor.
  """
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a threat actor.
  """
  def update(%__MODULE__{} = actor, attrs) do
    actor
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a threat actor.
  """
  def delete(%__MODULE__{} = actor) do
    Repo.delete(actor)
  end

  # ============================================================================
  # IOC Linking
  # ============================================================================

  @doc """
  Link IOCs to a threat actor.
  Updates the IOC metadata to include threat actor reference.
  """
  def link_iocs(%__MODULE__{id: actor_id, name: name}, ioc_ids) when is_list(ioc_ids) do
    from(i in IOC,
      where: i.id in ^ioc_ids,
      update: [
        set: [
          metadata: fragment(
            "COALESCE(?, '{}'::jsonb) || ?",
            i.metadata,
            ^%{"threat_actor_id" => actor_id, "threat_actor_name" => name}
          )
        ]
      ]
    )
    |> Repo.update_all([])

    # Update IOC count
    update_ioc_count(actor_id)
  end

  @doc """
  Get IOCs linked to a threat actor.
  """
  def get_linked_iocs(%__MODULE__{id: actor_id}, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(i in IOC,
      where: fragment("?->>'threat_actor_id' = ?", i.metadata, ^actor_id),
      order_by: [desc: i.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  defp update_ioc_count(actor_id) do
    count =
      from(i in IOC,
        where: fragment("?->>'threat_actor_id' = ?", i.metadata, ^actor_id),
        select: count(i.id)
      )
      |> Repo.one()

    from(a in __MODULE__, where: a.id == ^actor_id)
    |> Repo.update_all(set: [ioc_count: count || 0])
  end

  # ============================================================================
  # Attribution
  # ============================================================================

  @doc """
  Find potential threat actor attribution for an alert.

  Uses TTPs, IOCs, and malware families to identify likely threat actors.
  Returns a list of potential attributions with confidence scores.
  """
  def find_attribution(alert) do
    techniques = Map.get(alert, :mitre_techniques, []) || []
    enrichment = Map.get(alert, :enrichment, %{}) || %{}
    malware = Map.get(enrichment, "malware_family", nil)

    # Score each actor
    actors = list(limit: 100, active: true)

    actors
    |> Enum.map(fn actor ->
      score = calculate_attribution_score(actor, techniques, malware)
      {actor, score}
    end)
    |> Enum.filter(fn {_, score} -> score > 0 end)
    |> Enum.sort_by(fn {_, score} -> score end, :desc)
    |> Enum.take(5)
    |> Enum.map(fn {actor, score} ->
      %{
        actor: actor,
        confidence: min(score / 100, 1.0),
        matching_ttps: Enum.filter(techniques, &(&1 in actor.ttps)),
        matching_malware: if(malware && malware in actor.known_malware, do: malware)
      }
    end)
  end

  defp calculate_attribution_score(actor, techniques, malware) do
    # TTP matching (each matching TTP = 20 points, max 60)
    ttp_matches = Enum.count(techniques, &(&1 in actor.ttps))
    ttp_score = min(ttp_matches * 20, 60)

    # Malware matching (30 points)
    malware_score =
      if malware && malware in actor.known_malware do
        30
      else
        0
      end

    # Recency bonus (up to 10 points)
    recency_score =
      case actor.last_seen do
        nil -> 0
        last_seen ->
          days_ago = DateTime.diff(DateTime.utc_now(), last_seen, :day)
          cond do
            days_ago < 30 -> 10
            days_ago < 90 -> 5
            days_ago < 365 -> 2
            true -> 0
          end
      end

    ttp_score + malware_score + recency_score
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  @doc """
  Get threat actor statistics.
  """
  def get_stats do
    total = Repo.aggregate(__MODULE__, :count, :id)
    active = Repo.aggregate(from(a in __MODULE__, where: a.active == true), :count, :id)

    by_motivation =
      from(a in __MODULE__,
        where: a.active == true and not is_nil(a.motivation),
        group_by: a.motivation,
        select: {a.motivation, count(a.id)}
      )
      |> Repo.all()
      |> Map.new()

    by_country =
      from(a in __MODULE__,
        where: a.active == true and not is_nil(a.origin_country),
        group_by: a.origin_country,
        select: {a.origin_country, count(a.id)}
      )
      |> Repo.all()
      |> Map.new()

    %{
      total: total,
      active: active,
      by_motivation: by_motivation,
      by_country: by_country
    }
  end
end
