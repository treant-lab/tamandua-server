defmodule TamanduaServer.AI.ConversationStore do
  @moduledoc """
  Server-side persistence for AI Assistant conversations.

  Uses PostgreSQL for durable history and keeps an ETS cache as a safe fallback
  while migrations are being applied or the database is temporarily unavailable.

  Each conversation has:
  - id: unique UUID
  - user_id: the owning user
  - title: derived from the first user message
  - messages: list of %{role, content, timestamp}
  - created_at / updated_at: timestamps
  """

  use GenServer
  import Ecto.Query

  alias TamanduaServer.AI.Conversation
  alias TamanduaServer.Repo

  require Logger

  @ets_table :ai_conversations

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  List conversations for a given user, ordered by most-recently updated first.
  """
  @spec list_conversations(String.t()) :: [map()]
  def list_conversations(user_id) do
    GenServer.call(__MODULE__, {:list, user_id})
  end

  @doc """
  Get a single conversation by ID.
  Returns `{:ok, conversation}` or `{:error, :not_found}`.
  """
  @spec get_conversation(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_conversation(conversation_id) do
    GenServer.call(__MODULE__, {:get, conversation_id})
  end

  @doc """
  Get a single conversation by owner and ID.
  """
  @spec get_conversation(String.t(), String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_conversation(user_id, conversation_id) do
    GenServer.call(__MODULE__, {:get_for_user, user_id, conversation_id})
  end

  @doc """
  Save (create or update) a conversation.

  When `conversation_id` is nil a new conversation is created.
  Returns `{:ok, conversation}`.
  """
  @spec save_conversation(String.t(), String.t() | nil, String.t(), [map()]) :: {:ok, map()}
  def save_conversation(user_id, conversation_id, title, messages) do
    GenServer.call(__MODULE__, {:save, user_id, conversation_id, title, messages})
  end

  @doc """
  Delete a conversation.
  """
  @spec delete_conversation(String.t()) :: :ok
  def delete_conversation(conversation_id) do
    GenServer.cast(__MODULE__, {:delete, conversation_id})
  end

  @doc """
  Delete a conversation only when it belongs to the given user.
  """
  @spec delete_conversation(String.t(), String.t()) :: :ok
  def delete_conversation(user_id, conversation_id) do
    GenServer.call(__MODULE__, {:delete_for_user, user_id, conversation_id})
  end

  # ---------------------------------------------------------------------------
  # Server Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    table = :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])
    warm_cache_from_db()
    Logger.info("AI ConversationStore started (ETS table: #{inspect(table)}, durable: postgres)")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:list, user_id}, _from, state) do
    conversations =
      case list_from_db(user_id) do
        {:ok, conversations} ->
          Enum.each(conversations, &cache_conversation/1)
          conversations

        {:error, reason} ->
          Logger.warning("AI conversation DB list failed, using ETS fallback: #{inspect(reason)}")
          list_from_ets(user_id)
      end

    {:reply, conversations, state}
  end

  @impl true
  def handle_call({:get, conversation_id}, _from, state) do
    result =
      case get_from_db(conversation_id) do
        {:ok, conversation} ->
          cache_conversation(conversation)
          {:ok, conversation}

        {:error, :not_found} ->
          get_from_ets(conversation_id)

        {:error, reason} ->
          Logger.warning("AI conversation DB get failed, using ETS fallback: #{inspect(reason)}")
          get_from_ets(conversation_id)
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_for_user, user_id, conversation_id}, _from, state) do
    result =
      case get_from_db(conversation_id, user_id) do
        {:ok, conversation} ->
          cache_conversation(conversation)
          {:ok, conversation}

        {:error, :not_found} ->
          get_from_ets(conversation_id, user_id)

        {:error, reason} ->
          Logger.warning("AI conversation DB scoped get failed, using ETS fallback: #{inspect(reason)}")
          get_from_ets(conversation_id, user_id)
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:save, user_id, conversation_id, title, messages}, _from, state) do
    result =
      case save_to_db(user_id, conversation_id, title, messages) do
        {:ok, conversation} ->
          cache_conversation(conversation)
          {:ok, conversation}

        {:error, :not_found} = error ->
          error

        {:error, reason} ->
          Logger.warning("AI conversation DB save failed, using ETS fallback: #{inspect(reason)}")
          conversation = save_to_ets(user_id, conversation_id, title, messages)
          cache_conversation(conversation)
          {:ok, conversation}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:delete_for_user, user_id, conversation_id}, _from, state) do
    delete_from_db(conversation_id, user_id)
    delete_from_ets(conversation_id, user_id)
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:delete, conversation_id}, state) do
    delete_from_db(conversation_id)
    :ets.delete(@ets_table, conversation_id)
    {:noreply, state}
  end

  defp list_from_db(user_id) do
    conversations =
      Conversation
      |> where([c], c.user_id == ^user_id)
      |> order_by([c], desc: c.updated_at)
      |> limit(50)
      |> Repo.all()
      |> Enum.map(&serialize_conversation/1)

    {:ok, conversations}
  rescue
    e -> {:error, e}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp get_from_db(conversation_id) do
    case Repo.get(Conversation, conversation_id) do
      nil -> {:error, :not_found}
      conversation -> {:ok, serialize_conversation(conversation)}
    end
  rescue
    e -> {:error, e}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp get_from_db(conversation_id, user_id) do
    case Repo.get_by(Conversation, id: conversation_id, user_id: user_id) do
      nil -> {:error, :not_found}
      conversation -> {:ok, serialize_conversation(conversation)}
    end
  rescue
    e -> {:error, e}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp save_to_db(user_id, conversation_id, title, messages) do
    id = conversation_id || Ecto.UUID.generate()
    attrs = %{id: id, user_id: user_id, title: title || "Untitled", messages: normalize_messages(messages)}

    result =
      case Repo.get(Conversation, id) do
        nil -> %Conversation{id: id}
        %{user_id: ^user_id} = conversation -> conversation
        _other_owner -> :not_found
      end

    case result do
      :not_found ->
        {:error, :not_found}

      conversation ->
        case conversation |> Conversation.changeset(attrs) |> upsert_conversation() do
          {:ok, conversation} -> {:ok, serialize_conversation(conversation)}
          {:error, changeset} -> {:error, changeset}
        end
    end
  rescue
    e -> {:error, e}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp upsert_conversation(%Ecto.Changeset{data: %Conversation{__meta__: %{state: :built}}} = changeset) do
    Repo.insert(changeset)
  end

  defp upsert_conversation(changeset), do: Repo.update(changeset)

  defp delete_from_db(conversation_id) do
    Conversation
    |> where([c], c.id == ^conversation_id)
    |> Repo.delete_all()

    :ok
  rescue
    e ->
      Logger.warning("AI conversation DB delete failed: #{Exception.message(e)}")
      :ok
  catch
    kind, reason ->
      Logger.warning("AI conversation DB delete crashed: #{kind} #{inspect(reason)}")
      :ok
  end

  defp delete_from_db(conversation_id, user_id) do
    Conversation
    |> where([c], c.id == ^conversation_id and c.user_id == ^user_id)
    |> Repo.delete_all()

    :ok
  rescue
    e ->
      Logger.warning("AI conversation scoped DB delete failed: #{Exception.message(e)}")
      :ok
  catch
    kind, reason ->
      Logger.warning("AI conversation scoped DB delete crashed: #{kind} #{inspect(reason)}")
      :ok
  end

  defp warm_cache_from_db do
    Conversation
    |> order_by([c], desc: c.updated_at)
    |> limit(200)
    |> Repo.all()
    |> Enum.map(&serialize_conversation/1)
    |> Enum.each(&cache_conversation/1)
  rescue
    e ->
      Logger.warning("AI conversation cache warmup skipped: #{Exception.message(e)}")
      :ok
  catch
    kind, reason ->
      Logger.warning("AI conversation cache warmup crashed: #{kind} #{inspect(reason)}")
      :ok
  end

  defp list_from_ets(user_id) do
    :ets.tab2list(@ets_table)
    |> Enum.filter(fn {_id, conv} -> conv.user_id == user_id || conv[:user_id] == user_id end)
    |> Enum.map(fn {_id, conv} -> conv end)
    |> Enum.sort_by(&(&1.updated_at || &1[:updated_at]), {:desc, DateTime})
  end

  defp get_from_ets(conversation_id) do
    case :ets.lookup(@ets_table, conversation_id) do
      [{^conversation_id, conv}] -> {:ok, conv}
      [] -> {:error, :not_found}
    end
  end

  defp get_from_ets(conversation_id, user_id) do
    case :ets.lookup(@ets_table, conversation_id) do
      [{^conversation_id, conv}] ->
        if conv.user_id == user_id || conv[:user_id] == user_id do
          {:ok, conv}
        else
          {:error, :not_found}
        end

      [] ->
        {:error, :not_found}
    end
  end

  defp delete_from_ets(conversation_id, user_id) do
    case get_from_ets(conversation_id, user_id) do
      {:ok, _conv} -> :ets.delete(@ets_table, conversation_id)
      {:error, :not_found} -> :ok
    end
  end

  defp save_to_ets(user_id, conversation_id, title, messages) do
    now = DateTime.utc_now()

    {id, created_at} =
      case conversation_id do
        nil ->
          {Ecto.UUID.generate(), now}

        existing ->
          case :ets.lookup(@ets_table, existing) do
            [{^existing, prev}] -> {existing, prev.created_at || prev[:created_at] || now}
            [] -> {existing, now}
          end
      end

    %{
      id: id,
      user_id: user_id,
      title: title || "Untitled",
      messages: normalize_messages(messages),
      created_at: created_at,
      createdAt: DateTime.to_iso8601(created_at),
      updated_at: now,
      updatedAt: DateTime.to_iso8601(now)
    }
  end

  defp cache_conversation(%{id: id} = conversation) when is_binary(id) do
    :ets.insert(@ets_table, {id, conversation})
    :ok
  end

  defp cache_conversation(_), do: :ok

  defp serialize_conversation(%Conversation{} = conversation) do
    %{
      id: conversation.id,
      user_id: conversation.user_id,
      title: conversation.title,
      messages: conversation.messages || [],
      created_at: conversation.inserted_at,
      createdAt: format_datetime(conversation.inserted_at),
      updated_at: conversation.updated_at,
      updatedAt: format_datetime(conversation.updated_at)
    }
  end

  defp normalize_messages(messages) when is_list(messages) do
    Enum.map(messages, fn
      message when is_map(message) ->
        message
        |> Enum.map(fn {key, value} -> {to_string(key), value} end)
        |> Enum.into(%{})

      other ->
        %{"role" => "assistant", "content" => to_string(other), "timestamp" => DateTime.to_iso8601(DateTime.utc_now())}
    end)
  end

  defp normalize_messages(_), do: []

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
end
