defmodule TamanduaServer.Accounts.PlatformOperatorSession do
  @moduledoc """
  Opaque projection returned by a server-owned persistent session store.

  The current Tamandua user session implementation is ETS-backed and therefore
  cannot satisfy this contract. The default store deliberately fails closed.
  """

  @enforce_keys [:id, :user_id, :binding_hash, :authenticated_at, :expires_at]
  defstruct [
    :id,
    :user_id,
    :binding_hash,
    :authenticated_at,
    :expires_at,
    :revoked_at,
    auth_method: :session
  ]

  @type t :: %__MODULE__{
          id: binary(),
          user_id: binary(),
          binding_hash: binary(),
          authenticated_at: DateTime.t(),
          expires_at: DateTime.t(),
          revoked_at: DateTime.t() | nil,
          auth_method: :session
        }

  defmodule Store do
    @moduledoc false
    @callback fetch_for_update(Ecto.Repo.t(), binary(), binary()) ::
                {:ok, TamanduaServer.Accounts.PlatformOperatorSession.t()} | {:error, atom()}
  end

  defmodule UnavailableStore do
    @moduledoc false
    @behaviour Store

    @impl true
    def fetch_for_update(_repo, _session_id, _binding), do: {:error, :persistent_session_required}
  end

  defmodule PersistentStore do
    @moduledoc false
    @behaviour Store

    @impl true
    def fetch_for_update(repo, session_id, binding) do
      TamanduaServer.Accounts.PersistentUserSessionStore.fetch_for_update(
        repo,
        session_id,
        binding
      )
    end
  end
end
