defmodule TamanduaServer.Support.EscalationWorkerProductLockTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Support.EscalationWorker

  defmodule RepoSpy do
    def all(_query), do: notify(:repo_all)
    def update(_changeset), do: notify(:repo_update)

    defp notify(operation) do
      send(self(), operation)
      raise "disabled support escalation worker called #{operation}"
    end
  end

  defmodule DispatcherSpy do
    def dispatch(_type, _title, _body, _attrs) do
      send(self(), :dispatcher_dispatch)
      raise "disabled support escalation worker dispatched a notification"
    end
  end

  setup do
    previous = Application.get_env(:tamandua_server, EscalationWorker)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, EscalationWorker)
      else
        Application.put_env(:tamandua_server, EscalationWorker, previous)
      end
    end)

    :ok
  end

  test "default product lock returns disabled without repository or notification effects" do
    Application.put_env(:tamandua_server, EscalationWorker,
      repo: RepoSpy,
      dispatcher: DispatcherSpy
    )

    assert {:ok, %{status: :disabled, reason: :product_lock}} =
             EscalationWorker.perform(%Oban.Job{})

    refute_received :repo_all
    refute_received :repo_update
    refute_received :dispatcher_dispatch
  end

  test "only literal true opens the product lock" do
    worker_source = source("lib/tamandua_server/support/escalation_worker.ex")
    guard_position = position(worker_source, "Keyword.get(config, :enabled, false) === true")
    clock_position = position(worker_source, "now = DateTime.utc_now()")
    repo_position = position(worker_source, "Keyword.get(config, :repo, Repo)")

    dispatcher_position =
      position(worker_source, "Keyword.get(config, :dispatcher, Dispatcher)")

    assert guard_position < clock_position
    assert guard_position < repo_position
    assert guard_position < dispatcher_position

    for value <- [false, nil, 1, "true", :enabled] do
      Application.put_env(:tamandua_server, EscalationWorker,
        enabled: value,
        repo: RepoSpy,
        dispatcher: DispatcherSpy
      )

      assert {:ok, %{status: :disabled, reason: :product_lock}} =
               EscalationWorker.perform(%Oban.Job{})
    end

    refute_received :repo_all
    refute_received :repo_update
    refute_received :dispatcher_dispatch
  end

  test "current Oban configuration has no support queue or cron registration" do
    for source <- config_sources() do
      refute source =~ "support:"
      refute source =~ "TamanduaServer.Support.EscalationWorker"
    end
  end

  defp source(relative_path) do
    Path.expand("../../../#{relative_path}", __DIR__)
    |> File.read!()
  end

  defp config_sources do
    Path.expand("../../../config/*.{ex,exs}", __DIR__)
    |> Path.wildcard()
    |> Enum.map(&File.read!/1)
  end

  defp position(source, needle) do
    {position, _length} = :binary.match(source, needle)
    position
  end
end
