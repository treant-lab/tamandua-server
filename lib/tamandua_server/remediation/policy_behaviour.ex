defmodule TamanduaServer.Remediation.PolicyBehaviour do
  @moduledoc """
  Behaviour for remediation policy modules.

  Policy modules implement specific remediation strategies and rules
  for automated response actions.

  ## Implementing a Policy

      defmodule MyApp.Remediation.CustomPolicy do
        @behaviour TamanduaServer.Remediation.PolicyBehaviour

        @impl true
        def name, do: "custom_policy"

        @impl true
        def description, do: "Custom policy for specific threats"

        @impl true
        def default_rules do
          [
            %{
              id: "rule_1",
              name: "Auto-respond to critical",
              condition: %{severity: :critical},
              action: :quarantine
            }
          ]
        end

        @impl true
        def evaluate(alert, context) do
          # Return matching action or :no_match
        end

        @impl true
        def execute(action, context) do
          # Execute the action
        end
      end
  """

  @doc "Return the unique policy name identifier"
  @callback name() :: String.t()

  @doc "Return a human-readable description of the policy"
  @callback description() :: String.t()

  @doc "Return the default rules for this policy"
  @callback default_rules() :: [map()]

  @doc "Evaluate an alert against policy rules and return recommended action"
  @callback evaluate(alert :: map(), context :: map()) ::
              {:ok, action :: map()} | {:no_match, reason :: String.t()}

  @doc "Execute a recommended action"
  @callback execute(action :: map(), context :: map()) ::
              {:ok, result :: map()} | {:error, reason :: term()}
end
