defmodule TamanduaServer.Detection.DSL do
  @moduledoc """
  Main DSL module - provides unified interface to all DSL components.

  This is the primary entry point for working with the Tamandua Detection DSL.

  ## Quick Start

      # Parse DSL source
      {:ok, ast} = DSL.parse(source)

      # Compile to executable detection
      {:ok, compiled} = DSL.compile(ast)

      # Load into runtime
      :ok = DSL.load_detection(source)

      # Process events
      {:ok, results} = DSL.process_event(event)

  ## Architecture

  - **Lexer** - Tokenizes DSL source code
  - **Parser** - Builds Abstract Syntax Tree (AST)
  - **Compiler** - Compiles AST to executable functions
  - **Runtime** - Executes detections, tracks state
  - **API** - Database persistence and management

  ## See Also

  - `TamanduaServer.Detection.DSL.Grammar` - Language specification
  - `TamanduaServer.Detection.DSL.Parser` - Parse DSL to AST
  - `TamanduaServer.Detection.DSL.Compiler` - Compile AST to code
  - `TamanduaServer.Detection.DSL.Runtime` - Execute detections
  - `TamanduaServer.Detection.DSL.API` - Management API
  """

  alias TamanduaServer.Detection.DSL.{
    Grammar,
    Lexer,
    Parser,
    Compiler,
    Runtime,
    API
  }

  # ─────────────────────────────────────────────────────────────────────
  # Public API - Parsing
  # ─────────────────────────────────────────────────────────────────────

  @doc """
  Parse DSL source code into an Abstract Syntax Tree.

  ## Examples

      iex> source = "detection test { name: \\"Test\\" severity: high }"
      iex> {:ok, ast} = DSL.parse(source)
      iex> ast.name
      "test"
  """
  @spec parse(String.t()) :: {:ok, map()} | {:error, String.t()}
  defdelegate parse(source), to: Parser

  @doc """
  Tokenize DSL source code.

  Useful for syntax highlighting and debugging.

  ## Examples

      iex> {:ok, tokens} = DSL.tokenize("detection test { }")
      iex> Enum.take(tokens, 3)
      [{:keyword, "detection"}, {:identifier, "test"}, {:symbol, "{"}]
  """
  @spec tokenize(String.t()) :: {:ok, [Lexer.token()]} | {:error, String.t()}
  defdelegate tokenize(source), to: Lexer

  # ─────────────────────────────────────────────────────────────────────
  # Public API - Compilation
  # ─────────────────────────────────────────────────────────────────────

  @doc """
  Compile AST into executable detection.

  ## Examples

      iex> {:ok, ast} = DSL.parse(source)
      iex> {:ok, compiled} = DSL.compile(ast)
      iex> compiled.name
      "test"
  """
  @spec compile(map()) :: {:ok, Compiler.compiled_detection()} | {:error, String.t()}
  defdelegate compile(ast), to: Compiler

  @doc """
  Parse and compile DSL source in one step.

  ## Examples

      iex> {:ok, compiled} = DSL.compile_source(source)
  """
  @spec compile_source(String.t()) :: {:ok, Compiler.compiled_detection()} | {:error, String.t()}
  def compile_source(source) do
    with {:ok, ast} <- parse(source),
         {:ok, compiled} <- compile(ast) do
      {:ok, compiled}
    end
  end

  @doc """
  Validate DSL source without compiling.

  Checks for syntax errors and semantic issues.

  ## Examples

      iex> DSL.validate(source)
      :ok
  """
  @spec validate(String.t()) :: :ok | {:error, String.t()}
  defdelegate validate(source), to: API, as: :validate_source

  # ─────────────────────────────────────────────────────────────────────
  # Public API - Runtime
  # ─────────────────────────────────────────────────────────────────────

  @doc """
  Load a detection into the runtime from source code.

  ## Examples

      iex> DSL.load_detection(source)
      {:ok, "detection_name"}
  """
  @spec load_detection(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defdelegate load_detection(source), to: Runtime

  @doc """
  Load multiple detections at once.

  ## Examples

      iex> DSL.load_detections([source1, source2])
      {:ok, ["detection1", "detection2"]}
  """
  @spec load_detections([String.t()]) :: {:ok, [String.t()]} | {:error, String.t()}
  defdelegate load_detections(sources), to: Runtime

  @doc """
  Unload a detection from the runtime.

  ## Examples

      iex> DSL.unload_detection("lateral_movement")
      :ok
  """
  @spec unload_detection(String.t()) :: :ok
  defdelegate unload_detection(name), to: Runtime

  @doc """
  Process an event through all loaded detections.

  Returns list of triggered detections.

  ## Examples

      iex> event = %{"event_type" => "process_create", "payload" => %{...}}
      iex> {:ok, results} = DSL.process_event(event)
      iex> Enum.map(results, & &1.detection)
      ["lateral_movement", "credential_dumping"]
  """
  @spec process_event(map()) :: {:ok, [map()]}
  defdelegate process_event(event), to: Runtime

  @doc """
  Get list of loaded detection names.

  ## Examples

      iex> DSL.list_detections()
      ["lateral_movement", "credential_dumping", ...]
  """
  @spec list_detections() :: [String.t()]
  defdelegate list_detections(), to: Runtime

  @doc """
  Get runtime statistics.

  ## Examples

      iex> DSL.get_stats()
      %{
        events_processed: 1234,
        detections_triggered: 56,
        loaded_detections: 10,
        ...
      }
  """
  @spec get_stats() :: map()
  defdelegate get_stats(), to: Runtime

  # ─────────────────────────────────────────────────────────────────────
  # Public API - Persistence
  # ─────────────────────────────────────────────────────────────────────

  @doc """
  Create and persist a detection.

  Saves to database and loads into runtime.

  ## Examples

      iex> DSL.create_detection(%{source: source, created_by: "admin"})
      {:ok, %DslDetection{}}
  """
  @spec create_detection(map()) :: {:ok, TamanduaServer.Detection.DslDetection.t()} | {:error, term()}
  defdelegate create_detection(attrs), to: API

  @doc """
  Update an existing detection.

  ## Examples

      iex> DSL.update_detection(id, %{source: new_source})
      {:ok, %DslDetection{}}
  """
  @spec update_detection(String.t(), map()) :: {:ok, TamanduaServer.Detection.DslDetection.t()} | {:error, term()}
  defdelegate update_detection(id, attrs), to: API

  @doc """
  Delete a detection.

  Removes from database and unloads from runtime.

  ## Examples

      iex> DSL.delete_detection(id)
      {:ok, %DslDetection{}}
  """
  @spec delete_detection(String.t()) :: {:ok, TamanduaServer.Detection.DslDetection.t()} | {:error, term()}
  defdelegate delete_detection(id), to: API

  @doc """
  Get a detection by ID.

  ## Examples

      iex> DSL.get_detection(id)
      %DslDetection{name: "lateral_movement", ...}
  """
  @spec get_detection(String.t()) :: TamanduaServer.Detection.DslDetection.t() | nil
  defdelegate get_detection(id), to: API

  @doc """
  Reload all enabled detections from database.

  ## Examples

      iex> DSL.reload_all()
      {:ok, 15}
  """
  @spec reload_all() :: {:ok, integer()} | {:error, term()}
  defdelegate reload_all(), to: API

  @doc """
  Get detection templates.

  Returns a map of template name => DSL source.

  ## Examples

      iex> templates = DSL.get_templates()
      iex> Map.keys(templates)
      ["lateral_movement", "credential_dumping", ...]
  """
  @spec get_templates() :: %{String.t() => String.t()}
  defdelegate get_templates(), to: API

  # ─────────────────────────────────────────────────────────────────────
  # Public API - Utilities
  # ─────────────────────────────────────────────────────────────────────

  @doc """
  Get grammar reference.

  Returns information about DSL syntax, keywords, operators, etc.

  ## Examples

      iex> DSL.grammar_info()
      %{
        keywords: [...],
        operators: [...],
        event_types: [...],
        ...
      }
  """
  @spec grammar_info() :: map()
  def grammar_info do
    %{
      keywords: Grammar.keywords(),
      operators: Grammar.operators(),
      symbols: Grammar.symbols(),
      event_types: Grammar.event_types(),
      aggregation_functions: Grammar.aggregation_functions(),
      severity_levels: Grammar.severity_levels()
    }
  end

  @doc """
  Format AST for human-readable output.

  ## Examples

      iex> {:ok, ast} = DSL.parse(source)
      iex> IO.puts DSL.format_ast(ast)
  """
  @spec format_ast(map()) :: String.t()
  defdelegate format_ast(ast), to: Parser

  @doc """
  Format tokens for debugging.

  ## Examples

      iex> {:ok, tokens} = DSL.tokenize(source)
      iex> IO.puts DSL.format_tokens(tokens)
  """
  @spec format_tokens([Lexer.token()]) :: String.t()
  defdelegate format_tokens(tokens), to: Lexer

  @doc """
  Clear all runtime state (for testing).

  ## Examples

      iex> DSL.clear_state()
      :ok
  """
  @spec clear_state() :: :ok
  defdelegate clear_state(), to: Runtime
end
