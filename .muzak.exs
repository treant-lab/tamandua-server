# Muzak Configuration for Elixir Mutation Testing
# This file configures mutation testing for the Tamandua EDR backend
# to validate test suite quality and identify weak test coverage

%{
  # Files to mutate - focus on critical business logic
  files: [
    # Detection engine - critical for security
    "lib/tamandua_server/detection/**/*.ex",

    # Alert management - critical for incident response
    "lib/tamandua_server/alerts/**/*.ex",

    # Telemetry processing - critical for data integrity
    "lib/tamandua_server/telemetry/**/*.ex",

    # Agent management - critical for agent communication
    "lib/tamandua_server/agents/**/*.ex",

    # Response execution - critical for remediation
    "lib/tamandua_server/response/**/*.ex",

    # YARA rule engine
    "lib/tamandua_server/detection/yara/**/*.ex",

    # Sigma rule engine
    "lib/tamandua_server/detection/sigma/**/*.ex",

    # ML integration
    "lib/tamandua_server/detection/ml_client.ex"
  ],

  # Mutation operators to apply
  # Each operator tests different aspects of code logic
  operators: [
    # Arithmetic mutations: +, -, *, /, rem, div
    # Tests: 2 + 3 -> 2 - 3, 2 * 3 -> 2 / 3
    :arithmetic,

    # Comparison mutations: ==, !=, <, >, <=, >=
    # Tests: x > 5 -> x >= 5, x == y -> x != y
    :comparison,

    # Logical mutations: and, or, not, &&, ||
    # Tests: a and b -> a or b, not x -> x
    :logical,

    # Conditional mutations: if, unless, case, cond
    # Tests: if condition -> if not condition
    :conditionals,

    # Constant mutations: true/false, nil, numbers, strings
    # Tests: true -> false, 0 -> 1, "string" -> ""
    :constants,

    # Return mutations: early returns, default values
    # Tests: removing/modifying early returns
    :returns,

    # Function call mutations: argument changes
    # Tests: fn(a, b) -> fn(b, a)
    :function_calls
  ],

  # Patterns to exclude from mutation
  exclude: [
    # Test files themselves
    "**/test/**",
    "**/tests/**",

    # Database migrations
    "**/migrations/**",

    # Generated files
    "**/generated/**",

    # Configuration files
    "**/config/**",

    # Web interface (separate testing strategy)
    "**/tamandua_server_web/live/**",
    "**/tamandua_server_web/controllers/**",

    # Simple getters/setters
    ~r/def get_\w+\(/,
    ~r/def set_\w+\(/,

    # Logging statements (hard to test meaningfully)
    ~r/Logger\.(debug|info|warn|error)/
  ],

  # Test command to run for each mutant
  # Uses faster test strategy for mutation testing
  test_command: "mix test --trace --max-failures 1",

  # Timeout for each test run (seconds)
  # Should be 2-3x normal test suite time
  timeout: 60,

  # Minimum mutation score required (percentage)
  # Below this threshold, mutation testing fails
  threshold: 80,

  # Number of parallel processes
  # Adjust based on available CPU cores
  processes: 4,

  # Output format options
  output: :html,

  # Additional output formats
  additional_outputs: [
    :json,   # For CI/CD integration
    :text    # For console review
  ],

  # Coverage requirements per module
  module_thresholds: %{
    # Critical security modules require higher scores
    "TamanduaServer.Detection.Engine" => 90,
    "TamanduaServer.Detection.Yara" => 85,
    "TamanduaServer.Detection.Sigma" => 85,
    "TamanduaServer.Alerts.Manager" => 85,
    "TamanduaServer.Response.Executor" => 90,

    # Other modules use default threshold
    :default => 80
  },

  # Mutation sampling strategy
  # Use :full for CI/CD, :sample for development
  sampling: :full,

  # Sample size if using sampling (percentage)
  sample_size: 20,

  # Report configuration
  report: %{
    # Show survived mutants (those that need better tests)
    show_survived: true,

    # Show killed mutants (for verification)
    show_killed: false,

    # Show timeout mutants (may indicate slow tests)
    show_timeout: true,

    # Show error mutants (compilation or runtime errors)
    show_errors: true,

    # Group by file
    group_by: :file,

    # Sort by mutation score (ascending - worst first)
    sort_by: :score
  },

  # Advanced options
  advanced: %{
    # Skip equivalent mutants (those that don't change behavior)
    skip_equivalent: true,

    # Use incremental mutation (only mutate changed files)
    incremental: false,

    # Save mutation results for comparison
    save_results: true,

    # Fail fast - stop after N survived mutants
    fail_fast: nil,

    # Verbose output for debugging
    verbose: false
  }
}
