defmodule TamanduaServer.Detection.DSL.Grammar do
  @moduledoc """
  DSL Grammar specification for Tamandua custom detection language.

  ## Grammar (EBNF notation)

  ```ebnf
  detection        ::= detection_header "{" detection_body "}"

  detection_header ::= "detection" IDENTIFIER

  detection_body   ::= metadata_block sequence_block? aggregation_block?

  metadata_block   ::= (metadata_line)*
  metadata_line    ::= IDENTIFIER ":" value

  sequence_block   ::= "sequence" temporal_constraint? "{" event_list "}"
  temporal_constraint ::= "within" DURATION

  event_list       ::= event_def+
  event_def        ::= "event" IDENTIFIER ":" event_type "{" event_conditions "}"

  event_type       ::= "process_create" | "network_connect" | "file_write" |
                       "registry_write" | "dns_query" | "module_load" |
                       "any"

  event_conditions ::= (where_clause | capture_clause)*

  where_clause     ::= "where:" expression
  expression       ::= logical_or
  logical_or       ::= logical_and ("OR" logical_and)*
  logical_and      ::= comparison ("AND" comparison)*
  comparison       ::= field_ref operator value
                     | field_ref "in" list
                     | field_ref "matches" regex
                     | "not" expression
                     | "(" expression ")"

  field_ref        ::= IDENTIFIER ("." IDENTIFIER)*
  operator         ::= "=" | "!=" | ">" | ">=" | "<" | "<=" | "contains" |
                       "startswith" | "endswith"

  capture_clause   ::= "capture:" capture_list
  capture_list     ::= IDENTIFIER ("," IDENTIFIER)*

  aggregation_block ::= "aggregation" "{" aggregation_rule+ "}"
  aggregation_rule  ::= agg_expression "->" action

  agg_expression   ::= agg_function "(" agg_field ")" operator value temporal_constraint?
  agg_function     ::= "count" | "sum" | "avg" | "min" | "max" | "stddev" |
                       "percentile" | "z_score"

  agg_field        ::= field_ref | "distinct" field_ref | "*"

  action           ::= "escalate" "to" severity
                     | "create_alert" STRING
                     | "execute" STRING

  severity         ::= "critical" | "high" | "medium" | "low" | "info"

  value            ::= STRING | NUMBER | BOOLEAN | IDENTIFIER | call_ml
  call_ml          ::= "ml" "(" STRING "," field_ref ")"

  list             ::= "[" value ("," value)* "]"
  regex            ::= "/" PATTERN "/"

  DURATION         ::= NUMBER ("s" | "m" | "h" | "d")
  IDENTIFIER       ::= [a-zA-Z_][a-zA-Z0-9_]*
  STRING           ::= '"' [^"]* '"'
  NUMBER           ::= [0-9]+ ("." [0-9]+)?
  BOOLEAN          ::= "true" | "false"
  ```

  ## Example

  ```
  detection lateral_movement {
    name: "Lateral Movement via PsExec"
    description: "Detects PsExec-based lateral movement"
    severity: high
    mitre: ["T1021.002"]

    sequence within 5m {
      event e1: process_create {
        where: process.name = "psexec.exe" AND is_elevated = true
        capture: initiator_host, user
      }

      event e2: network_connect {
        where: dst_port = 445 AND src_host = e1.initiator_host
        capture: target_host
      }

      event e3: process_create {
        where: parent.name = "services.exe" AND host = e2.target_host
        capture: spawned_process
      }
    }

    aggregation {
      count(distinct e2.target_host) > 3 within 1h -> escalate to critical
      count(*) > 10 within 30m -> create_alert "Mass lateral movement detected"
    }
  }
  ```

  ## Field Reference Resolution

  - Event fields: `e1.process.name`, `e2.dst_port`
  - Captured values: `e1.initiator_host`
  - Built-in fields: `timestamp`, `agent_id`, `host`

  ## Temporal Constraints

  - `within 5s` - 5 seconds
  - `within 5m` - 5 minutes
  - `within 1h` - 1 hour
  - `within 1d` - 1 day

  ## ML Integration

  - `ml("model_name", field)` - Call ML model with field value
  - Returns: prediction score (0.0 - 1.0)

  ## Aggregation Functions

  - `count(field)` - Count occurrences
  - `count(distinct field)` - Count unique values
  - `sum(field)` - Sum numeric values
  - `avg(field)` - Average
  - `min(field)`, `max(field)` - Min/max
  - `stddev(field)` - Standard deviation
  - `percentile(field, N)` - Nth percentile
  - `z_score(field)` - Z-score (outlier detection)
  """

  @type token ::
          {:identifier, String.t()}
          | {:string, String.t()}
          | {:number, number()}
          | {:boolean, boolean()}
          | {:operator, String.t()}
          | {:keyword, String.t()}
          | {:symbol, String.t()}
          | {:duration, {number(), String.t()}}
          | {:regex, String.t()}
          | :eof

  @keywords ~w(
    detection sequence within event where capture aggregation
    escalate to create_alert execute ml
    count sum avg min max stddev percentile z_score distinct
    process_create network_connect file_write registry_write dns_query module_load any
    and or not in matches
    critical high medium low info
    true false
  )

  @operators ~w(= != > >= < <= contains startswith endswith)

  @symbols ["{", "}", "(", ")", "[", "]", ":", ",", ".", "->", "/"]

  def keywords, do: @keywords
  def operators, do: @operators
  def symbols, do: @symbols

  @doc """
  Returns the precedence for operators (higher = binds tighter).
  """
  def operator_precedence(op) do
    case op do
      "or" -> 1
      "and" -> 2
      "not" -> 3
      "=" -> 4
      "!=" -> 4
      ">" -> 4
      ">=" -> 4
      "<" -> 4
      "<=" -> 4
      "contains" -> 4
      "startswith" -> 4
      "endswith" -> 4
      "in" -> 4
      "matches" -> 4
      _ -> 0
    end
  end

  @doc """
  Returns supported event types.
  """
  def event_types do
    ~w(process_create network_connect file_write registry_write dns_query module_load any)
  end

  @doc """
  Returns supported aggregation functions.
  """
  def aggregation_functions do
    ~w(count sum avg min max stddev percentile z_score)
  end

  @doc """
  Returns supported severity levels.
  """
  def severity_levels do
    ~w(critical high medium low info)
  end

  @doc """
  Duration multipliers in seconds.
  """
  def duration_to_seconds(value, unit) do
    case unit do
      "s" -> value
      "m" -> value * 60
      "h" -> value * 3600
      "d" -> value * 86400
      _ -> value
    end
  end
end
