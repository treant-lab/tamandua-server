defmodule TamanduaServer.Repo.Migrations.AddEtwTamperingFields do
  @moduledoc """
  Adds ETW tampering detection fields to the alerts table.

  These fields capture detailed information about ETW (Event Tracing for Windows)
  tampering attempts detected by the agent, including:
  - Target function that was patched (e.g., NtTraceEvent, EtwEventWrite)
  - Original prologue bytes before patching
  - Patched bytes found during detection
  - Patch pattern classification (ret, xor_eax_ret, jmp_rel32, etc.)
  - Target memory region (syscall_stub, etw_function, ntdll_text)

  MITRE ATT&CK: T1562.006 - Impair Defenses: Indicator Blocking
  """
  use Ecto.Migration

  def change do
    alter table(:alerts) do
      # Target function name (e.g., "NtTraceEvent", "EtwEventWrite", "EtwEventWriteFull")
      add :target_function, :string

      # Original bytes from the function prologue before patching
      add :original_bytes, :binary

      # Patched bytes found during detection
      add :patched_bytes, :binary

      # Classification of the patch pattern:
      # - "ret" - Simple return (0xC3)
      # - "xor_eax_ret" - XOR EAX, EAX; RET (0x31 0xC0 0xC3)
      # - "jmp_rel32" - Relative jump (0xE9 XX XX XX XX)
      # - "jmp_abs" - Absolute jump via register
      # - "nop_sled" - NOP slide followed by return
      # - "int3_trap" - Breakpoint trap
      # - "ud2" - Undefined instruction
      # - "unknown" - Unclassified pattern
      add :patch_pattern, :string

      # Target memory region where tampering was detected:
      # - "syscall_stub" - ntdll syscall stub
      # - "etw_function" - ETW-related function
      # - "ntdll_text" - ntdll .text section
      # - "kernel32_text" - kernel32 .text section
      # - "amsi_function" - AMSI-related function
      # - "other" - Other memory region
      add :target_region, :string
    end

    # Index for filtering alerts by ETW tampering details
    create index(:alerts, [:target_function])
    create index(:alerts, [:patch_pattern])
    create index(:alerts, [:target_region])

    # Composite index for common ETW tampering queries
    create index(:alerts, [:target_function, :patch_pattern])
  end
end
