/*
    Tamandua EDR - Indirect Syscall Detection Rules
    Detects SysWhispers, Hell's Gate, Halo's Gate, and related patterns

    These rules identify techniques used to bypass EDR hooks by:
    - Direct syscall execution outside ntdll.dll
    - Dynamic syscall number resolution
    - Jumping to ntdll syscall stubs from shellcode

    References:
    - https://github.com/jthuraisamy/SysWhispers
    - https://github.com/jthuraisamy/SysWhispers2
    - https://github.com/klezVirus/SysWhispers3
    - https://vxug.fakedomain.pg/papers/VXUG/Exclusive/HellsGate.pdf
*/

rule SysWhispers_Indirect_Syscall
{
    meta:
        description = "Detects SysWhispers indirect syscall patterns"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "high"
        reference = "SysWhispers EDR bypass technique"

    strings:
        // mov r10, rcx - standard syscall setup
        $mov_r10_rcx = { 4C 8B D1 }

        // syscall instruction
        $syscall = { 0F 05 }

        // JMP indirect pattern (JMP [rip+disp])
        $jmp_indirect = { FF 25 }

        // mov eax, imm32 (syscall number)
        $mov_eax_ssn = { B8 ?? ?? 00 00 }

    condition:
        $mov_r10_rcx and ($syscall or $jmp_indirect) and $mov_eax_ssn
}

rule SysWhispers2_Direct_Syscall_Stub
{
    meta:
        description = "Detects SysWhispers2 direct syscall stub pattern"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "critical"
        reference = "SysWhispers2 full syscall stub outside ntdll"

    strings:
        // Full SysWhispers2 stub:
        // mov r10, rcx
        // mov eax, <SSN>
        // syscall
        // ret
        $stub_full = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }

        // Alternative with test byte (Windows 10+)
        // mov r10, rcx
        // mov eax, <SSN>
        // test byte ptr [SharedUserData], 1
        $stub_win10 = { 4C 8B D1 B8 ?? ?? 00 00 F6 04 25 08 03 FE 7F 01 }

    condition:
        any of them
}

rule SysWhispers3_Indirect_Jump
{
    meta:
        description = "Detects SysWhispers3 indirect jump to syscall stub"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "high"
        reference = "SysWhispers3 JMP to ntdll syscall instruction"

    strings:
        // mov r10, rcx
        $setup = { 4C 8B D1 }

        // mov eax, <SSN>
        $ssn = { B8 ?? ?? 00 00 }

        // JMP rel32 (E9)
        $jmp_rel32 = { E9 ?? ?? ?? ?? }

        // JMP [rip+disp32]
        $jmp_rip = { FF 25 ?? ?? ?? ?? }

    condition:
        $setup and $ssn and ($jmp_rel32 or $jmp_rip)
}

rule HellsGate_Syscall_Resolution
{
    meta:
        description = "Detects Hell's Gate dynamic syscall number resolution"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "critical"
        reference = "Hell's Gate PEB walking for syscall resolution"

    strings:
        // PEB access via GS segment (x64)
        // mov rax, gs:[0x60]
        $peb_access_1 = { 65 48 8B 04 25 60 00 00 00 }
        $peb_access_2 = { 65 48 8B 0C 25 60 00 00 00 }
        $peb_access_3 = { 65 4C 8B 04 25 60 00 00 00 }

        // mov r10, rcx (syscall setup)
        $mov_r10_rcx = { 4C 8B D1 }

        // cmp byte ptr [...], 0xB8 (checking for mov eax opcode)
        $cmp_b8_1 = { 80 38 B8 }
        $cmp_b8_2 = { 80 78 ?? B8 }
        $cmp_b8_3 = { 80 3? B8 }

        // syscall instruction
        $syscall = { 0F 05 }

    condition:
        any of ($peb_access*) and $mov_r10_rcx and (any of ($cmp_b8*) or $syscall)
}

rule HalosGate_Clean_Syscall
{
    meta:
        description = "Detects Halo's Gate clean syscall technique"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "critical"
        reference = "Halo's Gate walking neighboring syscalls for clean numbers"

    strings:
        // Pattern: Read syscall stub at [func+0] and check for mov eax
        // cmp byte ptr [reg], 0x4C (looking for mov r10, rcx)
        $check_4c = { 80 3? 4C }

        // cmp byte ptr [reg+1], 0x8B
        $check_8b = { 80 7? 01 8B }

        // Walking exports - GetProcAddress pattern
        $get_proc = "GetProcAddress" ascii

        // LdrGetProcedureAddress
        $ldr_get = "LdrGetProcedureAddress" ascii

        // mov r10, rcx + mov eax, imm32
        $syscall_setup = { 4C 8B D1 B8 ?? ?? 00 00 }

        // add/sub to walk neighboring functions
        $walk_add = { 83 ?? 20 }
        $walk_sub = { 83 ?? 20 }

    condition:
        ($check_4c or $check_8b) and $syscall_setup or
        (($get_proc or $ldr_get) and $syscall_setup and ($walk_add or $walk_sub))
}

rule TartarusGate_MultiNtdll
{
    meta:
        description = "Detects Tartarus Gate multiple ntdll technique"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "critical"
        reference = "Loading clean ntdll from disk to bypass hooks"

    strings:
        // Loading ntdll from disk
        $ntdll_path_1 = "\\SystemRoot\\System32\\ntdll.dll" wide ascii
        $ntdll_path_2 = "C:\\Windows\\System32\\ntdll.dll" wide ascii nocase
        $ntdll_path_3 = "\\??\\C:\\Windows\\System32\\ntdll.dll" wide ascii

        // Mapping section
        $map_section = "NtMapViewOfSection" ascii
        $create_section = "NtCreateSection" ascii

        // Reading file
        $read_file = "NtReadFile" ascii
        $create_file = "NtCreateFile" ascii

        // Syscall stub after loading
        $syscall_stub = { 4C 8B D1 B8 ?? ?? 00 00 }

        // .text section reference
        $text_section = ".text" ascii

    condition:
        any of ($ntdll_path*) and
        (($map_section and $create_section) or ($read_file and $create_file)) and
        $syscall_stub
}

rule FreshyCalls_Syscall_Sorting
{
    meta:
        description = "Detects FreshyCalls syscall number sorting technique"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "high"
        reference = "FreshyCalls sorting Zw* functions to derive syscall numbers"

    strings:
        // Zw function prefixes (used for sorting)
        $zw_prefix = "Zw" ascii

        // Sorting/comparing function names
        $strcmp = "strcmp" ascii
        $wcsicmp = "_wcsicmp" ascii

        // Syscall setup
        $syscall_stub = { 4C 8B D1 B8 ?? ?? 00 00 }

        // Export enumeration
        $export_dir = { 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }

    condition:
        $zw_prefix and ($strcmp or $wcsicmp) and $syscall_stub
}

rule RecycledGate_Trampoline
{
    meta:
        description = "Detects RecycledGate trampoline technique"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "high"
        reference = "Using existing syscall instructions in ntdll as trampolines"

    strings:
        // Pattern: CALL to syscall instruction in ntdll
        // Call rel32
        $call_rel32 = { E8 ?? ?? ?? ?? }

        // mov r10, rcx before call
        $setup_call = { 4C 8B D1 B8 ?? ?? 00 00 E8 }

        // JMP to syscall instruction (0F 05)
        $jmp_to_syscall = { E9 ?? ?? ?? ?? }

        // push return address + jmp pattern
        $push_jmp = { 68 ?? ?? ?? ?? E9 }

    condition:
        ($setup_call or ($call_rel32 and $jmp_to_syscall)) or $push_jmp
}

rule Generic_Syscall_Evasion
{
    meta:
        description = "Generic detection of syscall-based EDR evasion"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "medium"
        reference = "Generic patterns common to syscall evasion"

    strings:
        // Multiple Nt/Zw function resolutions
        $nt_func_1 = "NtAllocateVirtualMemory" ascii
        $nt_func_2 = "NtProtectVirtualMemory" ascii
        $nt_func_3 = "NtWriteVirtualMemory" ascii
        $nt_func_4 = "NtCreateThreadEx" ascii
        $nt_func_5 = "NtQueueApcThread" ascii

        // Syscall instruction
        $syscall = { 0F 05 }

        // Int 2E (legacy syscall)
        $int_2e = { CD 2E }

        // Sysenter (x86)
        $sysenter = { 0F 34 }

        // mov r10, rcx
        $mov_r10 = { 4C 8B D1 }

    condition:
        3 of ($nt_func*) and ($syscall or $int_2e or $sysenter) and $mov_r10
}

rule Shellcode_Syscall_Stub
{
    meta:
        description = "Detects syscall stub embedded in shellcode"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "critical"
        reference = "Syscall stubs commonly found in shellcode"

    strings:
        // Common shellcode syscall patterns
        // NtAllocateVirtualMemory syscall stub
        $alloc_stub = { 4C 8B D1 B8 18 00 00 00 0F 05 C3 }

        // NtProtectVirtualMemory syscall stub
        $protect_stub = { 4C 8B D1 B8 50 00 00 00 0F 05 C3 }

        // NtWriteVirtualMemory syscall stub
        $write_stub = { 4C 8B D1 B8 3A 00 00 00 0F 05 C3 }

        // NtCreateThreadEx syscall stub
        $thread_stub = { 4C 8B D1 B8 C2 00 00 00 0F 05 C3 }

        // Generic pattern with any SSN
        $generic_stub = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }

    condition:
        2 of them or
        (#generic_stub > 3)  // Multiple syscall stubs
}

rule KUSER_SHARED_DATA_Syscall
{
    meta:
        description = "Detects Windows 10+ syscall stub with KUSER_SHARED_DATA check"
        author = "Tamandua Security Team"
        mitre = "T1106"
        severity = "high"
        reference = "Modern Windows syscall stub pattern"

    strings:
        // test byte ptr [0x7FFE0308], 1 (KUSER_SHARED_DATA.SystemCall)
        $kuser_check = { F6 04 25 08 03 FE 7F 01 }

        // Full modern syscall stub
        // mov r10, rcx
        // mov eax, <SSN>
        // test byte ptr [0x7FFE0308], 1
        // jne +3
        // syscall
        // ret
        // int 2E
        // ret
        $full_stub = { 4C 8B D1 B8 ?? ?? 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 CD 2E C3 }

    condition:
        any of them
}
