/*
    Tamandua EDR - Evasion Techniques Detection Rules
    Based on 2025-2026 evasion research findings.

    Detects:
    - BYOVD (Bring Your Own Vulnerable Driver) attacks
    - ETW tampering
    - AMSI bypass patterns
    - Direct syscall shellcode
    - Hardware breakpoint abuse
    - Kernel callback manipulation
*/

import "pe"

// ============================================================================
// BYOVD (Bring Your Own Vulnerable Driver) DETECTION
// ============================================================================

rule BYOVD_Embedded_Driver
{
    meta:
        description = "Detects embedded vulnerable drivers used for EDR evasion"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"
        reference = "Qilin/Warlock ransomware BYOVD attacks"

    strings:
        // Known vulnerable driver signatures
        $vuln1 = "rwdrv.sys" ascii wide nocase
        $vuln2 = "gdrv.sys" ascii wide nocase
        $vuln3 = "dbutil_2_3.sys" ascii wide nocase
        $vuln4 = "capcom.sys" ascii wide nocase
        $vuln5 = "asio.sys" ascii wide nocase
        $vuln6 = "driver7.sys" ascii wide nocase
        $vuln7 = "nvflash.sys" ascii wide nocase
        $vuln8 = "ene.sys" ascii wide nocase
        $vuln9 = "physmem.sys" ascii wide nocase
        $vuln10 = "RTCore64.sys" ascii wide nocase
        $vuln11 = "msimg32.dll" ascii wide nocase  // Qilin side-loading

        // Driver service installation
        $svc1 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ascii wide
        $svc2 = "NtLoadDriver" ascii
        $svc3 = "ZwLoadDriver" ascii

    condition:
        pe.is_pe and
        (any of ($vuln*) and any of ($svc*))
}

rule BYOVD_Physical_Memory_Access
{
    meta:
        description = "Detects tools that access physical memory via vulnerable drivers"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"

    strings:
        // Physical memory access patterns
        $phys1 = "\\Device\\PhysicalMemory" ascii wide
        $phys2 = "MmMapIoSpace" ascii
        $phys3 = "MmMapLockedPages" ascii
        $phys4 = "ZwMapViewOfSection" ascii

        // IOCTL patterns for vulnerable drivers
        $ioctl1 = "DeviceIoControl" ascii
        $ioctl2 = {B8 ?? ?? ?? 00 89 44 24}  // mov eax, IOCTL_CODE
        $ioctl3 = "WritePhysicalMemory" ascii nocase
        $ioctl4 = "ReadPhysicalMemory" ascii nocase

    condition:
        pe.is_pe and
        (2 of ($phys*) and any of ($ioctl*))
}

// ============================================================================
// ETW TAMPERING DETECTION
// ============================================================================

rule ETW_Patching_Shellcode
{
    meta:
        description = "Detects shellcode patterns used to patch ETW functions"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.006"

    strings:
        // EtwEventWrite patching patterns
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "ntdll.dll" ascii wide nocase
        $etw3 = "NtTraceEvent" ascii
        $etw4 = "EtwEventRegister" ascii

        // Patching patterns (ret, xor eax + ret, mov eax + ret)
        $patch1 = { C3 }                          // ret
        $patch2 = { 33 C0 C3 }                    // xor eax, eax; ret
        $patch3 = { 31 C0 C3 }                    // xor eax, eax; ret
        $patch4 = { B8 00 00 00 00 C3 }           // mov eax, 0; ret
        $patch5 = { 48 33 C0 C3 }                 // xor rax, rax; ret

        // VirtualProtect for making ETW writable
        $prot1 = "VirtualProtect" ascii
        $prot2 = "NtProtectVirtualMemory" ascii

    condition:
        (2 of ($etw*) and any of ($patch*) and any of ($prot*))
}

rule ETW_Provider_Tampering
{
    meta:
        description = "Detects ETW provider manipulation tools"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1562.006"

    strings:
        // ETW provider manipulation
        $api1 = "EventUnregister" ascii
        $api2 = "TraceSetInformation" ascii
        $api3 = "StopTrace" ascii wide
        $api4 = "ControlTrace" ascii wide

        // Registry paths for ETW providers
        $reg1 = "Control\\WMI\\Autologger" ascii wide
        $reg2 = "Microsoft-Windows-Threat-Intelligence" ascii wide
        $reg3 = "Microsoft-Windows-Kernel-Audit-API-Calls" ascii wide

    condition:
        pe.is_pe and
        (2 of ($api*) or any of ($reg*))
}

// ============================================================================
// AMSI BYPASS DETECTION
// ============================================================================

rule AMSI_Bypass_Patching
{
    meta:
        description = "Detects AMSI bypass via function patching"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1562.001"

    strings:
        // AMSI function targets
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "AmsiScanString" ascii
        $amsi3 = "AmsiInitialize" ascii
        $amsi4 = "amsi.dll" ascii wide nocase

        // Bypass indicators
        $bypass1 = "amsiInitFailed" ascii wide nocase
        $bypass2 = "AmsiContext" ascii wide
        $bypass3 = { B8 57 00 07 80 }  // mov eax, 0x80070057 (E_INVALIDARG)

        // PowerShell AMSI bypass strings
        $ps1 = "System.Management.Automation.AmsiUtils" ascii wide
        $ps2 = "amsiContext" ascii wide
        $ps3 = "[Ref].Assembly" ascii wide

    condition:
        (2 of ($amsi*) and any of ($bypass*)) or
        (2 of ($ps*))
}

// ============================================================================
// DIRECT SYSCALL DETECTION
// ============================================================================

rule Direct_Syscall_Shellcode
{
    meta:
        description = "Detects direct syscall patterns used to bypass API hooks"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1106"

    strings:
        // Syscall instruction patterns
        $syscall1 = { 0F 05 }                     // syscall
        $syscall2 = { 0F 34 }                     // sysenter
        $syscall3 = { CD 2E }                     // int 2E

        // SSN resolution patterns (reading syscall numbers from ntdll)
        $ssn1 = { B8 ?? ?? 00 00 }               // mov eax, SSN (syscall number)
        $ssn2 = { 4C 8B D1 B8 ?? ?? 00 00 }      // mov r10, rcx; mov eax, SSN

        // Known syscall resolution tools
        $tool1 = "GetSSN" ascii
        $tool2 = "syscall_" ascii
        $tool3 = "NtAllocateVirtualMemory" ascii

    condition:
        // Multiple syscall instructions with SSN patterns
        (#syscall1 > 3 or #syscall2 > 3) and
        (any of ($ssn*) or any of ($tool*))
}

rule SysWhispers_Pattern
{
    meta:
        description = "Detects SysWhispers and similar syscall evasion tools"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1106"

    strings:
        // SysWhispers signatures
        $sw1 = "SW2_" ascii
        $sw2 = "SW3_" ascii
        $sw3 = "SysWhispers" ascii
        $sw4 = "GetSyscallNumber" ascii

        // Acheron signatures
        $ach1 = "acheron" ascii nocase
        $ach2 = "AcheronSyscall" ascii

        // HellsGate signatures
        $hg1 = "HellsGate" ascii
        $hg2 = "HalosGate" ascii
        $hg3 = "TartarusGate" ascii

    condition:
        any of them
}

// ============================================================================
// HARDWARE BREAKPOINT ABUSE
// ============================================================================

rule Hardware_Breakpoint_Abuse
{
    meta:
        description = "Detects hardware breakpoint abuse for EDR evasion"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1562.001"

    strings:
        // VEH registration
        $veh1 = "AddVectoredExceptionHandler" ascii
        $veh2 = "RemoveVectoredExceptionHandler" ascii
        $veh3 = "RtlAddVectoredExceptionHandler" ascii

        // Context manipulation
        $ctx1 = "SetThreadContext" ascii
        $ctx2 = "GetThreadContext" ascii
        $ctx3 = "NtSetContextThread" ascii
        $ctx4 = "NtGetContextThread" ascii
        $ctx5 = "NtContinue" ascii  // Bypass for SetThreadContext logging

        // Debug register references
        $dr1 = "Dr0" ascii wide
        $dr2 = "Dr1" ascii wide
        $dr3 = "Dr2" ascii wide
        $dr4 = "Dr3" ascii wide
        $dr5 = "Dr7" ascii wide
        $dr6 = "ContextFlags" ascii wide

    condition:
        pe.is_pe and
        (any of ($veh*) and any of ($ctx*) and any of ($dr*))
}

rule Blindside_Technique
{
    meta:
        description = "Detects Blindside EDR evasion technique using hardware breakpoints"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"
        reference = "Cymulate Blindside research"

    strings:
        // Blindside-specific patterns
        $blind1 = "Blindside" ascii nocase
        $blind2 = "HardwareBreakpoint" ascii
        $blind3 = "EXCEPTION_SINGLE_STEP" ascii wide

        // Exception handler patterns for breakpoint handling
        $exc1 = { 48 8B 41 ?? 48 89 81 ?? 00 00 00 }  // Context register manipulation
        $exc2 = "STATUS_SINGLE_STEP" ascii wide
        $exc3 = { 81 38 04 00 00 80 }  // cmp [rax], 0x80000004 (STATUS_SINGLE_STEP)

    condition:
        any of ($blind*) or
        (2 of ($exc*))
}

// ============================================================================
// KERNEL CALLBACK MANIPULATION
// ============================================================================

rule Kernel_Callback_Removal
{
    meta:
        description = "Detects tools that manipulate kernel callbacks (EDR killers)"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"
        reference = "Qilin EDR killer"

    strings:
        // Callback manipulation functions
        $cb1 = "PsSetCreateProcessNotifyRoutine" ascii
        $cb2 = "PsSetCreateThreadNotifyRoutine" ascii
        $cb3 = "PsSetLoadImageNotifyRoutine" ascii
        $cb4 = "CmRegisterCallback" ascii
        $cb5 = "ObRegisterCallbacks" ascii
        $cb6 = "FltRegisterFilter" ascii

        // Callback removal patterns
        $remove1 = "RemoveCallback" ascii nocase
        $remove2 = "UnregisterCallback" ascii nocase
        $remove3 = "DisableCallback" ascii nocase

        // EDR driver names (Qilin's target list)
        $edr1 = "SentinelAgent" ascii wide nocase
        $edr2 = "CrowdStrike" ascii wide nocase
        $edr3 = "CylanceProtect" ascii wide nocase
        $edr4 = "Sophos" ascii wide nocase
        $edr5 = "Symantec" ascii wide nocase
        $edr6 = "MsMpEng" ascii wide nocase
        $edr7 = "csagent" ascii wide nocase
        $edr8 = "aswSP" ascii wide nocase

    condition:
        pe.is_pe and
        ((2 of ($cb*) and any of ($remove*)) or
         (3 of ($edr*) and any of ($cb*)))
}

// ============================================================================
// MODULE STOMPING DETECTION
// ============================================================================

rule Module_Stomping_Pattern
{
    meta:
        description = "Detects module stomping shellcode injection technique"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1055.001"

    strings:
        // DLL loading for stomping
        $load1 = "LoadLibraryA" ascii
        $load2 = "LoadLibraryW" ascii
        $load3 = "LoadLibraryExW" ascii

        // Memory manipulation for stomping
        $mem1 = "WriteProcessMemory" ascii
        $mem2 = "NtWriteVirtualMemory" ascii
        $mem3 = "VirtualProtectEx" ascii

        // Entry point modification
        $entry1 = "AddressOfEntryPoint" ascii
        $entry2 = { 3C 00 }  // PE header offset to entry point

        // Common stomp targets
        $target1 = "ntdll.dll" ascii wide nocase
        $target2 = "kernel32.dll" ascii wide nocase
        $target3 = "user32.dll" ascii wide nocase

    condition:
        pe.is_pe and
        (any of ($load*) and any of ($mem*) and any of ($entry*)) or
        (2 of ($target*) and 2 of ($mem*))
}

// ============================================================================
// INDIRECT SYSCALL DETECTION
// ============================================================================

rule Indirect_Syscall_Pattern
{
    meta:
        description = "Detects indirect syscall technique (jumping to syscall in ntdll)"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1106"

    strings:
        // Scanning for syscall instruction in ntdll
        $scan1 = { 0F B7 ?? ?? 83 ?? 05 }  // movzx + cmp for finding 0x050F
        $scan2 = { 66 81 ?? 05 0F }        // cmp word, 0x0F05

        // Jump gadget patterns
        $jmp1 = { FF E0 }                  // jmp rax
        $jmp2 = { FF E1 }                  // jmp rcx
        $jmp3 = { FF 25 }                  // jmp [rip+...]
        $jmp4 = { 41 FF E3 }               // jmp r11

        // GetProcAddress for resolving syscall location
        $resolve1 = "GetProcAddress" ascii
        $resolve2 = "LdrGetProcedureAddress" ascii

    condition:
        (any of ($scan*) and any of ($jmp*)) or
        (any of ($resolve*) and #jmp1 > 5)
}

// ============================================================================
// PROCESS HOLLOWING / DOPPELGANGING
// ============================================================================

rule Process_Hollowing_Pattern
{
    meta:
        description = "Detects process hollowing technique"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1055.012"

    strings:
        // Process creation in suspended state
        $create1 = "CreateProcessA" ascii
        $create2 = "CreateProcessW" ascii
        $create3 = "NtCreateProcess" ascii
        $create4 = "CREATE_SUSPENDED" ascii wide

        // Memory unmapping
        $unmap1 = "NtUnmapViewOfSection" ascii
        $unmap2 = "ZwUnmapViewOfSection" ascii

        // Context manipulation
        $ctx1 = "SetThreadContext" ascii
        $ctx2 = "NtSetContextThread" ascii
        $ctx3 = "ResumeThread" ascii
        $ctx4 = "NtResumeThread" ascii

        // Memory allocation in target
        $alloc1 = "VirtualAllocEx" ascii
        $alloc2 = "NtAllocateVirtualMemory" ascii

    condition:
        pe.is_pe and
        (any of ($create*) and any of ($unmap*) and any of ($ctx*)) or
        (2 of ($create*) and 2 of ($alloc*) and any of ($ctx*))
}

rule Process_Doppelganging
{
    meta:
        description = "Detects process doppelganging technique"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1055.013"

    strings:
        // Transaction APIs
        $tx1 = "NtCreateTransaction" ascii
        $tx2 = "RtlSetCurrentTransaction" ascii
        $tx3 = "NtRollbackTransaction" ascii
        $tx4 = "NtCreateSection" ascii

        // Process creation from section
        $proc1 = "NtCreateProcessEx" ascii
        $proc2 = "NtCreateThreadEx" ascii

    condition:
        pe.is_pe and
        (2 of ($tx*) and any of ($proc*))
}
