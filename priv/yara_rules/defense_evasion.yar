/*
    Tamandua EDR - Defense Evasion Detection Rules
    These rules detect obfuscation and evasion techniques.
*/

rule Evasion_Process_Injection
{
    meta:
        description = "Detects common process injection techniques"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1055"

    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "RtlCreateUserThread" ascii
        $api6 = "QueueUserAPC" ascii
        $api7 = "SetThreadContext" ascii
        $api8 = "NtQueueApcThread" ascii
        $api9 = "NtMapViewOfSection" ascii
        $api10 = "NtUnmapViewOfSection" ascii

    condition:
        ($api1 and $api2 and ($api3 or $api4 or $api5 or $api6)) or
        ($api7 and $api2) or
        ($api9 and $api10)
}

rule Evasion_Process_Hollowing
{
    meta:
        description = "Detects process hollowing technique"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1055.012"

    strings:
        $api1 = "CreateProcess" ascii
        $api2 = "CREATE_SUSPENDED" ascii wide
        $api3 = "NtUnmapViewOfSection" ascii
        $api4 = "ZwUnmapViewOfSection" ascii
        $api5 = "VirtualAllocEx" ascii
        $api6 = "WriteProcessMemory" ascii
        $api7 = "SetThreadContext" ascii
        $api8 = "ResumeThread" ascii
        $api9 = "NtResumeThread" ascii

    condition:
        $api1 and $api2 and ($api3 or $api4) and $api5 and $api6 and ($api7 or $api8 or $api9)
}

rule Evasion_DLL_Injection_LoadLibrary
{
    meta:
        description = "Detects DLL injection via LoadLibrary"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1055.001"

    strings:
        $api1 = "OpenProcess" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "GetProcAddress" ascii
        $api5 = "LoadLibraryA" ascii
        $api6 = "LoadLibraryW" ascii
        $api7 = "CreateRemoteThread" ascii

    condition:
        $api1 and $api2 and $api3 and $api4 and ($api5 or $api6) and $api7
}

rule Evasion_AMSI_Bypass
{
    meta:
        description = "Detects AMSI bypass attempts"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"

    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide
        $amsi2 = "AmsiInitialize" ascii wide
        $amsi3 = "amsi.dll" ascii wide nocase
        $amsi4 = "AmsiOpenSession" ascii wide
        $amsi5 = "AmsiCloseSession" ascii wide

        $bypass1 = "amsiContext" ascii wide
        $bypass2 = "amsiSession" ascii wide
        $bypass3 = { B8 57 00 07 80 C3 }
        $bypass4 = "SetProtection" ascii
        $bypass5 = "VirtualProtect" ascii

        $ps1 = "[Ref].Assembly.GetType(" ascii wide
        $ps2 = "System.Management.Automation.AmsiUtils" ascii wide
        $ps3 = "amsiInitFailed" ascii wide

    condition:
        (any of ($amsi*) and any of ($bypass*)) or (2 of ($ps*))
}

rule Evasion_ETW_Bypass
{
    meta:
        description = "Detects ETW bypass attempts"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"

    strings:
        $etw1 = "EtwEventWrite" ascii
        $etw2 = "NtTraceEvent" ascii
        $etw3 = "EtwEventRegister" ascii
        $etw4 = "EtwNotificationRegister" ascii

        $patch1 = { C2 14 00 }
        $patch2 = { C3 }
        $patch3 = "VirtualProtect" ascii

        $ntdll1 = "ntdll.dll" ascii wide nocase

    condition:
        (any of ($etw*) and any of ($patch*) and $ntdll1)
}

rule Evasion_API_Unhooking
{
    meta:
        description = "Detects API unhooking/EDR evasion"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"

    strings:
        $api1 = "NtProtectVirtualMemory" ascii
        $api2 = "NtWriteVirtualMemory" ascii
        $api3 = "NtReadVirtualMemory" ascii

        $unhook1 = "ntdll.dll" ascii wide
        $unhook2 = ".text" ascii
        $unhook3 = "GetModuleHandle" ascii
        $unhook4 = "GetProcAddress" ascii
        $unhook5 = "ReadFile" ascii
        $unhook6 = "MapViewOfFile" ascii

        $syscall1 = { 0F 05 C3 }
        $syscall2 = "syscall" ascii

    condition:
        (2 of ($api*) and 3 of ($unhook*)) or (any of ($api*) and any of ($syscall*))
}

rule Evasion_Direct_Syscall
{
    meta:
        description = "Detects direct syscall usage to bypass hooks"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1106"

    strings:
        $syscall_x64 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        $syscall_x86 = { B8 ?? ?? 00 00 8D 54 24 04 CD 2E C3 }

        $nt1 = "NtAllocateVirtualMemory" ascii
        $nt2 = "NtProtectVirtualMemory" ascii
        $nt3 = "NtWriteVirtualMemory" ascii
        $nt4 = "NtCreateThreadEx" ascii
        $nt5 = "NtQueueApcThread" ascii
        $nt6 = "NtOpenProcess" ascii

    condition:
        (any of ($syscall*) and 2 of ($nt*))
}

rule Evasion_Parent_PID_Spoofing
{
    meta:
        description = "Detects parent PID spoofing"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1134.004"

    strings:
        $api1 = "UpdateProcThreadAttribute" ascii
        $api2 = "InitializeProcThreadAttributeList" ascii
        $api3 = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" ascii wide
        $api4 = { 00 00 02 00 01 00 }

    condition:
        ($api1 and $api2) or $api3 or $api4
}

rule Evasion_Token_Manipulation
{
    meta:
        description = "Detects token manipulation for privilege escalation"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1134"

    strings:
        $api1 = "ImpersonateLoggedOnUser" ascii
        $api2 = "SetThreadToken" ascii
        $api3 = "DuplicateTokenEx" ascii
        $api4 = "AdjustTokenPrivileges" ascii
        $api5 = "CreateProcessWithToken" ascii
        $api6 = "CreateProcessAsUser" ascii
        $api7 = "NtSetInformationToken" ascii

        $priv1 = "SeDebugPrivilege" ascii wide
        $priv2 = "SeTcbPrivilege" ascii wide
        $priv3 = "SeImpersonatePrivilege" ascii wide
        $priv4 = "SeAssignPrimaryTokenPrivilege" ascii wide

    condition:
        (3 of ($api*)) or (1 of ($api*) and 2 of ($priv*))
}

rule Evasion_Reflective_DLL
{
    meta:
        description = "Detects reflective DLL loading"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1620"

    strings:
        $ref1 = "ReflectiveLoader" ascii wide
        $ref2 = "ReflectiveDLL" ascii wide
        $ref3 = "_RDI" ascii
        $ref4 = "reflective" ascii wide nocase

        $pe1 = { 4D 5A }
        $pe2 = "This program cannot be run in DOS mode" ascii

        $code1 = { 8B 45 3C 89 45 }
        $code2 = { 48 8B 41 3C }

    condition:
        (any of ($ref*)) or (all of ($pe*) and any of ($code*))
}

rule Evasion_String_Obfuscation
{
    meta:
        description = "Detects common string obfuscation techniques"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1027"

    strings:
        $xor1 = { 80 30 ?? 40 }
        $xor2 = { 80 34 ?? ?? 40 }
        $xor3 = { 32 ?? ?? 88 }

        $base64_1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
        $base64_2 = "FromBase64String" ascii
        $base64_3 = "ToBase64String" ascii

        $stack1 = { C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? }

    condition:
        (2 of ($xor*)) or (2 of ($base64*)) or $stack1
}

rule Evasion_Timestomping
{
    meta:
        description = "Detects file timestamp manipulation"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1070.006"

    strings:
        $api1 = "SetFileTime" ascii
        $api2 = "NtSetInformationFile" ascii
        $api3 = "ZwSetInformationFile" ascii
        $api4 = "touch -t" ascii wide
        $api5 = "timestomp" ascii wide nocase

    condition:
        any of them
}

rule Evasion_UAC_Bypass
{
    meta:
        description = "Detects UAC bypass techniques"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1548.002"

    strings:
        $fodhelper = "fodhelper.exe" ascii wide nocase
        $eventvwr = "eventvwr.exe" ascii wide nocase
        $computerdefaults = "computerdefaults.exe" ascii wide nocase
        $sdclt = "sdclt.exe" ascii wide nocase
        $slui = "slui.exe" ascii wide nocase

        $reg1 = "ms-settings\\shell\\open\\command" ascii wide
        $reg2 = "mscfile\\shell\\open\\command" ascii wide
        $reg3 = "Software\\Classes\\exefile\\shell" ascii wide

        $com1 = "CMSTPLUA" ascii wide
        $com2 = "ICMLuaUtil" ascii wide

    condition:
        (any of ($fodhelper, $eventvwr, $computerdefaults, $sdclt, $slui) and any of ($reg*)) or (all of ($com*))
}
