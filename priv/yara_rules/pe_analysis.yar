/*
    Tamandua EDR - PE Analysis Rules
    Advanced detection using PE module for structural analysis.

    These rules detect malware based on PE characteristics rather than
    just string patterns, making them more resilient to obfuscation.
*/

import "pe"
import "math"

// ============================================================================
// SUSPICIOUS PE CHARACTERISTICS
// ============================================================================

rule PE_Suspicious_Section_Names
{
    meta:
        description = "Detects executables with suspicious section names indicating packing or obfuscation"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1027"

    condition:
        pe.number_of_sections > 0 and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".upx0" or
            pe.sections[i].name == ".upx1" or
            pe.sections[i].name == ".aspack" or
            pe.sections[i].name == ".adata" or
            pe.sections[i].name == ".vmp0" or
            pe.sections[i].name == ".vmp1" or
            pe.sections[i].name == ".themida" or
            pe.sections[i].name == ".enigma" or
            pe.sections[i].name == ".petite" or
            pe.sections[i].name == ".nsp0" or
            pe.sections[i].name == ".nsp1"
        )
}

rule PE_High_Entropy_Section
{
    meta:
        description = "Detects PE with high entropy sections indicating encryption or packing"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1027.002"

    condition:
        pe.number_of_sections > 0 and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].raw_data_size > 1024 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.5
        )
}

rule PE_Executable_In_Resource
{
    meta:
        description = "Detects PE files embedded in resources (dropper behavior)"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1027.009"

    condition:
        pe.number_of_resources > 0 and
        for any i in (0..pe.number_of_resources - 1): (
            pe.resources[i].length > 4096 and
            uint16(pe.resources[i].offset) == 0x5A4D  // MZ header
        )
}

rule PE_No_Import_Table
{
    meta:
        description = "Detects PE with no import table (likely packed or shellcode loader)"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1027.002"

    condition:
        pe.number_of_imports == 0 and
        pe.number_of_sections > 0 and
        filesize > 4096
}

rule PE_Suspicious_Timestamp
{
    meta:
        description = "Detects PE with suspicious compilation timestamp (future or very old)"
        author = "Tamandua Security Team"
        severity = "low"
        mitre_attack = "T1070.006"

    condition:
        pe.timestamp < 946684800 or  // Before 2000
        pe.timestamp > 1893456000     // After 2030
}

// ============================================================================
// CREDENTIAL THEFT - PE ANALYSIS
// ============================================================================

rule PE_LSASS_Access_Imports
{
    meta:
        description = "Detects PE importing APIs used for LSASS memory access"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1003.001"

    condition:
        pe.imports("dbghelp.dll", "MiniDumpWriteDump") or
        pe.imports("dbgcore.dll", "MiniDumpWriteDump") or
        (
            pe.imports("kernel32.dll", "OpenProcess") and
            pe.imports("kernel32.dll", "ReadProcessMemory") and
            (
                pe.imports("kernel32.dll", "VirtualQueryEx") or
                pe.imports("ntdll.dll", "NtQueryVirtualMemory")
            )
        )
}

rule PE_Credential_Dump_Imports
{
    meta:
        description = "Detects PE with import pattern consistent with credential dumping"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1003"

    strings:
        $s1 = "lsass" ascii wide nocase
        $s2 = "sekurlsa" ascii wide
        $s3 = "wdigest" ascii wide
        $s4 = "kerberos" ascii wide

    condition:
        pe.imports("advapi32.dll", "LsaOpenPolicy") and
        pe.imports("advapi32.dll", "LsaQueryInformationPolicy") and
        any of ($s*)
}

rule PE_SAM_Registry_Access
{
    meta:
        description = "Detects PE importing APIs for SAM registry access"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1003.002"

    strings:
        $sam = "SAM" ascii wide
        $system = "SYSTEM" ascii wide
        $security = "SECURITY" ascii wide

    condition:
        pe.imports("advapi32.dll", "RegSaveKeyExW") or
        pe.imports("advapi32.dll", "RegSaveKeyExA") or
        (
            pe.imports("advapi32.dll", "RegOpenKeyExW") and
            2 of ($sam, $system, $security)
        )
}

// ============================================================================
// RANSOMWARE - PE ANALYSIS
// ============================================================================

rule PE_Ransomware_Crypto_Imports
{
    meta:
        description = "Detects PE with crypto API imports typical of ransomware"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1486"

    condition:
        // Windows CryptoAPI pattern
        (
            pe.imports("advapi32.dll", "CryptAcquireContextW") and
            pe.imports("advapi32.dll", "CryptGenRandom") and
            pe.imports("advapi32.dll", "CryptEncrypt")
        ) or
        // CNG pattern
        (
            pe.imports("bcrypt.dll", "BCryptOpenAlgorithmProvider") and
            pe.imports("bcrypt.dll", "BCryptGenerateSymmetricKey") and
            pe.imports("bcrypt.dll", "BCryptEncrypt")
        )
}

rule PE_Ransomware_File_Enumeration
{
    meta:
        description = "Detects PE combining file enumeration with crypto (ransomware pattern)"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1486"

    strings:
        $ext1 = ".doc" ascii wide
        $ext2 = ".docx" ascii wide
        $ext3 = ".xls" ascii wide
        $ext4 = ".xlsx" ascii wide
        $ext5 = ".pdf" ascii wide
        $ext6 = ".jpg" ascii wide
        $ext7 = ".png" ascii wide
        $ext8 = ".sql" ascii wide
        $ext9 = ".mdb" ascii wide
        $ext10 = ".zip" ascii wide

    condition:
        pe.imports("kernel32.dll", "FindFirstFileW") and
        pe.imports("kernel32.dll", "FindNextFileW") and
        (
            pe.imports("advapi32.dll", "CryptEncrypt") or
            pe.imports("bcrypt.dll", "BCryptEncrypt")
        ) and
        5 of ($ext*)
}

rule PE_Shadow_Copy_Deletion
{
    meta:
        description = "Detects PE with VSS deletion capability (ransomware behavior)"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1490"

    strings:
        $vss1 = "vssadmin" ascii wide nocase
        $vss2 = "delete shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy" ascii wide nocase
        $vss4 = "bcdedit" ascii wide nocase
        $vss5 = "Win32_ShadowCopy" ascii wide

    condition:
        pe.imports("kernel32.dll", "CreateProcessW") and
        pe.imports("shell32.dll", "ShellExecuteW") and
        2 of ($vss*)
}

// ============================================================================
// LATERAL MOVEMENT - PE ANALYSIS
// ============================================================================

rule PE_PsExec_Like
{
    meta:
        description = "Detects PE with PsExec-like remote execution capabilities"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1021.002"

    condition:
        pe.imports("advapi32.dll", "OpenSCManagerW") and
        pe.imports("advapi32.dll", "CreateServiceW") and
        pe.imports("advapi32.dll", "StartServiceW") and
        pe.imports("netapi32.dll", "NetUseAdd")
}

rule PE_WMI_Execution
{
    meta:
        description = "Detects PE using WMI for remote execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1047"

    strings:
        $wmi1 = "Win32_Process" ascii wide
        $wmi2 = "Win32_ProcessStartup" ascii wide
        $wmi3 = "root\\cimv2" ascii wide

    condition:
        pe.imports("ole32.dll", "CoInitializeEx") and
        pe.imports("ole32.dll", "CoCreateInstance") and
        2 of ($wmi*)
}

// ============================================================================
// DEFENSE EVASION - PE ANALYSIS
// ============================================================================

rule PE_Process_Injection_Imports
{
    meta:
        description = "Detects PE with classic process injection API pattern"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1055"

    condition:
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("ntdll.dll", "NtCreateThreadEx") or
            pe.imports("ntdll.dll", "RtlCreateUserThread")
        )
}

rule PE_APC_Injection
{
    meta:
        description = "Detects PE with APC injection capabilities"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1055.004"

    condition:
        pe.imports("kernel32.dll", "OpenThread") and
        pe.imports("kernel32.dll", "QueueUserAPC") and
        pe.imports("kernel32.dll", "VirtualAllocEx")
}

rule PE_Unhooking_Pattern
{
    meta:
        description = "Detects PE attempting to unhook EDR/AV by remapping ntdll"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1562.001"

    strings:
        $ntdll = "ntdll.dll" ascii wide nocase
        $kernel = "\\KnownDlls\\ntdll.dll" ascii wide

    condition:
        pe.imports("kernel32.dll", "CreateFileMappingW") and
        pe.imports("kernel32.dll", "MapViewOfFile") and
        pe.imports("ntdll.dll", "NtProtectVirtualMemory") and
        any of ($ntdll, $kernel)
}

rule PE_AMSI_Bypass_Pattern
{
    meta:
        description = "Detects PE attempting to bypass AMSI"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1562.001"

    strings:
        $amsi1 = "amsi.dll" ascii wide nocase
        $amsi2 = "AmsiScanBuffer" ascii
        $amsi3 = "AmsiInitialize" ascii
        $amsi4 = "AmsiOpenSession" ascii

    condition:
        pe.imports("kernel32.dll", "GetProcAddress") and
        pe.imports("kernel32.dll", "VirtualProtect") and
        2 of ($amsi*)
}

// ============================================================================
// PERSISTENCE - PE ANALYSIS
// ============================================================================

rule PE_Service_Creation
{
    meta:
        description = "Detects PE creating Windows services for persistence"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1543.003"

    condition:
        pe.imports("advapi32.dll", "OpenSCManagerW") and
        pe.imports("advapi32.dll", "CreateServiceW") and
        pe.imports("advapi32.dll", "ChangeServiceConfig2W")
}

rule PE_Registry_Run_Keys
{
    meta:
        description = "Detects PE modifying Run registry keys for persistence"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1547.001"

    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii wide nocase

    condition:
        pe.imports("advapi32.dll", "RegSetValueExW") and
        any of ($run*)
}

rule PE_Scheduled_Task
{
    meta:
        description = "Detects PE creating scheduled tasks for persistence"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1053.005"

    strings:
        $task1 = "ITaskScheduler" ascii wide
        $task2 = "Schedule.Service" ascii wide
        $task3 = "schtasks" ascii wide nocase

    condition:
        pe.imports("ole32.dll", "CoCreateInstance") and
        any of ($task*)
}

// ============================================================================
// COMMAND AND CONTROL - PE ANALYSIS
// ============================================================================

rule PE_HTTP_C2_Pattern
{
    meta:
        description = "Detects PE with HTTP C2 communication pattern"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1071.001"

    condition:
        (
            pe.imports("winhttp.dll", "WinHttpOpen") and
            pe.imports("winhttp.dll", "WinHttpConnect") and
            pe.imports("winhttp.dll", "WinHttpOpenRequest")
        ) or
        (
            pe.imports("wininet.dll", "InternetOpenW") and
            pe.imports("wininet.dll", "InternetConnectW") and
            pe.imports("wininet.dll", "HttpOpenRequestW")
        )
}

rule PE_DNS_Tunneling_Pattern
{
    meta:
        description = "Detects PE with potential DNS tunneling capabilities"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1071.004"

    strings:
        $dns1 = "DnsQuery_" ascii
        $dns2 = "TXT" ascii wide
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii

    condition:
        pe.imports("dnsapi.dll", "DnsQuery_A") and
        $b64 and
        any of ($dns*)
}

// ============================================================================
// COBALT STRIKE / C2 FRAMEWORKS
// ============================================================================

rule PE_Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon characteristics"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1071.001"
        family = "CobaltStrike"

    strings:
        $cfg1 = { 00 01 00 01 00 02 }  // Beacon config header
        $cfg2 = "%s as %s\\%s: %d" ascii
        $cfg3 = "beacon.dll" ascii
        $cfg4 = "ReflectiveLoader" ascii
        $cfg5 = "%s (admin)" ascii
        $pipe = "\\\\.\\pipe\\msagent_" ascii

    condition:
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "CreateThread") and
        (3 of ($cfg*) or $pipe)
}

rule PE_Sliver_Implant
{
    meta:
        description = "Detects Sliver C2 implant characteristics"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1071.001"
        family = "Sliver"

    strings:
        $go1 = "runtime.goexit" ascii
        $go2 = "runtime.main" ascii
        $sliver1 = "sliver" ascii nocase
        $sliver2 = "bishopfox" ascii nocase
        $proto = "protobuf" ascii

    condition:
        pe.imports("kernel32.dll", "VirtualAlloc") and
        all of ($go*) and
        (any of ($sliver*) or $proto)
}
