/*
    Tamandua EDR - Advanced Threat Detection Rules
    Detection for sophisticated attack techniques including:
    - APT tooling
    - Living-off-the-land binaries (LOLBins)
    - Memory-only attacks
    - Advanced persistence
*/

import "pe"
import "math"

// ============================================================================
// APT TOOLING
// ============================================================================

rule APT_Cobalt_Strike_Malleable_C2
{
    meta:
        description = "Detects Cobalt Strike with malleable C2 profiles"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1071.001"
        family = "CobaltStrike"

    strings:
        // Beacon config patterns
        $beacon1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 }
        $beacon2 = { 69 68 69 68 69 6B 69 68 }  // "ihihikih"
        $beacon3 = { 2E 2F 2E 2F 2E 2C 2E 2F }  // Beacon sleep

        // Named pipe patterns
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\msse-" ascii wide
        $pipe3 = "\\\\.\\pipe\\status_" ascii wide
        $pipe4 = "\\\\.\\pipe\\postex_" ascii wide

        // Common Cobalt Strike strings
        $str1 = "beacon.dll" ascii
        $str2 = "beacon.x64.dll" ascii
        $str3 = "ReflectiveLoader" ascii
        $str4 = "%s as %s\\%s: %d" ascii
        $str5 = "Could not connect to pipe" ascii

    condition:
        (pe.is_pe and 2 of ($beacon*)) or
        (2 of ($pipe*)) or
        (3 of ($str*))
}

rule APT_Brute_Ratel
{
    meta:
        description = "Detects Brute Ratel C4 framework"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1071.001"
        family = "BruteRatel"

    strings:
        $br1 = "badger" ascii nocase
        $br2 = "brc4" ascii nocase
        $br3 = "bruteratel" ascii nocase

        // BRc4 specific patterns
        $pat1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8D 0D }
        $pat2 = { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 }

        // Crypto patterns
        $cry1 = "curve25519" ascii
        $cry2 = "chacha20" ascii

    condition:
        pe.is_pe and
        (2 of ($br*) or ($pat1 and $pat2) or (2 of ($cry*) and any of ($br*)))
}

rule APT_Havoc_Framework
{
    meta:
        description = "Detects Havoc C2 framework"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1071.001"
        family = "Havoc"

    strings:
        $havoc1 = "havoc" ascii nocase
        $havoc2 = "demon" ascii nocase
        $havoc3 = "HavocFramework" ascii

        // Demon agent patterns
        $demon1 = "DemonMain" ascii
        $demon2 = "PackageInfo" ascii
        $demon3 = "CommandRegister" ascii

    condition:
        pe.is_pe and
        (2 of ($havoc*) or 2 of ($demon*))
}

rule APT_Mythic_Agent
{
    meta:
        description = "Detects Mythic C2 agents (Apollo, Athena, etc.)"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1071.001"
        family = "Mythic"

    strings:
        $mythic1 = "mythic" ascii nocase
        $mythic2 = "apollo" ascii nocase
        $mythic3 = "athena" ascii nocase
        $mythic4 = "poseidon" ascii nocase

        // Mythic task patterns
        $task1 = "task_id" ascii
        $task2 = "callback_id" ascii
        $task3 = "completed" ascii

        // C# agent patterns (Apollo)
        $cs1 = "System.Reflection.Assembly" ascii
        $cs2 = "GetProcAddress" ascii
        $cs3 = "VirtualAlloc" ascii

    condition:
        pe.is_pe and
        (2 of ($mythic*) or (all of ($task*) and 2 of ($cs*)))
}

// ============================================================================
// LOLBIN ABUSE
// ============================================================================

rule LOLBin_MSBuild_Abuse
{
    meta:
        description = "Detects MSBuild being used for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1127.001"

    strings:
        $msbuild1 = "MSBuild" ascii wide nocase
        $msbuild2 = ".csproj" ascii wide nocase
        $msbuild3 = ".vbproj" ascii wide nocase

        // Inline task patterns
        $task1 = "UsingTask" ascii wide
        $task2 = "TaskName=" ascii wide
        $task3 = "AssemblyFile=" ascii wide
        $task4 = "<Code Type=" ascii wide
        $task5 = "TaskFactory" ascii wide

        // Code execution
        $exec1 = "Process.Start" ascii wide
        $exec2 = "DllImport" ascii wide
        $exec3 = "Assembly.Load" ascii wide
        $exec4 = "Reflection.Emit" ascii wide

    condition:
        ($msbuild1 and (any of ($msbuild2, $msbuild3))) and
        (2 of ($task*) and any of ($exec*))
}

rule LOLBin_InstallUtil_Abuse
{
    meta:
        description = "Detects InstallUtil being used for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.004"

    strings:
        $inst1 = "InstallUtil" ascii wide nocase
        $inst2 = "System.Configuration.Install" ascii wide
        $inst3 = "RunInstaller" ascii wide
        $inst4 = "Installer" ascii wide

        // Uninstall abuse
        $uninstall1 = "Uninstall" ascii wide
        $uninstall2 = "OnBeforeUninstall" ascii wide
        $uninstall3 = "OnAfterUninstall" ascii wide

    condition:
        pe.is_pe and
        2 of ($inst*) and any of ($uninstall*)
}

rule LOLBin_Regasm_Regsvcs_Abuse
{
    meta:
        description = "Detects Regasm/Regsvcs abuse for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.009"

    strings:
        $reg1 = "ComRegisterFunction" ascii wide
        $reg2 = "ComUnregisterFunction" ascii wide
        $reg3 = "System.EnterpriseServices" ascii wide
        $reg4 = "ServicedComponent" ascii wide

    condition:
        pe.is_pe and
        2 of them
}

rule LOLBin_WMIC_XSL_Abuse
{
    meta:
        description = "Detects WMIC with XSL for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1220"

    strings:
        $wmic1 = "wmic" ascii wide nocase
        $wmic2 = "/format:" ascii wide nocase
        $wmic3 = ".xsl" ascii wide nocase

        // XSL script patterns
        $xsl1 = "ActiveXObject" ascii wide
        $xsl2 = "WScript.Shell" ascii wide
        $xsl3 = "msxsl:script" ascii wide
        $xsl4 = "language=" ascii wide

    condition:
        (2 of ($wmic*)) or (2 of ($xsl*) and any of ($wmic*))
}

// ============================================================================
// MEMORY-ONLY ATTACKS
// ============================================================================

rule MemOnly_Donut_Shellcode
{
    meta:
        description = "Detects Donut shellcode generator output"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1620"

    strings:
        // Donut loader patterns
        $donut1 = { E8 ?? ?? ?? ?? 58 48 83 E8 ?? 48 8D ?? }
        $donut2 = { 65 48 8B 04 25 60 00 00 00 }  // PEB access

        // .NET CLR loading
        $clr1 = "CLRCreateInstance" ascii
        $clr2 = "ICLRRuntimeHost" ascii
        $clr3 = "mscorlib" ascii wide
        $clr4 = "System.Reflection" ascii wide

        // API hashing
        $hash1 = { 8B ?? 0F B6 ?? 8D ?? ?? 8B ?? C1 ?? 0D }

    condition:
        (any of ($donut*) and any of ($clr*)) or
        ($hash1 and 2 of ($clr*))
}

rule MemOnly_sRDI_Shellcode
{
    meta:
        description = "Detects sRDI (Shellcode Reflective DLL Injection)"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1620"

    strings:
        // sRDI bootstrap
        $srdi1 = { 55 8B EC 83 EC ?? 53 56 57 }
        $srdi2 = { 48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 }

        // Reflective loading patterns
        $refl1 = { 4D 5A 90 00 03 00 00 00 }  // MZ header search
        $refl2 = { 50 45 00 00 }  // PE signature

        // Common exports
        $exp1 = "ReflectiveLoader" ascii
        $exp2 = "_ReflectiveLoader" ascii
        $exp3 = "ordinal_1" ascii

    condition:
        (any of ($srdi*) and ($refl1 or $refl2)) or
        any of ($exp*)
}

rule MemOnly_PEzor_Output
{
    meta:
        description = "Detects PEzor shellcode packer output"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1027.002"

    strings:
        // PEzor loader patterns
        $pez1 = "inline_syscall" ascii
        $pez2 = "indirect_syscall" ascii
        $pez3 = "unhook" ascii
        $pez4 = "self_delete" ascii

        // Common syscall patterns
        $sys1 = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }
        $sys2 = { 49 89 CA B8 ?? 00 00 00 0F 05 C3 }

    condition:
        pe.is_pe and
        (2 of ($pez*) or any of ($sys*))
}

// ============================================================================
// ADVANCED PERSISTENCE
// ============================================================================

rule Persistence_WMI_Event_Subscription
{
    meta:
        description = "Detects WMI event subscription persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.003"

    strings:
        $wmi1 = "__EventConsumer" ascii wide
        $wmi2 = "__EventFilter" ascii wide
        $wmi3 = "__FilterToConsumerBinding" ascii wide
        $wmi4 = "CommandLineEventConsumer" ascii wide
        $wmi5 = "ActiveScriptEventConsumer" ascii wide

        // Creation patterns
        $create1 = "Set objWMI" ascii wide nocase
        $create2 = "Win32_ProcessStartTrace" ascii wide
        $create3 = "ExecNotificationQuery" ascii wide

    condition:
        3 of ($wmi*) or (2 of ($wmi*) and any of ($create*))
}

rule Persistence_COM_Hijack
{
    meta:
        description = "Detects COM object hijacking for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.015"

    strings:
        // COM registration paths
        $reg1 = "Software\\Classes\\CLSID" ascii wide nocase
        $reg2 = "InprocServer32" ascii wide
        $reg3 = "LocalServer32" ascii wide
        $reg4 = "TreatAs" ascii wide

        // Known hijackable CLSIDs
        $clsid1 = "{42aedc87-2188-41fd-b9a3-0c966feabec1}" ascii wide nocase  // MMCSS
        $clsid2 = "{fbeb8a05-beee-4442-804e-409d6c4515e9}" ascii wide nocase  // Known hijack
        $clsid3 = "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e2}" ascii wide nocase  // CAccPropServicesClass

    condition:
        (2 of ($reg*)) or any of ($clsid*)
}

rule Persistence_Image_File_Execution_Options
{
    meta:
        description = "Detects IFEO debugger persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.012"

    strings:
        $ifeo1 = "Image File Execution Options" ascii wide nocase
        $ifeo2 = "Debugger" ascii wide
        $ifeo3 = "GlobalFlag" ascii wide
        $ifeo4 = "SilentProcessExit" ascii wide

        // Common targets
        $target1 = "sethc.exe" ascii wide nocase
        $target2 = "utilman.exe" ascii wide nocase
        $target3 = "osk.exe" ascii wide nocase
        $target4 = "narrator.exe" ascii wide nocase
        $target5 = "magnify.exe" ascii wide nocase

    condition:
        $ifeo1 and ($ifeo2 or $ifeo3 or $ifeo4) and any of ($target*)
}

rule Persistence_AppInit_DLLs
{
    meta:
        description = "Detects AppInit_DLLs persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.010"

    strings:
        $appinit1 = "AppInit_DLLs" ascii wide
        $appinit2 = "LoadAppInit_DLLs" ascii wide
        $appinit3 = "RequireSignedAppInit_DLLs" ascii wide

        // Registry paths
        $path1 = "Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii wide nocase
        $path2 = "Wow6432Node" ascii wide

    condition:
        any of ($appinit*) and any of ($path*)
}

// ============================================================================
// CREDENTIAL ACCESS - ADVANCED
// ============================================================================

rule CredAccess_DPAPI_Masterkey
{
    meta:
        description = "Detects DPAPI master key extraction"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1555.004"

    strings:
        $dpapi1 = "CryptUnprotectData" ascii
        $dpapi2 = "CryptProtectData" ascii
        $dpapi3 = "CRYPTPROTECT_UI_FORBIDDEN" ascii

        // Master key paths
        $path1 = "Microsoft\\Protect" ascii wide
        $path2 = "Microsoft\\Credentials" ascii wide
        $path3 = "Roaming\\Microsoft\\Protect" ascii wide

        // Mimikatz DPAPI
        $mimi1 = "dpapi::masterkey" ascii wide
        $mimi2 = "sekurlsa::dpapi" ascii wide

    condition:
        pe.is_pe and
        (2 of ($dpapi*) and any of ($path*)) or any of ($mimi*)
}

rule CredAccess_Windows_Vault
{
    meta:
        description = "Detects Windows Vault credential access"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1555.004"

    strings:
        $vault1 = "VaultEnumerateItems" ascii
        $vault2 = "VaultEnumerateVaults" ascii
        $vault3 = "VaultGetItem" ascii
        $vault4 = "VaultOpenVault" ascii

        // Vault paths
        $path1 = "Microsoft\\Vault" ascii wide
        $path2 = "Web Credentials" ascii wide
        $path3 = "Windows Credentials" ascii wide

    condition:
        pe.is_pe and
        2 of ($vault*) or any of ($path*)
}

rule CredAccess_LSA_Secrets
{
    meta:
        description = "Detects LSA secrets extraction"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1003.004"

    strings:
        $lsa1 = "LsaOpenPolicy" ascii
        $lsa2 = "LsaQueryInformationPolicy" ascii
        $lsa3 = "LsaRetrievePrivateData" ascii
        $lsa4 = "LsaStorePrivateData" ascii

        // LSA secrets paths
        $path1 = "SECURITY\\Policy\\Secrets" ascii wide nocase
        $path2 = "$MACHINE.ACC" ascii wide
        $path3 = "DefaultPassword" ascii wide
        $path4 = "DPAPI" ascii wide

        // Tools
        $tool1 = "lsadump::secrets" ascii wide

    condition:
        pe.is_pe and
        (3 of ($lsa*) or (any of ($lsa*) and any of ($path*))) or $tool1
}

// ============================================================================
// NETWORK INDICATORS
// ============================================================================

rule Network_DNS_Over_HTTPS
{
    meta:
        description = "Detects DNS over HTTPS (DoH) usage for C2"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1071.004"

    strings:
        $doh1 = "dns-query" ascii wide
        $doh2 = "application/dns-message" ascii wide
        $doh3 = "application/dns-json" ascii wide

        // Known DoH providers
        $prov1 = "cloudflare-dns.com" ascii wide
        $prov2 = "dns.google" ascii wide
        $prov3 = "1.1.1.1/dns-query" ascii wide
        $prov4 = "8.8.8.8/resolve" ascii wide
        $prov5 = "dns.quad9.net" ascii wide

    condition:
        pe.is_pe and
        (any of ($doh*) or any of ($prov*))
}

rule Network_Domain_Fronting
{
    meta:
        description = "Detects potential domain fronting configuration"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1090.004"

    strings:
        // CDN hosts commonly used for fronting
        $cdn1 = "cloudfront.net" ascii wide nocase
        $cdn2 = "azureedge.net" ascii wide nocase
        $cdn3 = "fastly.net" ascii wide nocase
        $cdn4 = "akamai" ascii wide nocase

        // Host header manipulation
        $host1 = "Host:" ascii wide
        $host2 = "X-Forwarded-Host" ascii wide

        // HTTP methods
        $http1 = "GET /" ascii
        $http2 = "POST /" ascii
        $http3 = "PUT /" ascii

    condition:
        pe.is_pe and
        any of ($cdn*) and any of ($host*) and any of ($http*)
}
