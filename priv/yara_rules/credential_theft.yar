/*
    Tamandua EDR - Credential Theft Detection Rules
    These rules detect credential dumping and theft tools.
*/

rule CredTheft_Mimikatz
{
    meta:
        description = "Detects Mimikatz credential theft tool"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Mimikatz"
        mitre_attack = "T1003.001"

    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "gentilkiwi" ascii wide
        $s3 = "sekurlsa::" ascii wide
        $s4 = "kerberos::" ascii wide
        $s5 = "lsadump::" ascii wide
        $s6 = "privilege::debug" ascii wide
        $s7 = "token::elevate" ascii wide
        $s8 = "dpapi::" ascii wide
        $s9 = "vault::" ascii wide
        $s10 = "Primary\\Credentials" ascii
        $s11 = "mimilib.dll" ascii wide
        $s12 = "mimidrv.sys" ascii wide

        $f1 = "sekurlsa_wdigest_" ascii
        $f2 = "kuhl_m_" ascii

    condition:
        (3 of ($s*)) or (1 of ($f*))
}

rule CredTheft_LaZagne
{
    meta:
        description = "Detects LaZagne password recovery tool"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "LaZagne"
        mitre_attack = "T1555"

    strings:
        $s1 = "lazagne" ascii wide nocase
        $s2 = "laZagne" ascii wide
        $s3 = "credman" ascii wide
        $s4 = "memorydump" ascii wide
        $s5 = "pypykatz" ascii wide

        $py1 = "from lazagne" ascii
        $py2 = "import lazagne" ascii
        $py3 = "softwares.browsers" ascii
        $py4 = "softwares.sysadmin" ascii

    condition:
        (2 of ($s*)) or (2 of ($py*))
}

rule CredTheft_Rubeus
{
    meta:
        description = "Detects Rubeus Kerberos attack tool"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Rubeus"
        mitre_attack = "T1558.003"

    strings:
        $s1 = "Rubeus" ascii wide
        $s2 = "asreproast" ascii wide nocase
        $s3 = "kerberoast" ascii wide nocase
        $s4 = "s4u" ascii wide
        $s5 = "asktgt" ascii wide nocase
        $s6 = "asktgs" ascii wide nocase
        $s7 = "ptt" ascii wide
        $s8 = "kirbi" ascii wide
        $s9 = "createnetonly" ascii wide
        $s10 = "changepw" ascii wide
        $s11 = "tgtdeleg" ascii wide

    condition:
        (3 of them)
}

rule CredTheft_Impacket
{
    meta:
        description = "Detects Impacket attack tool suite"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Impacket"
        mitre_attack = "T1003,T1021.002"

    strings:
        $s1 = "impacket" ascii wide nocase
        $s2 = "secretsdump" ascii wide nocase
        $s3 = "psexec" ascii wide nocase
        $s4 = "wmiexec" ascii wide nocase
        $s5 = "smbexec" ascii wide nocase
        $s6 = "atexec" ascii wide nocase
        $s7 = "dcomexec" ascii wide nocase
        $s8 = "ntlmrelayx" ascii wide nocase
        $s9 = "GetNPUsers" ascii
        $s10 = "GetUserSPNs" ascii

        $py1 = "from impacket" ascii
        $py2 = "import impacket" ascii

    condition:
        (2 of ($s*)) or any of ($py*)
}

rule CredTheft_SharpHound
{
    meta:
        description = "Detects SharpHound BloodHound data collector"
        author = "Tamandua Security Team"
        severity = "high"
        family = "SharpHound"
        mitre_attack = "T1087.002"

    strings:
        $s1 = "SharpHound" ascii wide
        $s2 = "BloodHound" ascii wide
        $s3 = "InvokeBloodHound" ascii wide
        $s4 = "CollectionMethod" ascii wide
        $s5 = "computers.json" ascii wide
        $s6 = "users.json" ascii wide
        $s7 = "groups.json" ascii wide
        $s8 = "domains.json" ascii wide
        $s9 = "DcOnly" ascii wide

    condition:
        3 of them
}

rule CredTheft_LSASS_Dump
{
    meta:
        description = "Detects LSASS memory dump techniques"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1003.001"

    strings:
        $api1 = "MiniDumpWriteDump" ascii
        $api2 = "OpenProcess" ascii
        $api3 = "lsass" ascii wide nocase
        $api4 = "DbgHelp" ascii
        $api5 = "dbgcore" ascii

        $proc1 = "procdump" ascii wide nocase
        $proc2 = "sqldumper" ascii wide nocase
        $proc3 = "comsvcs.dll" ascii wide
        $proc4 = "rundll32" ascii wide

        $cmd1 = "sekurlsa::minidump" ascii wide
        $cmd2 = "lsass.dmp" ascii wide
        $cmd3 = "lsass.exe" ascii wide

    condition:
        ($api1 and $api3) or ($api2 and $api3) or (2 of ($proc*)) or any of ($cmd*)
}

rule CredTheft_SAM_Dump
{
    meta:
        description = "Detects SAM database dumping"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1003.002"

    strings:
        $s1 = "reg save HKLM\\SAM" ascii wide nocase
        $s2 = "reg save HKLM\\SYSTEM" ascii wide nocase
        $s3 = "reg save HKLM\\SECURITY" ascii wide nocase
        $s4 = "HiveNightmare" ascii wide
        $s5 = "SeriousSAM" ascii wide
        $s6 = "vssadmin create shadow" ascii wide nocase
        $s7 = "esentutl" ascii wide

        $ntds1 = "ntds.dit" ascii wide nocase
        $ntds2 = "NTDS\\ntds.dit" ascii wide

    condition:
        (2 of ($s*)) or any of ($ntds*)
}

rule CredTheft_ProcDump
{
    meta:
        description = "Detects ProcDump being used for credential theft"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1003.001"

    strings:
        $s1 = "procdump" ascii wide nocase
        $s2 = "-ma lsass" ascii wide nocase
        $s3 = "-accepteula -ma" ascii wide
        $s4 = "lsass.exe" ascii wide

        $sus1 = "-ma" ascii wide
        $sus2 = "lsass" ascii wide nocase

    condition:
        ($s1 and ($s2 or $s3 or $s4)) or (all of ($sus*))
}

rule CredTheft_Browser_Stealer
{
    meta:
        description = "Detects browser credential stealer patterns"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1555.003"

    strings:
        $chrome1 = "Chrome\\User Data\\Default" ascii wide
        $chrome2 = "Login Data" ascii wide
        $chrome3 = "cookies" ascii wide nocase
        $chrome4 = "CryptUnprotectData" ascii

        $firefox1 = "Mozilla\\Firefox\\Profiles" ascii wide
        $firefox2 = "logins.json" ascii wide
        $firefox3 = "signons.sqlite" ascii wide
        $firefox4 = "key4.db" ascii wide
        $firefox5 = "cert9.db" ascii wide

        $edge1 = "Microsoft\\Edge\\User Data" ascii wide

        $sql1 = "SELECT action_url, username_value, password_value FROM logins" ascii wide
        $sql2 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide

    condition:
        (2 of ($chrome*)) or (2 of ($firefox*)) or ($edge1 and 1 of ($chrome*)) or any of ($sql*)
}

rule CredTheft_WiFi_Password
{
    meta:
        description = "Detects WiFi password extraction"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1555"

    strings:
        $cmd1 = "netsh wlan show profiles" ascii wide nocase
        $cmd2 = "netsh wlan show profile" ascii wide nocase
        $cmd3 = "key=clear" ascii wide nocase
        $cmd4 = "WlanGetProfile" ascii
        $cmd5 = "wlanapi.dll" ascii

    condition:
        2 of them
}

rule CredTheft_DCSync
{
    meta:
        description = "Detects DCSync attack indicators"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1003.006"

    strings:
        $s1 = "lsadump::dcsync" ascii wide
        $s2 = "DRS_EXTENSIONS_INT" ascii
        $s3 = "DS_REPLICATION_GET_CHANGES" ascii
        $s4 = "GetNCChanges" ascii
        $s5 = "GUID_DRS_GET_CHANGES" ascii
        $s6 = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" ascii wide nocase
        $s7 = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" ascii wide nocase

    condition:
        2 of them
}
