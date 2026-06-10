/*
    Tamandua EDR - Trojan and RAT Detection Rules
    These rules detect common remote access trojans and backdoors.
*/

rule RAT_Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike Beacon payload"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Cobalt Strike"
        mitre_attack = "T1071,T1059.001"

    strings:
        $beacon1 = "%s (admin)" ascii
        $beacon2 = "%s as %s\\%s" ascii
        $beacon3 = "beacon.dll" ascii
        $beacon4 = "beacon.x64.dll" ascii
        $beacon5 = "ReflectiveLoader" ascii
        $beacon6 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $beacon7 = "Started service %s on %s" ascii
        $beacon8 = "powershell -nop -exec bypass -EncodedCommand" ascii wide

        $config1 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $config2 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? }

    condition:
        (3 of ($beacon*)) or any of ($config*)
}

rule RAT_Metasploit_Meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter payloads"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Meterpreter"
        mitre_attack = "T1055,T1059"

    strings:
        $metsrv1 = "metsrv" ascii
        $metsrv2 = "ext_server_stdapi" ascii
        $metsrv3 = "ext_server_priv" ascii
        $metsrv4 = "stdapi_" ascii
        $metsrv5 = "priv_" ascii

        $rev1 = "reverse_tcp" ascii
        $rev2 = "reverse_http" ascii
        $rev3 = "reverse_https" ascii
        $rev4 = "bind_tcp" ascii

        $shell = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $shell64 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 }

    condition:
        (2 of ($metsrv*)) or (1 of ($rev*) and ($shell or $shell64))
}

rule RAT_AsyncRAT
{
    meta:
        description = "Detects AsyncRAT remote access trojan"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "AsyncRAT"
        mitre_attack = "T1219"

    strings:
        $s1 = "AsyncClient" ascii wide
        $s2 = "AsyncRAT" ascii wide
        $s3 = "Asynchronous" ascii wide
        $s4 = "get_Ession" ascii
        $s5 = "get_HWID" ascii
        $s6 = "get_Ession" ascii
        $s7 = "ClientSocket" ascii
        $s8 = "HandlePacket" ascii
        $s9 = "Pastebin" ascii

        $cfg1 = "Ports" ascii
        $cfg2 = "Hosts" ascii
        $cfg3 = "Install" ascii
        $cfg4 = "MTX" ascii
        $cfg5 = "Anti" ascii

    condition:
        (4 of ($s*)) or (3 of ($cfg*) and 2 of ($s*))
}

rule RAT_Quasar
{
    meta:
        description = "Detects Quasar RAT"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Quasar"
        mitre_attack = "T1219"

    strings:
        $s1 = "QuasarClient" ascii wide
        $s2 = "Quasar.Client" ascii wide
        $s3 = "Quasar.Common" ascii wide
        $s4 = "GetKeyloggerLogs" ascii
        $s5 = "GetPasswords" ascii
        $s6 = "FileManagerHandler" ascii
        $s7 = "ReverseProxyHandler" ascii
        $s8 = "RemoteDesktopHandler" ascii

    condition:
        3 of them
}

rule RAT_NjRAT
{
    meta:
        description = "Detects njRAT remote access trojan"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "njRAT"
        mitre_attack = "T1219"

    strings:
        $s1 = "njRAT" ascii wide nocase
        $s2 = "njq8" ascii wide
        $s3 = "njw0rm" ascii wide nocase
        $s4 = "YOURHOST" ascii wide
        $s5 = "|'|'|" ascii wide
        $s6 = "netsh firewall add allowedprogram" ascii wide
        $s7 = "SEE_MASK_NOZONECHECKS" ascii wide
        $s8 = "Execute" ascii
        $s9 = "Download" ascii
        $s10 = "Update" ascii

    condition:
        (2 of ($s1, $s2, $s3)) or (1 of ($s1, $s2, $s3) and 3 of them)
}

rule RAT_DarkComet
{
    meta:
        description = "Detects DarkComet RAT"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "DarkComet"
        mitre_attack = "T1219"

    strings:
        $s1 = "DarkComet" ascii wide
        $s2 = "DC_MUTEX-" ascii wide
        $s3 = "#BOT#" ascii wide
        $s4 = "#KCMDDC" ascii
        $s5 = "YOURIP" ascii wide
        $s6 = "YOURPORT" ascii wide
        $s7 = "EditSERVER" ascii wide
        $s8 = "YOURFTPUSER" ascii wide

    condition:
        3 of them
}

rule RAT_Emotet
{
    meta:
        description = "Detects Emotet banking trojan/loader"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Emotet"
        mitre_attack = "T1566.001,T1059.001"

    strings:
        $str1 = "Content-Type: multipart/form-data" ascii
        $str2 = "Cookie:" ascii
        $str3 = "POST" ascii

        $pdb1 = "\\emotet\\" ascii nocase
        $pdb2 = "\\Loader\\" ascii

        $code1 = { 8B 4D ?? 8B 55 ?? 8B 45 ?? 0F B6 04 01 32 04 0A }
        $code2 = { 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 15 }

    condition:
        (all of ($str*)) or any of ($pdb*) or all of ($code*)
}

rule RAT_Sliver
{
    meta:
        description = "Detects Sliver C2 implant"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Sliver"
        mitre_attack = "T1071"

    strings:
        $go1 = "sliver" ascii nocase
        $go2 = "sliverpb" ascii
        $go3 = "bishopfox" ascii nocase
        $go4 = "implant" ascii

        $func1 = "RegisterImplantCallbacks" ascii
        $func2 = "GetSystemUUID" ascii
        $func3 = "StartBeaconLoop" ascii
        $func4 = "PivotTCPReq" ascii

    condition:
        (2 of ($go*)) or (2 of ($func*))
}

rule RAT_Havoc
{
    meta:
        description = "Detects Havoc C2 demon implant"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Havoc"
        mitre_attack = "T1071"

    strings:
        $s1 = "Demon" ascii
        $s2 = "demon.x64" ascii
        $s3 = "HavocFramework" ascii
        $s4 = "demon::Command" ascii

        $cfg1 = "UserAgent" ascii
        $cfg2 = "Jitter" ascii
        $cfg3 = "Sleep" ascii
        $cfg4 = "Injection" ascii

    condition:
        (2 of ($s*)) or (1 of ($s*) and 2 of ($cfg*))
}

rule RAT_Generic_Keylogger
{
    meta:
        description = "Detects generic keylogger functionality"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1056.001"

    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "GetKeyState" ascii
        $api3 = "GetKeyboardState" ascii
        $api4 = "SetWindowsHookEx" ascii
        $api5 = "GetForegroundWindow" ascii
        $api6 = "GetWindowText" ascii

        $key1 = "[SHIFT]" ascii wide
        $key2 = "[CTRL]" ascii wide
        $key3 = "[ALT]" ascii wide
        $key4 = "[ENTER]" ascii wide
        $key5 = "[BACKSPACE]" ascii wide
        $key6 = "[TAB]" ascii wide

    condition:
        (3 of ($api*) and 1 of ($key*)) or (4 of ($api*))
}

rule RAT_Generic_ScreenCapture
{
    meta:
        description = "Detects generic screen capture functionality"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1113"

    strings:
        $api1 = "GetDC" ascii
        $api2 = "CreateCompatibleDC" ascii
        $api3 = "CreateCompatibleBitmap" ascii
        $api4 = "BitBlt" ascii
        $api5 = "GetDIBits" ascii
        $api6 = "GdipCreateBitmapFromHBITMAP" ascii
        $api7 = "GdipSaveImageToFile" ascii

    condition:
        4 of them
}
