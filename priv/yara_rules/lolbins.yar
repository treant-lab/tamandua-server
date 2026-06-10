/*
    Tamandua EDR - Living Off The Land Binaries (LOLBins) Detection Rules
    These rules detect abuse of legitimate Windows utilities.
*/

rule LOLBin_PowerShell_Suspicious
{
    meta:
        description = "Detects suspicious PowerShell execution patterns"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1059.001"

    strings:
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encodedcommand" ascii wide nocase
        $enc3 = "-ec" ascii wide nocase

        $bypass1 = "-nop" ascii wide nocase
        $bypass2 = "-noprofile" ascii wide nocase
        $bypass3 = "-ep bypass" ascii wide nocase
        $bypass4 = "-exec bypass" ascii wide nocase
        $bypass5 = "-executionpolicy bypass" ascii wide nocase
        $bypass6 = "-w hidden" ascii wide nocase
        $bypass7 = "-windowstyle hidden" ascii wide nocase
        $bypass8 = "Set-ExecutionPolicy Bypass" ascii wide nocase

        $download1 = "DownloadString" ascii wide
        $download2 = "DownloadFile" ascii wide
        $download3 = "DownloadData" ascii wide
        $download4 = "Net.WebClient" ascii wide
        $download5 = "Invoke-WebRequest" ascii wide
        $download6 = "iwr" ascii wide
        $download7 = "curl" ascii wide
        $download8 = "wget" ascii wide

        $iex1 = "IEX" ascii wide
        $iex2 = "Invoke-Expression" ascii wide
        $iex3 = "Invoke-Command" ascii wide

    condition:
        (any of ($enc*) and any of ($bypass*)) or
        (any of ($download*) and any of ($iex*)) or
        (2 of ($bypass*) and any of ($download*))
}

rule LOLBin_CertUtil_Download
{
    meta:
        description = "Detects CertUtil abuse for downloading files"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1105"

    strings:
        $s1 = "certutil" ascii wide nocase
        $s2 = "-urlcache" ascii wide nocase
        $s3 = "-split" ascii wide nocase
        $s4 = "-f" ascii wide nocase
        $s5 = "http" ascii wide nocase
        $s6 = "-decode" ascii wide nocase
        $s7 = "-encode" ascii wide nocase

    condition:
        $s1 and (($s2 and $s4) or $s6 or $s7)
}

rule LOLBin_MSHTA
{
    meta:
        description = "Detects MSHTA abuse for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.005"

    strings:
        $mshta = "mshta" ascii wide nocase
        $vbscript = "vbscript:" ascii wide nocase
        $javascript = "javascript:" ascii wide nocase
        $http = "http" ascii wide nocase
        $hta = ".hta" ascii wide nocase

    condition:
        $mshta and ($vbscript or $javascript or ($http and $hta))
}

rule LOLBin_Regsvr32_Squiblydoo
{
    meta:
        description = "Detects Regsvr32 abuse (Squiblydoo)"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.010"

    strings:
        $regsvr32 = "regsvr32" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
        $i = "/i:" ascii wide nocase
        $s = "/s" ascii wide nocase
        $u = "/u" ascii wide nocase
        $n = "/n" ascii wide nocase
        $http = "http" ascii wide nocase

    condition:
        $regsvr32 and ($scrobj or ($i and $http) or ($s and $u and $n))
}

rule LOLBin_WMIC
{
    meta:
        description = "Detects suspicious WMIC usage"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1047"

    strings:
        $wmic = "wmic" ascii wide nocase
        $process_call = "process call create" ascii wide nocase
        $node = "/node:" ascii wide nocase
        $format = "/format:" ascii wide nocase
        $os_get = "os get" ascii wide nocase
        $http = "http" ascii wide nocase

    condition:
        $wmic and ($process_call or ($format and $http) or $node)
}

rule LOLBin_Rundll32
{
    meta:
        description = "Detects suspicious Rundll32 usage"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.011"

    strings:
        $rundll32 = "rundll32" ascii wide nocase

        $dll1 = "javascript:" ascii wide nocase
        $dll2 = "shell32.dll,Control_RunDLL" ascii wide nocase
        $dll3 = "shell32.dll,ShellExec_RunDLL" ascii wide nocase
        $dll4 = "url.dll,FileProtocolHandler" ascii wide nocase
        $dll5 = "zipfldr.dll,RouteTheCall" ascii wide nocase
        $dll6 = "advpack.dll,LaunchINFSection" ascii wide nocase
        $dll7 = "advpack.dll,RegisterOCX" ascii wide nocase
        $dll8 = "ieadvpack.dll,LaunchINFSection" ascii wide nocase
        $dll9 = "ieframe.dll,OpenURL" ascii wide nocase
        $dll10 = "shdocvw.dll,OpenURL" ascii wide nocase
        $dll11 = "pcwutl.dll,LaunchApplication" ascii wide nocase

        $http = "http" ascii wide nocase

    condition:
        $rundll32 and (any of ($dll*) or $http)
}

rule LOLBin_MSBuild
{
    meta:
        description = "Detects MSBuild abuse for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1127.001"

    strings:
        $msbuild = "msbuild" ascii wide nocase
        $inline1 = "<Task>" ascii wide
        $inline2 = "UsingTask" ascii wide
        $inline3 = "TaskName" ascii wide
        $inline4 = "AssemblyFile" ascii wide
        $inline5 = "InlineTask" ascii wide
        $compile = "CSharpCodeProvider" ascii wide

    condition:
        $msbuild and (3 of ($inline*) or $compile)
}

rule LOLBin_InstallUtil
{
    meta:
        description = "Detects InstallUtil abuse"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.004"

    strings:
        $installutil = "installutil" ascii wide nocase
        $logfile = "/logfile=" ascii wide nocase
        $logtoconsole = "/logtoconsole=false" ascii wide nocase
        $u = "/u" ascii wide nocase

    condition:
        $installutil and ($logfile or $logtoconsole or $u)
}

rule LOLBin_BitsAdmin
{
    meta:
        description = "Detects BitsAdmin abuse for file transfer"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1197"

    strings:
        $bitsadmin = "bitsadmin" ascii wide nocase
        $transfer = "/transfer" ascii wide nocase
        $create = "/create" ascii wide nocase
        $addfile = "/addfile" ascii wide nocase
        $setnotifycmdline = "/setnotifycmdline" ascii wide nocase
        $resume = "/resume" ascii wide nocase
        $http = "http" ascii wide nocase

    condition:
        $bitsadmin and (($transfer and $http) or ($create and $addfile) or $setnotifycmdline)
}

rule LOLBin_CMSTP
{
    meta:
        description = "Detects CMSTP abuse for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.003"

    strings:
        $cmstp = "cmstp" ascii wide nocase
        $inf = ".inf" ascii wide nocase
        $s = "/s" ascii wide nocase
        $au = "/au" ascii wide nocase

    condition:
        $cmstp and ($inf or $s or $au)
}

rule LOLBin_Forfiles
{
    meta:
        description = "Detects ForFiles abuse for code execution"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1202"

    strings:
        $forfiles = "forfiles" ascii wide nocase
        $p = "/p" ascii wide nocase
        $m = "/m" ascii wide nocase
        $c = "/c" ascii wide nocase
        $cmd = "cmd" ascii wide nocase

    condition:
        $forfiles and $c and $cmd
}

rule LOLBin_Msiexec
{
    meta:
        description = "Detects Msiexec abuse for code execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.007"

    strings:
        $msiexec = "msiexec" ascii wide nocase
        $http = "http" ascii wide nocase
        $i = "/i" ascii wide nocase
        $q = "/q" ascii wide nocase
        $y = "/y" ascii wide nocase
        $z = "/z" ascii wide nocase

    condition:
        $msiexec and (($i and $http) or ($q and $http) or $y or $z)
}

rule LOLBin_Odbcconf
{
    meta:
        description = "Detects Odbcconf abuse"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.008"

    strings:
        $odbcconf = "odbcconf" ascii wide nocase
        $regsvr = "/a {REGSVR" ascii wide nocase
        $action = "-a" ascii wide nocase
        $dll = ".dll" ascii wide nocase

    condition:
        $odbcconf and ($regsvr or ($action and $dll))
}

rule LOLBin_Pcalua
{
    meta:
        description = "Detects Pcalua (Program Compatibility Assistant) abuse"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1202"

    strings:
        $pcalua = "pcalua" ascii wide nocase
        $a = "-a" ascii wide nocase

    condition:
        all of them
}

rule LOLBin_SyncAppvPublishingServer
{
    meta:
        description = "Detects SyncAppvPublishingServer abuse"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218"

    strings:
        $sync = "SyncAppvPublishingServer" ascii wide nocase
        $ps = "powershell" ascii wide nocase
        $n = "n;" ascii wide

    condition:
        $sync and ($ps or $n)
}

rule LOLBin_Msdeploy
{
    meta:
        description = "Detects Msdeploy abuse"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218"

    strings:
        $msdeploy = "msdeploy" ascii wide nocase
        $verb = "-verb:sync" ascii wide nocase
        $source = "-source:runcommand" ascii wide nocase

    condition:
        $msdeploy and $verb and $source
}

rule LOLBin_Diantz_Makecab
{
    meta:
        description = "Detects Diantz/Makecab abuse for alternate data stream"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1564.004"

    strings:
        $diantz = "diantz" ascii wide nocase
        $makecab = "makecab" ascii wide nocase
        $ads = ":ads" ascii wide nocase

    condition:
        ($diantz or $makecab) and $ads
}

rule LOLBin_Esentutl
{
    meta:
        description = "Detects Esentutl abuse for file copy"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1003.003"

    strings:
        $esentutl = "esentutl" ascii wide nocase
        $y = "/y" ascii wide nocase
        $vss = "vss" ascii wide nocase
        $ntds = "ntds.dit" ascii wide nocase

    condition:
        $esentutl and ($y or $vss or $ntds)
}
