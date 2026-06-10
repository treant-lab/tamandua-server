/*
    Tamandua EDR - Malicious Document Detection Rules

    Detects malicious content in:
    - LNK (Windows Shortcuts)
    - PDF (Embedded JavaScript, exploits)
    - Office Macros (VBA, OLE)
    - HTA/HTML Applications
    - ISO/IMG containers

    MITRE ATT&CK:
    - T1204.002 (User Execution: Malicious File)
    - T1566.001 (Phishing: Spearphishing Attachment)
    - T1059.005 (VBScript)
    - T1059.007 (JavaScript)
*/

// ============================================================================
// MALICIOUS LNK (SHORTCUT) DETECTION
// ============================================================================

rule Maldoc_LNK_Suspicious_Target
{
    meta:
        description = "Detects LNK files with suspicious command execution targets"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1204.002"
        filetype = "lnk"

    strings:
        // LNK file header
        $lnk_header = { 4C 00 00 00 01 14 02 00 }

        // Suspicious targets
        $target1 = "cmd.exe" ascii wide nocase
        $target2 = "powershell" ascii wide nocase
        $target3 = "pwsh.exe" ascii wide nocase
        $target4 = "wscript" ascii wide nocase
        $target5 = "cscript" ascii wide nocase
        $target6 = "mshta" ascii wide nocase
        $target7 = "rundll32" ascii wide nocase
        $target8 = "regsvr32" ascii wide nocase
        $target9 = "certutil" ascii wide nocase
        $target10 = "bitsadmin" ascii wide nocase

        // Suspicious arguments
        $arg1 = "/c " ascii wide nocase
        $arg2 = "-enc" ascii wide nocase
        $arg3 = "-e " ascii wide nocase
        $arg4 = "FromBase64" ascii wide nocase
        $arg5 = "downloadstring" ascii wide nocase
        $arg6 = "invoke-expression" ascii wide nocase
        $arg7 = "iex" ascii wide nocase
        $arg8 = "bypass" ascii wide nocase
        $arg9 = "hidden" ascii wide nocase

    condition:
        $lnk_header at 0 and
        (any of ($target*) and any of ($arg*))
}

rule Maldoc_LNK_Hidden_Extension
{
    meta:
        description = "Detects LNK files masquerading with hidden extensions"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1036.004"
        filetype = "lnk"

    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }

        // Fake extensions in LNK name/path
        $fake1 = ".pdf.lnk" ascii wide nocase
        $fake2 = ".doc.lnk" ascii wide nocase
        $fake3 = ".docx.lnk" ascii wide nocase
        $fake4 = ".xlsx.lnk" ascii wide nocase
        $fake5 = ".txt.lnk" ascii wide nocase
        $fake6 = ".jpg.lnk" ascii wide nocase
        $fake7 = ".png.lnk" ascii wide nocase
        $fake8 = ".mp3.lnk" ascii wide nocase

    condition:
        $lnk_header at 0 and any of ($fake*)
}

rule Maldoc_LNK_Remote_Path
{
    meta:
        description = "Detects LNK files pointing to remote/network paths"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1204.002"
        filetype = "lnk"

    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }

        // Remote paths
        $remote1 = "\\\\192." ascii wide
        $remote2 = "\\\\10." ascii wide
        $remote3 = "\\\\172." ascii wide
        $remote4 = "http://" ascii wide nocase
        $remote5 = "https://" ascii wide nocase
        $remote6 = "ftp://" ascii wide nocase
        $remote7 = "\\\\\\\\*\\" ascii wide  // UNC path with wildcard

    condition:
        $lnk_header at 0 and any of ($remote*)
}

rule Maldoc_LNK_Environment_Variable_Abuse
{
    meta:
        description = "Detects LNK files abusing environment variables"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1204.002"
        filetype = "lnk"

    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }

        // Environment variable abuse
        $env1 = "%COMSPEC%" ascii wide nocase
        $env2 = "%APPDATA%" ascii wide nocase
        $env3 = "%TEMP%" ascii wide nocase
        $env4 = "%TMP%" ascii wide nocase
        $env5 = "%LOCALAPPDATA%" ascii wide nocase
        $env6 = "%PUBLIC%" ascii wide nocase
        $env7 = "%PROGRAMDATA%" ascii wide nocase

    condition:
        $lnk_header at 0 and 2 of ($env*)
}

// ============================================================================
// MALICIOUS PDF DETECTION
// ============================================================================

rule Maldoc_PDF_JavaScript
{
    meta:
        description = "Detects PDF with embedded JavaScript"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1059.007"
        filetype = "pdf"

    strings:
        $pdf_header = "%PDF-"

        // JavaScript indicators
        $js1 = "/JavaScript" ascii nocase
        $js2 = "/JS" ascii nocase
        $js3 = "/OpenAction" ascii nocase
        $js4 = "/AA" ascii nocase  // Additional Actions
        $js5 = "/Launch" ascii nocase
        $js6 = "eval(" ascii nocase
        $js7 = "unescape(" ascii nocase
        $js8 = "fromCharCode" ascii nocase

    condition:
        $pdf_header at 0 and
        (($js1 or $js2) and ($js3 or $js4)) or
        (any of ($js5, $js6, $js7, $js8))
}

rule Maldoc_PDF_Embedded_File
{
    meta:
        description = "Detects PDF with embedded executable files"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1204.002"
        filetype = "pdf"

    strings:
        $pdf_header = "%PDF-"

        // Embedded file indicators
        $embed1 = "/EmbeddedFiles" ascii nocase
        $embed2 = "/EmbeddedFile" ascii nocase
        $embed3 = "/Filespec" ascii nocase
        $embed4 = "/F (" ascii

        // Suspicious file types
        $exe1 = ".exe" ascii nocase
        $exe2 = ".dll" ascii nocase
        $exe3 = ".scr" ascii nocase
        $exe4 = ".bat" ascii nocase
        $exe5 = ".cmd" ascii nocase
        $exe6 = ".ps1" ascii nocase
        $exe7 = ".vbs" ascii nocase
        $exe8 = ".hta" ascii nocase

        // PE header in stream
        $mz = { 4D 5A }

    condition:
        $pdf_header at 0 and
        (any of ($embed*) and any of ($exe*)) or
        ($pdf_header at 0 and $mz)
}

rule Maldoc_PDF_Exploit_Patterns
{
    meta:
        description = "Detects known PDF exploit patterns"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1203"
        filetype = "pdf"

    strings:
        $pdf_header = "%PDF-"

        // Heap spray patterns
        $spray1 = { 0C 0C 0C 0C 0C 0C 0C 0C }
        $spray2 = { 0D 0D 0D 0D 0D 0D 0D 0D }
        $spray3 = { 41 41 41 41 41 41 41 41 }

        // Shellcode patterns
        $shell1 = { EB ?? 5? }  // JMP + POP
        $shell2 = { E8 00 00 00 00 5? }  // CALL + POP
        $shell3 = { 64 A1 30 00 00 00 }  // TEB access

        // CVE patterns
        $cve1 = "/Colors 2147483" ascii  // Integer overflow
        $cve2 = "/Predictor 50" ascii  // Buffer overflow
        $cve3 = "util.printf" ascii  // Format string
        $cve4 = "Collab.collectEmailInfo" ascii  // CVE-2007-5659
        $cve5 = "app.doc.syncAnnotScan" ascii  // CVE-2009-0927

    condition:
        $pdf_header at 0 and
        (any of ($spray*) or any of ($shell*) or any of ($cve*))
}

rule Maldoc_PDF_Suspicious_URIs
{
    meta:
        description = "Detects PDF with suspicious URI actions"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1204.002"
        filetype = "pdf"

    strings:
        $pdf_header = "%PDF-"

        $uri1 = "/URI" ascii
        $uri2 = "/GoToR" ascii  // Remote GoTo
        $uri3 = "/GoToE" ascii  // Embedded GoTo
        $uri4 = "/SubmitForm" ascii
        $uri5 = "/ImportData" ascii

        // Suspicious protocols
        $proto1 = "file://" ascii nocase
        $proto2 = "smb://" ascii nocase
        $proto3 = "\\\\\\\\192." ascii
        $proto4 = "data:" ascii nocase

    condition:
        $pdf_header at 0 and
        (any of ($uri*) and any of ($proto*))
}

// ============================================================================
// MALICIOUS OFFICE MACRO DETECTION (OLE/OOXML)
// ============================================================================

rule Maldoc_Office_OLE_Macro
{
    meta:
        description = "Detects Office documents with suspicious VBA macros"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1059.005"
        filetype = "office"

    strings:
        // OLE header
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }

        // VBA indicators
        $vba1 = "VBA" ascii wide
        $vba2 = "_VBA_PROJECT" ascii wide
        $vba3 = "Attribute VB_" ascii
        $vba4 = "ThisDocument" ascii
        $vba5 = "ThisWorkbook" ascii

        // Suspicious VBA functions
        $func1 = "Shell" ascii nocase
        $func2 = "WScript.Shell" ascii nocase
        $func3 = "CreateObject" ascii nocase
        $func4 = "Environ" ascii nocase
        $func5 = "PowerShell" ascii nocase
        $func6 = "cmd.exe" ascii nocase
        $func7 = "DownloadFile" ascii nocase
        $func8 = "URLDownloadToFile" ascii nocase
        $func9 = "XMLHTTP" ascii nocase
        $func10 = "ADODB.Stream" ascii nocase

    condition:
        $ole_header at 0 and
        any of ($vba*) and
        2 of ($func*)
}

rule Maldoc_Office_AutoOpen
{
    meta:
        description = "Detects Office macros with auto-execution"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1204.002"
        filetype = "office"

    strings:
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }

        // Auto-execution triggers
        $auto1 = "Auto_Open" ascii nocase
        $auto2 = "AutoOpen" ascii nocase
        $auto3 = "Auto_Close" ascii nocase
        $auto4 = "AutoClose" ascii nocase
        $auto5 = "AutoExec" ascii nocase
        $auto6 = "Auto_Exec" ascii nocase
        $auto7 = "Workbook_Open" ascii nocase
        $auto8 = "Document_Open" ascii nocase
        $auto9 = "Document_Close" ascii nocase
        $auto10 = "AutoExit" ascii nocase

    condition:
        $ole_header at 0 and any of ($auto*)
}

rule Maldoc_Office_Obfuscation
{
    meta:
        description = "Detects obfuscated Office macros"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1027"
        filetype = "office"

    strings:
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }

        // Obfuscation patterns
        $obf1 = "Chr(" ascii nocase
        $obf2 = "ChrW(" ascii nocase
        $obf3 = "StrReverse" ascii nocase
        $obf4 = "CallByName" ascii nocase
        $obf5 = "Replace(" ascii nocase
        $obf6 = "Mid(" ascii nocase
        $obf7 = "CLng(" ascii nocase

        // Base64 patterns
        $b64_1 = "QUJD" ascii  // ABC
        $b64_2 = "TVqQ" ascii  // MZ (PE header)
        $b64_3 = "UEsD" ascii  // PK (ZIP)

    condition:
        $ole_header at 0 and
        (3 of ($obf*) or any of ($b64_*))
}

rule Maldoc_Office_DDE_Attack
{
    meta:
        description = "Detects Office DDE (Dynamic Data Exchange) attacks"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1559.002"
        filetype = "office"

    strings:
        // OOXML indicators
        $xml1 = "<?xml" ascii
        $xml2 = "word/" ascii
        $xml3 = "xl/" ascii

        // DDE patterns
        $dde1 = "DDEAUTO" ascii nocase
        $dde2 = "DDE " ascii
        $dde3 = { 13 00 44 44 45 }  // Field with DDE
        $dde4 = "cmd.exe" ascii nocase
        $dde5 = "powershell" ascii nocase
        $dde6 = "\\\\c" ascii

    condition:
        (any of ($xml*)) and
        (any of ($dde1, $dde2, $dde3)) and
        (any of ($dde4, $dde5, $dde6))
}

rule Maldoc_Office_External_Relationship
{
    meta:
        description = "Detects Office documents with external template injection"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1221"
        filetype = "office"

    strings:
        // OOXML relationship indicators
        $rel1 = "relationships" ascii
        $rel2 = "Target=" ascii
        $rel3 = "TargetMode=\"External\"" ascii

        // External targets
        $ext1 = "http://" ascii nocase
        $ext2 = "https://" ascii nocase
        $ext3 = "file://" ascii nocase
        $ext4 = "\\\\\\\\192." ascii
        $ext5 = "\\\\\\\\10." ascii
        $ext6 = ".dotm" ascii nocase
        $ext7 = ".dot" ascii nocase

    condition:
        any of ($rel*) and any of ($ext*)
}

// ============================================================================
// HTA/HTML APPLICATION DETECTION
// ============================================================================

rule Maldoc_HTA_Suspicious
{
    meta:
        description = "Detects suspicious HTA applications"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1218.005"
        filetype = "hta"

    strings:
        $hta1 = "<HTA:APPLICATION" ascii nocase
        $hta2 = "<script" ascii nocase
        $hta3 = "vbscript" ascii nocase
        $hta4 = "javascript" ascii nocase

        // Dangerous functions
        $func1 = "WScript.Shell" ascii nocase
        $func2 = "Shell.Application" ascii nocase
        $func3 = "Scripting.FileSystemObject" ascii nocase
        $func4 = "ADODB.Stream" ascii nocase
        $func5 = "powershell" ascii nocase
        $func6 = "cmd.exe" ascii nocase
        $func7 = "CreateObject" ascii nocase
        $func8 = "GetObject" ascii nocase

    condition:
        $hta1 and any of ($hta2, $hta3, $hta4) and 2 of ($func*)
}

// ============================================================================
// ISO/IMG CONTAINER DETECTION
// ============================================================================

rule Maldoc_ISO_With_Executable
{
    meta:
        description = "Detects ISO/IMG files containing executables"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1204.002"
        filetype = "iso"

    strings:
        // ISO header patterns
        $iso1 = "CD001" ascii  // ISO 9660
        $iso2 = { 00 00 00 00 00 00 00 00 43 44 30 30 31 }  // ISO with padding

        // Executable indicators inside ISO
        $exe1 = "MZ" ascii  // PE header
        $exe2 = ".exe" ascii nocase
        $exe3 = ".dll" ascii nocase
        $exe4 = ".scr" ascii nocase
        $exe5 = ".bat" ascii nocase
        $exe6 = ".cmd" ascii nocase
        $exe7 = ".lnk" ascii nocase
        $exe8 = ".vbs" ascii nocase
        $exe9 = ".ps1" ascii nocase

    condition:
        ($iso1 or $iso2) and 2 of ($exe*)
}

rule Maldoc_ISO_Hidden_Extension
{
    meta:
        description = "Detects ISO files with double/hidden extensions"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1036.004"
        filetype = "iso"

    strings:
        $iso1 = "CD001" ascii

        // Double extension patterns
        $double1 = ".pdf.iso" ascii nocase
        $double2 = ".doc.iso" ascii nocase
        $double3 = ".docx.iso" ascii nocase
        $double4 = ".xlsx.iso" ascii nocase
        $double5 = ".jpg.iso" ascii nocase
        $double6 = ".png.iso" ascii nocase

        // IMG variants
        $img1 = ".pdf.img" ascii nocase
        $img2 = ".doc.img" ascii nocase

    condition:
        $iso1 and (any of ($double*) or any of ($img*))
}

// ============================================================================
// GENERIC SCRIPT-BASED MALWARE
// ============================================================================

rule Maldoc_VBS_Downloader
{
    meta:
        description = "Detects VBScript downloaders"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1059.005"
        filetype = "vbs"

    strings:
        // VBS indicators
        $vbs1 = "CreateObject" ascii nocase
        $vbs2 = "WScript" ascii nocase
        $vbs3 = "Dim " ascii nocase

        // Download functions
        $dl1 = "XMLHTTP" ascii nocase
        $dl2 = "ServerXMLHTTP" ascii nocase
        $dl3 = "MSXML2" ascii nocase
        $dl4 = "WinHttp" ascii nocase
        $dl5 = "InternetExplorer.Application" ascii nocase

        // File operations
        $file1 = "ADODB.Stream" ascii nocase
        $file2 = "SaveToFile" ascii nocase
        $file3 = "FileSystemObject" ascii nocase
        $file4 = "CreateTextFile" ascii nocase

        // Execution
        $exec1 = "Shell" ascii nocase
        $exec2 = "Run " ascii nocase
        $exec3 = "Exec" ascii nocase

    condition:
        any of ($vbs*) and
        any of ($dl*) and
        any of ($file*) and
        any of ($exec*)
}

rule Maldoc_JS_Downloader
{
    meta:
        description = "Detects JavaScript downloaders"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1059.007"
        filetype = "js"

    strings:
        // WSH JScript indicators
        $js1 = "new ActiveXObject" ascii nocase
        $js2 = "WScript" ascii nocase
        $js3 = "var " ascii

        // Download
        $dl1 = "XMLHTTP" ascii nocase
        $dl2 = "WinHttp" ascii nocase
        $dl3 = "URLDownloadToFile" ascii nocase

        // File operations
        $file1 = "ADODB.Stream" ascii nocase
        $file2 = "Scripting.FileSystemObject" ascii nocase
        $file3 = "saveToFile" ascii nocase

        // Execution
        $exec1 = "WScript.Shell" ascii nocase
        $exec2 = ".Run(" ascii nocase
        $exec3 = ".Exec(" ascii nocase

        // Obfuscation
        $obf1 = "eval(" ascii nocase
        $obf2 = "fromCharCode" ascii nocase
        $obf3 = "String.fromCharCode" ascii nocase

    condition:
        any of ($js*) and
        (any of ($dl*) or any of ($file*)) and
        (any of ($exec*) or any of ($obf*))
}

rule Maldoc_PowerShell_In_Document
{
    meta:
        description = "Detects PowerShell commands embedded in documents"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1059.001"
        filetype = "office"

    strings:
        // PowerShell indicators
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $ps3 = "-enc" ascii wide nocase
        $ps4 = "-encodedcommand" ascii wide nocase
        $ps5 = "-e " ascii wide nocase
        $ps6 = "FromBase64String" ascii wide nocase
        $ps7 = "Invoke-Expression" ascii wide nocase
        $ps8 = "IEX" ascii wide nocase
        $ps9 = "DownloadString" ascii wide nocase
        $ps10 = "DownloadFile" ascii wide nocase
        $ps11 = "Net.WebClient" ascii wide nocase
        $ps12 = "Invoke-WebRequest" ascii wide nocase
        $ps13 = "-windowstyle hidden" ascii wide nocase
        $ps14 = "-nop" ascii wide nocase
        $ps15 = "-noprofile" ascii wide nocase

    condition:
        $ps1 or $ps2 and
        3 of ($ps*)
}
