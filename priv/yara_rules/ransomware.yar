/*
    Tamandua EDR - Ransomware Detection Rules
    These rules detect common ransomware indicators in memory and on disk.
*/

rule Ransomware_Generic_Encryption_Strings
{
    meta:
        description = "Detects generic ransomware encryption-related strings"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1486"

    strings:
        $enc1 = "Your files have been encrypted" ascii wide nocase
        $enc2 = "All your files are encrypted" ascii wide nocase
        $enc3 = "your personal files are encrypted" ascii wide nocase
        $enc4 = "to decrypt your files" ascii wide nocase
        $enc5 = "pay the ransom" ascii wide nocase
        $enc6 = "bitcoin wallet" ascii wide nocase
        $enc7 = "send bitcoin" ascii wide nocase
        $enc8 = "decrypt your data" ascii wide nocase
        $enc9 = ".onion" ascii wide
        $enc10 = "tor browser" ascii wide nocase

        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypto" ascii wide
        $ext4 = ".crypt" ascii wide
        $ext5 = ".enc" ascii wide

    condition:
        (2 of ($enc*)) or (1 of ($enc*) and 1 of ($ext*))
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Detects attempts to delete Windows shadow copies"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1490"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy delete" ascii wide nocase
        $vss4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $vss5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $vss6 = "wbadmin delete catalog" ascii wide nocase
        $vss7 = "delete shadows /all /quiet" ascii wide nocase
        $vss8 = "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }" ascii wide nocase

    condition:
        any of them
}

rule Ransomware_WannaCry
{
    meta:
        description = "Detects WannaCry ransomware indicators"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "WannaCry"
        mitre_attack = "T1486,T1021.002"

    strings:
        $wc1 = "WanaCrypt0r" ascii wide
        $wc2 = "WANACRY!" ascii wide
        $wc3 = "WNcry@2ol7" ascii wide
        $wc4 = "@WanaDecryptor@" ascii wide
        $wc5 = "tasksche.exe" ascii wide
        $wc6 = "mssecsvc.exe" ascii wide
        $wc7 = "taskdl.exe" ascii wide
        $wc8 = {00 00 00 00 00 00 00 00 00 00 00 00 00 00 57 61 6E 61 43 72 79 70 74 6F 72}

    condition:
        2 of them
}

rule Ransomware_REvil_Sodinokibi
{
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "REvil"
        mitre_attack = "T1486"

    strings:
        $cfg1 = "\"pk\":" ascii
        $cfg2 = "\"pid\":" ascii
        $cfg3 = "\"sub\":" ascii
        $cfg4 = "\"dbg\":" ascii
        $cfg5 = "\"fast\":" ascii
        $cfg6 = "\"wipe\":" ascii
        $cfg7 = "\"wfld\":" ascii
        $cfg8 = "\"prc\":" ascii
        $cfg9 = "expand 32-byte k" ascii

        $s1 = "-nolan" ascii wide
        $s2 = "-nolocal" ascii wide
        $s3 = "-path" ascii wide
        $s4 = "readme" ascii wide

    condition:
        (5 of ($cfg*)) or (all of ($s*) and 2 of ($cfg*))
}

rule Ransomware_LockBit
{
    meta:
        description = "Detects LockBit ransomware"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "LockBit"
        mitre_attack = "T1486"

    strings:
        $lb1 = "LockBit" ascii wide nocase
        $lb2 = "lockbit" ascii wide
        $lb3 = "Restore-My-Files.txt" ascii wide
        $lb4 = ".lockbit" ascii wide
        $lb5 = ".abcd" ascii wide
        $lb6 = "http://lockbit" ascii wide

        $code1 = { 8B 45 ?? 33 45 ?? 89 45 ?? 8B 4D ?? 33 4D ?? }
        $code2 = { C7 45 ?? 6B 00 63 00 C7 45 ?? 6F 00 6C 00 }

    condition:
        (2 of ($lb*)) or (1 of ($lb*) and 1 of ($code*))
}

rule Ransomware_BlackCat_ALPHV
{
    meta:
        description = "Detects BlackCat/ALPHV ransomware"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "BlackCat"
        mitre_attack = "T1486"

    strings:
        $bc1 = "access-token" ascii
        $bc2 = "--child" ascii
        $bc3 = "--access-token" ascii
        $bc4 = "RECOVER-" ascii wide
        $bc5 = "-FILES.txt" ascii wide
        $bc6 = "alphv" ascii wide nocase
        $bc7 = "blackcat" ascii wide nocase

        $rust1 = "panicked at" ascii
        $rust2 = ".rs:" ascii

    condition:
        (2 of ($bc*)) or (1 of ($bc*) and all of ($rust*))
}

rule Ransomware_Conti
{
    meta:
        description = "Detects Conti ransomware"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Conti"
        mitre_attack = "T1486"

    strings:
        $s1 = "CONTI_README.txt" ascii wide
        $s2 = ".CONTI" ascii wide
        $s3 = "contirecovery" ascii wide
        $s4 = "-nomutex" ascii wide
        $s5 = "-size" ascii wide
        $s6 = "-log" ascii wide
        $s7 = "readme_lock" ascii

        $api1 = "RtlEncryptMemory" ascii
        $api2 = "RtlDecryptMemory" ascii

    condition:
        (2 of ($s*)) or (1 of ($s*) and 1 of ($api*))
}

rule Ransomware_Crypto_API_Usage
{
    meta:
        description = "Detects suspicious cryptographic API usage patterns"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1486"

    strings:
        $api1 = "CryptAcquireContext" ascii
        $api2 = "CryptGenRandom" ascii
        $api3 = "CryptEncrypt" ascii
        $api4 = "CryptImportKey" ascii
        $api5 = "CryptDestroyKey" ascii
        $api6 = "BCryptOpenAlgorithmProvider" ascii
        $api7 = "BCryptGenerateSymmetricKey" ascii
        $api8 = "BCryptEncrypt" ascii

        $file1 = "FindFirstFile" ascii
        $file2 = "FindNextFile" ascii
        $file3 = "SetFilePointer" ascii
        $file4 = "WriteFile" ascii
        $file5 = "MoveFileEx" ascii

    condition:
        (3 of ($api*)) and (3 of ($file*))
}

rule Ransomware_Extension_Targeting
{
    meta:
        description = "Detects ransomware file extension targeting"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1486"

    strings:
        $e1 = ".doc" ascii wide nocase
        $e2 = ".docx" ascii wide nocase
        $e3 = ".xls" ascii wide nocase
        $e4 = ".xlsx" ascii wide nocase
        $e5 = ".pdf" ascii wide nocase
        $e6 = ".jpg" ascii wide nocase
        $e7 = ".png" ascii wide nocase
        $e8 = ".ppt" ascii wide nocase
        $e9 = ".pptx" ascii wide nocase
        $e10 = ".sql" ascii wide nocase
        $e11 = ".mdb" ascii wide nocase
        $e12 = ".psd" ascii wide nocase
        $e13 = ".dwg" ascii wide nocase
        $e14 = ".zip" ascii wide nocase
        $e15 = ".rar" ascii wide nocase
        $e16 = ".7z" ascii wide nocase
        $e17 = ".vmdk" ascii wide nocase
        $e18 = ".vhdx" ascii wide nocase

        $skip1 = ".exe" ascii wide nocase
        $skip2 = ".dll" ascii wide nocase
        $skip3 = ".sys" ascii wide nocase
        $skip4 = "Windows" ascii wide
        $skip5 = "Program Files" ascii wide

    condition:
        12 of ($e*) and 3 of ($skip*)
}
