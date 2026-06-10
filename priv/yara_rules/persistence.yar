/*
    Tamandua EDR - Persistence Detection Rules
    These rules detect persistence mechanism indicators.
*/

rule Persistence_Registry_Run_Keys
{
    meta:
        description = "Detects manipulation of registry run keys for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1547.001"

    strings:
        $key1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $key2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $key3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide nocase
        $key4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" ascii wide nocase
        $key5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii wide nocase
        $key6 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
        $api3 = "RegOpenKeyEx" ascii

    condition:
        any of ($key*) and any of ($api*)
}

rule Persistence_Scheduled_Task
{
    meta:
        description = "Detects scheduled task creation for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1053.005"

    strings:
        $cmd1 = "schtasks /create" ascii wide nocase
        $cmd2 = "schtasks.exe /create" ascii wide nocase
        $cmd3 = "Register-ScheduledTask" ascii wide
        $cmd4 = "New-ScheduledTask" ascii wide

        $xml1 = "<Task version=" ascii wide
        $xml2 = "<Actions Context=" ascii wide
        $xml3 = "<Exec>" ascii wide
        $xml4 = "<Triggers>" ascii wide

        $api1 = "ITaskFolder" ascii
        $api2 = "ITaskService" ascii
        $api3 = "RegisterTaskDefinition" ascii

    condition:
        any of ($cmd*) or (2 of ($xml*)) or (2 of ($api*))
}

rule Persistence_WMI_Subscription
{
    meta:
        description = "Detects WMI event subscription for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.003"

    strings:
        $wmi1 = "__EventFilter" ascii wide
        $wmi2 = "__EventConsumer" ascii wide
        $wmi3 = "__FilterToConsumerBinding" ascii wide
        $wmi4 = "CommandLineEventConsumer" ascii wide
        $wmi5 = "ActiveScriptEventConsumer" ascii wide
        $wmi6 = "Win32_ProcessStartTrace" ascii wide

        $cmd1 = "wmic /namespace" ascii wide nocase
        $cmd2 = "Register-WmiEvent" ascii wide

    condition:
        (2 of ($wmi*)) or any of ($cmd*)
}

rule Persistence_Service_Creation
{
    meta:
        description = "Detects service creation for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1543.003"

    strings:
        $cmd1 = "sc create" ascii wide nocase
        $cmd2 = "sc.exe create" ascii wide nocase
        $cmd3 = "New-Service" ascii wide
        $cmd4 = "CreateService" ascii

        $api1 = "OpenSCManager" ascii
        $api2 = "CreateServiceA" ascii
        $api3 = "CreateServiceW" ascii
        $api4 = "StartService" ascii

        $key1 = "SYSTEM\\CurrentControlSet\\Services" ascii wide

    condition:
        any of ($cmd*) or (2 of ($api*)) or $key1
}

rule Persistence_Startup_Folder
{
    meta:
        description = "Detects startup folder abuse for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1547.001"

    strings:
        $path1 = "\\Start Menu\\Programs\\Startup" ascii wide
        $path2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide
        $path3 = "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" ascii wide
        $path4 = "shell:startup" ascii wide nocase
        $path5 = "shell:common startup" ascii wide nocase

        $api1 = "SHGetFolderPath" ascii
        $api2 = "SHGetKnownFolderPath" ascii
        $api3 = "CopyFile" ascii
        $api4 = "CreateFile" ascii

    condition:
        any of ($path*) and any of ($api*)
}

rule Persistence_DLL_Hijacking
{
    meta:
        description = "Detects DLL hijacking for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1574.001"

    strings:
        $dll1 = "version.dll" ascii wide nocase
        $dll2 = "dwmapi.dll" ascii wide nocase
        $dll3 = "cryptsp.dll" ascii wide nocase
        $dll4 = "cryptbase.dll" ascii wide nocase
        $dll5 = "secur32.dll" ascii wide nocase
        $dll6 = "propsys.dll" ascii wide nocase
        $dll7 = "ntmarta.dll" ascii wide nocase
        $dll8 = "linkinfo.dll" ascii wide nocase
        $dll9 = "ntshrui.dll" ascii wide nocase

        $path1 = "\\Windows\\System32\\" ascii wide
        $path2 = "\\Windows\\SysWOW64\\" ascii wide

        $proxy1 = "DllMain" ascii
        $proxy2 = "#pragma comment(linker" ascii
        $proxy3 = "LoadLibrary" ascii
        $proxy4 = "GetProcAddress" ascii

    condition:
        (2 of ($dll*)) and (any of ($path*) or 2 of ($proxy*))
}

rule Persistence_AppInit_DLLs
{
    meta:
        description = "Detects AppInit_DLLs abuse for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.010"

    strings:
        $key1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs" ascii wide nocase
        $key2 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs" ascii wide nocase
        $key3 = "LoadAppInit_DLLs" ascii wide

    condition:
        any of them
}

rule Persistence_Image_File_Execution
{
    meta:
        description = "Detects Image File Execution Options abuse"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.012"

    strings:
        $key1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase
        $key2 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase

        $val1 = "Debugger" ascii wide
        $val2 = "GlobalFlag" ascii wide
        $val3 = "VerifierDlls" ascii wide

    condition:
        any of ($key*) and any of ($val*)
}

rule Persistence_COM_Hijacking
{
    meta:
        description = "Detects COM object hijacking for persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1546.015"

    strings:
        $key1 = "SOFTWARE\\Classes\\CLSID" ascii wide
        $key2 = "HKEY_CLASSES_ROOT\\CLSID" ascii wide
        $key3 = "InprocServer32" ascii wide
        $key4 = "LocalServer32" ascii wide
        $key5 = "TreatAs" ascii wide
        $key6 = "ScriptletURL" ascii wide

    condition:
        ($key1 or $key2) and (2 of ($key3, $key4, $key5, $key6))
}

rule Persistence_Bootkit_Indicators
{
    meta:
        description = "Detects bootkit/rootkit persistence indicators"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1542"

    strings:
        $mbr1 = "\\Device\\Harddisk0\\DR0" ascii wide
        $mbr2 = "\\PhysicalDrive0" ascii wide
        $mbr3 = "\\DosDevices\\PhysicalDrive0" ascii wide

        $api1 = "NtCreateFile" ascii
        $api2 = "DeviceIoControl" ascii
        $api3 = "IOCTL_DISK_GET_DRIVE_GEOMETRY" ascii

        $boot1 = "bootmgr" ascii wide nocase
        $boot2 = "winload" ascii wide nocase
        $boot3 = "BOOTMGFW.EFI" ascii wide nocase

    condition:
        (any of ($mbr*) and any of ($api*)) or (2 of ($boot*) and any of ($api*))
}

rule Persistence_Winlogon_Helper
{
    meta:
        description = "Detects Winlogon helper DLL persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1547.004"

    strings:
        $key1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $val1 = "Shell" ascii wide
        $val2 = "Userinit" ascii wide
        $val3 = "Notify" ascii wide
        $val4 = "System" ascii wide

    condition:
        $key1 and any of ($val*)
}

rule Persistence_Office_Startup
{
    meta:
        description = "Detects Office startup folder/template persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1137.001"

    strings:
        $path1 = "\\Microsoft\\Word\\STARTUP" ascii wide
        $path2 = "\\Microsoft\\Excel\\XLSTART" ascii wide
        $path3 = "\\Microsoft\\Addins" ascii wide
        $path4 = "\\Microsoft\\Templates" ascii wide
        $path5 = "Normal.dotm" ascii wide
        $path6 = "Personal.xlsb" ascii wide

    condition:
        any of them
}

rule Persistence_Print_Monitor
{
    meta:
        description = "Detects print monitor DLL persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1547.010"

    strings:
        $key1 = "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" ascii wide nocase
        $api1 = "AddMonitor" ascii
        $api2 = "AddPrintProcessor" ascii

    condition:
        $key1 or any of ($api*)
}
