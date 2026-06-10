# Sigma Detection Rule TEMPLATES
# Run with: mix run priv/repo/seeds/sigma_rules.exs
#
# These are SYSTEM TEMPLATES that get copied to each organization.
# Organizations can customize their copies without affecting templates.
#
# Professional Sigma rules for detecting common attack techniques.
# Based on the Sigma rule specification (https://github.com/SigmaHQ/sigma)

alias TamanduaServer.Repo
alias TamanduaServer.Detection.SigmaRule

IO.puts("Seeding Sigma rule TEMPLATES (global)...")

sigma_templates = [
  # ============================================================================
  # CREDENTIAL ACCESS - T1003 (OS Credential Dumping)
  # ============================================================================

  %{
    name: "LSASS Memory Access via Mimikatz",
    description: "Detects Mimikatz-style access to LSASS memory for credential dumping",
    source: """
title: LSASS Memory Access via Mimikatz
id: 0d894093-71bc-43c3-8c4d-ecfc28dcf5d9
status: stable
author: Tamandua Security Team
date: 2024/01/15
modified: 2024/06/01
description: Detects Mimikatz-style LSASS memory access patterns indicating credential dumping attempts
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/gentilkiwi/mimikatz
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1410'
            - '0x1438'
            - '0x143a'
    filter_legitimate:
        SourceImage|endswith:
            - '\\wmiprvse.exe'
            - '\\svchost.exe'
            - '\\MsMpEng.exe'
            - '\\csrss.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate security software
    - Windows Defender Advanced Threat Protection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
    - mimikatz
    """,
    enabled: true,
    logsource: %{"category" => "process_access", "product" => "windows"},
    detection: %{
      "selection" => %{
        "TargetImage|endswith" => "\\lsass.exe",
        "GrantedAccess|contains" => ["0x1010", "0x1038", "0x1410", "0x1438", "0x143a"]
      },
      "filter_legitimate" => %{
        "SourceImage|endswith" => ["\\wmiprvse.exe", "\\svchost.exe", "\\MsMpEng.exe", "\\csrss.exe"]
      },
      "condition" => "selection and not filter_legitimate"
    },
    tags: ["credential-access", "T1003.001", "mimikatz", "lsass", "critical"]
  },

  %{
    name: "LSASS Process Dump via Comsvcs.dll",
    description: "Detects the use of comsvcs.dll MiniDump to dump LSASS process memory",
    source: """
title: LSASS Process Dump via Comsvcs.dll
id: a49fa4d5-11db-418c-8473-1e014a8dd462
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects usage of comsvcs.dll MiniDump export to dump LSASS memory - a common credential dumping technique
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://lolbas-project.github.io/lolbas/Libraries/Comsvcs/
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'
    selection_lsass:
        CommandLine|contains:
            - 'lsass'
            - '24'
    condition: selection_img and selection_cli and selection_lsass
falsepositives:
    - Very unlikely in legitimate usage
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
    - lolbas
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection_img" => %{
        "Image|endswith" => "\\rundll32.exe"
      },
      "selection_cli" => %{
        "CommandLine|contains|all" => ["comsvcs", "MiniDump"]
      },
      "selection_lsass" => %{
        "CommandLine|contains" => ["lsass", "24"]
      },
      "condition" => "selection_img and selection_cli and selection_lsass"
    },
    tags: ["credential-access", "T1003.001", "lolbas", "comsvcs", "critical"]
  },

  %{
    name: "SAM Database Access",
    description: "Detects access to the SAM database file which stores local account credentials",
    source: """
title: SAM Database Access
id: 4ff6c8d4-8c7a-4b9c-9a1c-7d8e9f0a1b2c
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects attempts to access the SAM database for credential extraction
references:
    - https://attack.mitre.org/techniques/T1003/002/
logsource:
    category: file_access
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\\SAM'
            - '\\SYSTEM'
            - '\\SECURITY'
        TargetFilename|endswith:
            - '\\config\\SAM'
            - '\\config\\SYSTEM'
    filter_system:
        Image|endswith:
            - '\\svchost.exe'
            - '\\lsass.exe'
    condition: selection and not filter_system
falsepositives:
    - Backup software
    - Legitimate admin tools
level: high
tags:
    - attack.credential_access
    - attack.t1003.002
    """,
    enabled: true,
    logsource: %{"category" => "file_access", "product" => "windows"},
    detection: %{
      "selection" => %{
        "TargetFilename|contains" => ["\\SAM", "\\SYSTEM", "\\SECURITY"]
      },
      "condition" => "selection and not filter_system"
    },
    tags: ["credential-access", "T1003.002", "sam", "registry"]
  },

  # ============================================================================
  # PROCESS INJECTION - T1055
  # ============================================================================

  %{
    name: "Process Injection via CreateRemoteThread",
    description: "Detects process injection using CreateRemoteThread API",
    source: """
title: Process Injection via CreateRemoteThread
id: 5b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects potential process injection via CreateRemoteThread API call
references:
    - https://attack.mitre.org/techniques/T1055/
logsource:
    category: create_remote_thread
    product: windows
detection:
    selection:
        SourceImage|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\cmd.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\mshta.exe'
            - '\\regsvr32.exe'
            - '\\rundll32.exe'
    filter_legitimate:
        TargetImage|endswith:
            - '\\svchost.exe'
        SourceImage|endswith:
            - '\\MsMpEng.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Some legitimate software may use this technique
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
    """,
    enabled: true,
    logsource: %{"category" => "create_remote_thread", "product" => "windows"},
    detection: %{
      "selection" => %{
        "SourceImage|endswith" => ["\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\mshta.exe"]
      },
      "condition" => "selection and not filter_legitimate"
    },
    tags: ["defense-evasion", "privilege-escalation", "T1055", "injection"]
  },

  %{
    name: "Process Hollowing Indicators",
    description: "Detects indicators of process hollowing technique",
    source: """
title: Process Hollowing Indicators
id: 6c6c6c6c-6c6c-6c6c-6c6c-6c6c6c6c6c6c
status: experimental
author: Tamandua Security Team
date: 2024/01/15
description: Detects process hollowing by monitoring for suspicious process creation patterns
references:
    - https://attack.mitre.org/techniques/T1055/012/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
        Image|endswith:
            - '\\svchost.exe'
            - '\\RuntimeBroker.exe'
            - '\\dllhost.exe'
    filter:
        ParentCommandLine|contains:
            - 'Windows\\System32'
            - 'Program Files'
    condition: selection and not filter
falsepositives:
    - Legitimate use by system administration tools
level: high
tags:
    - attack.defense_evasion
    - attack.t1055.012
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{
        "ParentImage|endswith" => ["\\cmd.exe", "\\powershell.exe"],
        "Image|endswith" => ["\\svchost.exe", "\\RuntimeBroker.exe", "\\dllhost.exe"]
      },
      "condition" => "selection and not filter"
    },
    tags: ["defense-evasion", "T1055.012", "process-hollowing"]
  },

  # ============================================================================
  # PERSISTENCE - T1547 (Boot or Logon Autostart Execution)
  # ============================================================================

  %{
    name: "Registry Run Key Modification",
    description: "Detects modification of registry Run keys for persistence",
    source: """
title: Registry Run Key Modification
id: 7d7d7d7d-7d7d-7d7d-7d7d-7d7d7d7d7d7d
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects modifications to registry Run keys commonly used for persistence
references:
    - https://attack.mitre.org/techniques/T1547/001/
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
            - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            - '\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
    filter_legitimate:
        Image|endswith:
            - '\\msiexec.exe'
            - '\\MsMpEng.exe'
        Details|contains:
            - 'Program Files'
            - 'Microsoft'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate software installation
    - Windows updates
level: medium
tags:
    - attack.persistence
    - attack.t1547.001
    """,
    enabled: true,
    logsource: %{"category" => "registry_set", "product" => "windows"},
    detection: %{
      "selection" => %{
        "TargetObject|contains" => [
          "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
          "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        ]
      },
      "condition" => "selection and not filter_legitimate"
    },
    tags: ["persistence", "T1547.001", "registry", "run-keys"]
  },

  %{
    name: "Scheduled Task Creation for Persistence",
    description: "Detects suspicious scheduled task creation that may indicate persistence",
    source: """
title: Scheduled Task Creation for Persistence
id: 8e8e8e8e-8e8e-8e8e-8e8e-8e8e8e8e8e8e
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects creation of scheduled tasks from suspicious locations or with suspicious parameters
references:
    - https://attack.mitre.org/techniques/T1053/005/
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\schtasks.exe'
        CommandLine|contains:
            - '/create'
    selection_suspicious:
        CommandLine|contains:
            - 'powershell'
            - 'cmd /c'
            - 'wscript'
            - 'cscript'
            - 'mshta'
            - 'AppData'
            - 'Temp'
            - 'ProgramData'
    condition: selection_tools and selection_suspicious
falsepositives:
    - Administrative scripts
    - Legitimate software installation
level: medium
tags:
    - attack.persistence
    - attack.execution
    - attack.t1053.005
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection_tools" => %{
        "Image|endswith" => "\\schtasks.exe",
        "CommandLine|contains" => "/create"
      },
      "selection_suspicious" => %{
        "CommandLine|contains" => ["powershell", "cmd /c", "AppData", "Temp"]
      },
      "condition" => "selection_tools and selection_suspicious"
    },
    tags: ["persistence", "execution", "T1053.005", "scheduled-task"]
  },

  %{
    name: "New Service Installation",
    description: "Detects new Windows service installation which may indicate persistence",
    source: """
title: New Service Installation
id: 9f9f9f9f-9f9f-9f9f-9f9f-9f9f9f9f9f9f
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects new service installation that may indicate persistence mechanism
references:
    - https://attack.mitre.org/techniques/T1543/003/
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter_legitimate:
        ServiceFileName|contains:
            - 'C:\\Program Files'
            - 'C:\\Windows\\System32'
    suspicious_paths:
        ServiceFileName|contains:
            - 'AppData'
            - 'Temp'
            - 'Users\\Public'
            - 'ProgramData'
    condition: selection and (not filter_legitimate or suspicious_paths)
falsepositives:
    - Legitimate software installation
level: medium
tags:
    - attack.persistence
    - attack.t1543.003
    """,
    enabled: true,
    logsource: %{"product" => "windows", "service" => "system"},
    detection: %{
      "selection" => %{"EventID" => 7045},
      "suspicious_paths" => %{
        "ServiceFileName|contains" => ["AppData", "Temp", "Users\\Public"]
      },
      "condition" => "selection and (not filter_legitimate or suspicious_paths)"
    },
    tags: ["persistence", "T1543.003", "service"]
  },

  # ============================================================================
  # DEFENSE EVASION - T1218 (Signed Binary Proxy Execution)
  # ============================================================================

  %{
    name: "Regsvr32 Scriptlet Execution",
    description: "Detects Regsvr32 used to execute scriptlets from remote URLs",
    source: """
title: Regsvr32 Scriptlet Execution
id: a0a0a0a0-a0a0-a0a0-a0a0-a0a0a0a0a0a0
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects the use of regsvr32 to execute COM scriptlets from remote URLs (Squiblydoo attack)
references:
    - https://attack.mitre.org/techniques/T1218/010/
    - https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\regsvr32.exe'
        CommandLine|contains:
            - '/s /n /u /i:'
            - 'scrobj.dll'
            - 'http://'
            - 'https://'
    condition: selection
falsepositives:
    - Unknown legitimate use cases
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.010
    - lolbas
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{
        "Image|endswith" => "\\regsvr32.exe",
        "CommandLine|contains" => ["/s /n /u /i:", "scrobj.dll", "http://", "https://"]
      },
      "condition" => "selection"
    },
    tags: ["defense-evasion", "T1218.010", "regsvr32", "lolbas"]
  },

  %{
    name: "MSHTA Execution",
    description: "Detects suspicious MSHTA execution patterns",
    source: """
title: MSHTA Execution
id: b1b1b1b1-b1b1-b1b1-b1b1-b1b1b1b1b1b1
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects suspicious mshta.exe execution that may indicate script execution or payload delivery
references:
    - https://attack.mitre.org/techniques/T1218/005/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\mshta.exe'
    selection_suspicious:
        CommandLine|contains:
            - 'javascript:'
            - 'vbscript:'
            - 'http://'
            - 'https://'
            - 'file://'
    condition: selection and selection_suspicious
falsepositives:
    - Legitimate HTA applications (rare)
level: high
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.005
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{"Image|endswith" => "\\mshta.exe"},
      "selection_suspicious" => %{
        "CommandLine|contains" => ["javascript:", "vbscript:", "http://", "https://"]
      },
      "condition" => "selection and selection_suspicious"
    },
    tags: ["defense-evasion", "execution", "T1218.005", "mshta"]
  },

  %{
    name: "Rundll32 Suspicious Execution",
    description: "Detects suspicious rundll32 execution patterns",
    source: """
title: Rundll32 Suspicious Execution
id: c2c2c2c2-c2c2-c2c2-c2c2-c2c2c2c2c2c2
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects suspicious rundll32.exe execution patterns commonly used for payload execution
references:
    - https://attack.mitre.org/techniques/T1218/011/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
    selection_suspicious:
        - CommandLine|contains:
            - 'javascript:'
            - 'http://'
            - 'https://'
            - ',DllRegisterServer'
            - 'shell32.dll,Control_RunDLL'
        - CommandLine|endswith:
            - '.dll'
        - ParentImage|endswith:
            - '\\outlook.exe'
            - '\\winword.exe'
            - '\\excel.exe'
    condition: selection and selection_suspicious
falsepositives:
    - Legitimate software using rundll32
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218.011
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{"Image|endswith" => "\\rundll32.exe"},
      "selection_suspicious" => %{
        "CommandLine|contains" => ["javascript:", "http://", ",DllRegisterServer"]
      },
      "condition" => "selection and selection_suspicious"
    },
    tags: ["defense-evasion", "T1218.011", "rundll32"]
  },

  # ============================================================================
  # EXECUTION - T1059 (Command and Scripting Interpreter)
  # ============================================================================

  %{
    name: "PowerShell Download Cradle",
    description: "Detects PowerShell download cradle patterns used for malware delivery",
    source: """
title: PowerShell Download Cradle
id: d3d3d3d3-d3d3-d3d3-d3d3-d3d3d3d3d3d3
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects common PowerShell download cradle patterns used to download and execute malware
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1105/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_download:
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'DownloadFile'
            - 'DownloadData'
            - 'WebClient'
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'curl '
            - 'wget '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
    condition: selection and selection_download
falsepositives:
    - Legitimate PowerShell scripts that download files
    - Software installation scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1105
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{"Image|endswith" => ["\\powershell.exe", "\\pwsh.exe"]},
      "selection_download" => %{
        "CommandLine|contains" => ["IEX", "DownloadString", "WebClient", "Invoke-WebRequest"]
      },
      "condition" => "selection and selection_download"
    },
    tags: ["execution", "T1059.001", "T1105", "powershell", "download-cradle"]
  },

  %{
    name: "PowerShell Encoded Command",
    description: "Detects PowerShell execution with encoded command",
    source: """
title: PowerShell Encoded Command
id: e4e4e4e4-e4e4-e4e4-e4e4-e4e4e4e4e4e4
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects PowerShell execution with encoded commands, often used to obfuscate malicious payloads
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1027/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec '
    condition: selection
falsepositives:
    - Some legitimate scripts use encoded commands
    - System Center Configuration Manager
level: medium
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
    - attack.t1027
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{
        "Image|endswith" => ["\\powershell.exe", "\\pwsh.exe"],
        "CommandLine|contains" => ["-enc", "-EncodedCommand", "-ec "]
      },
      "condition" => "selection"
    },
    tags: ["execution", "defense-evasion", "T1059.001", "T1027", "encoded"]
  },

  %{
    name: "Suspicious PowerShell Parameter Combinations",
    description: "Detects suspicious PowerShell parameter combinations often used by malware",
    source: """
title: Suspicious PowerShell Parameter Combinations
id: f5f5f5f5-f5f5-f5f5-f5f5-f5f5f5f5f5f5
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects suspicious PowerShell parameter combinations commonly used by malware to evade detection
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_bypass:
        CommandLine|contains:
            - '-nop'
            - '-noprofile'
            - '-w hidden'
            - '-windowstyle hidden'
            - '-sta'
            - '-ep bypass'
            - '-exec bypass'
            - '-executionpolicy bypass'
    condition: selection and selection_bypass
falsepositives:
    - Administrative scripts
    - Software deployment tools
level: medium
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{"Image|endswith" => ["\\powershell.exe", "\\pwsh.exe"]},
      "selection_bypass" => %{
        "CommandLine|contains" => ["-nop", "-w hidden", "-ep bypass", "-exec bypass"]
      },
      "condition" => "selection and selection_bypass"
    },
    tags: ["execution", "defense-evasion", "T1059.001", "bypass"]
  },

  # ============================================================================
  # LATERAL MOVEMENT - T1021
  # ============================================================================

  %{
    name: "PsExec Service Installation",
    description: "Detects PsExec service installation indicating lateral movement",
    source: """
title: PsExec Service Installation
id: 01010101-0101-0101-0101-010101010101
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects the installation of the PsExec service which indicates lateral movement using PsExec
references:
    - https://attack.mitre.org/techniques/T1021/002/
    - https://attack.mitre.org/techniques/T1570/
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains:
            - 'PSEXESVC'
            - 'PSEXEC'
            - 'PAExec'
            - 'RemCom'
    condition: selection
falsepositives:
    - Legitimate administrative use
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1570
    """,
    enabled: true,
    logsource: %{"product" => "windows", "service" => "system"},
    detection: %{
      "selection" => %{
        "EventID" => 7045,
        "ServiceName|contains" => ["PSEXESVC", "PSEXEC", "PAExec", "RemCom"]
      },
      "condition" => "selection"
    },
    tags: ["lateral-movement", "T1021.002", "T1570", "psexec"]
  },

  %{
    name: "Remote Service Creation",
    description: "Detects remote service creation via sc.exe which may indicate lateral movement",
    source: """
title: Remote Service Creation via SC
id: 12121212-1212-1212-1212-121212121212
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects sc.exe being used to create services on remote systems
references:
    - https://attack.mitre.org/techniques/T1021/002/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\sc.exe'
        CommandLine|contains|all:
            - 'create'
            - '\\\\'
    condition: selection
falsepositives:
    - Legitimate administrative activities
level: high
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1021.002
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{
        "Image|endswith" => "\\sc.exe",
        "CommandLine|contains|all" => ["create", "\\\\"]
      },
      "condition" => "selection"
    },
    tags: ["lateral-movement", "execution", "T1021.002", "sc.exe"]
  },

  # ============================================================================
  # EXFILTRATION - T1048
  # ============================================================================

  %{
    name: "Data Exfiltration via DNS",
    description: "Detects potential data exfiltration over DNS",
    source: """
title: Data Exfiltration via DNS
id: 23232323-2323-2323-2323-232323232323
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects potential DNS tunneling or data exfiltration via DNS by identifying unusually long DNS queries
references:
    - https://attack.mitre.org/techniques/T1048/
    - https://attack.mitre.org/techniques/T1071/004/
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|re: '^[a-zA-Z0-9]{30,}\\.'
    filter_legitimate:
        QueryName|endswith:
            - '.microsoft.com'
            - '.windows.com'
            - '.azure.com'
    condition: selection and not filter_legitimate
falsepositives:
    - Some CDNs use long subdomains
    - Legitimate services with encoded data in DNS
level: medium
tags:
    - attack.exfiltration
    - attack.command_and_control
    - attack.t1048
    - attack.t1071.004
    """,
    enabled: true,
    logsource: %{"category" => "dns_query", "product" => "windows"},
    detection: %{
      "selection" => %{"QueryName|re" => "^[a-zA-Z0-9]{30,}\\."},
      "condition" => "selection and not filter_legitimate"
    },
    tags: ["exfiltration", "command-and-control", "T1048", "T1071.004", "dns"]
  },

  # ============================================================================
  # IMPACT - T1486 (Data Encrypted for Impact)
  # ============================================================================

  %{
    name: "Ransomware File Extension Modification",
    description: "Detects mass file extension changes indicating ransomware activity",
    source: """
title: Ransomware File Extension Modification
id: 34343434-3434-3434-3434-343434343434
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects mass file extension modifications commonly associated with ransomware
references:
    - https://attack.mitre.org/techniques/T1486/
logsource:
    category: file_rename
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypted'
            - '.locky'
            - '.crypt'
            - '.lockbit'
            - '.conti'
            - '.ryuk'
            - '.blackcat'
            - '.alphv'
            - '.royal'
    condition: selection
falsepositives:
    - Very unlikely
level: critical
tags:
    - attack.impact
    - attack.t1486
    - ransomware
    """,
    enabled: true,
    logsource: %{"category" => "file_rename", "product" => "windows"},
    detection: %{
      "selection" => %{
        "TargetFilename|endswith" => [".encrypted", ".locked", ".crypted", ".lockbit", ".conti"]
      },
      "condition" => "selection"
    },
    tags: ["impact", "T1486", "ransomware", "critical"]
  },

  %{
    name: "Volume Shadow Copy Deletion",
    description: "Detects deletion of volume shadow copies often performed by ransomware",
    source: """
title: Volume Shadow Copy Deletion
id: 45454545-4545-4545-4545-454545454545
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects deletion of volume shadow copies which is a common ransomware technique to prevent recovery
references:
    - https://attack.mitre.org/techniques/T1490/
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    selection_wmic:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains|all:
            - 'shadowcopy'
            - 'delete'
    selection_powershell:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - 'Get-WmiObject Win32_ShadowCopy | Remove-WmiObject'
            - 'gwmi win32_shadowcopy | rwmi'
    condition: selection_vssadmin or selection_wmic or selection_powershell
falsepositives:
    - System administrators
level: critical
tags:
    - attack.impact
    - attack.t1490
    - ransomware
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection_vssadmin" => %{
        "Image|endswith" => "\\vssadmin.exe",
        "CommandLine|contains|all" => ["delete", "shadows"]
      },
      "selection_wmic" => %{
        "Image|endswith" => "\\wmic.exe",
        "CommandLine|contains|all" => ["shadowcopy", "delete"]
      },
      "condition" => "selection_vssadmin or selection_wmic or selection_powershell"
    },
    tags: ["impact", "T1490", "ransomware", "shadow-copy", "critical"]
  },

  # ============================================================================
  # DISCOVERY - T1082, T1083, T1057
  # ============================================================================

  %{
    name: "System Information Discovery",
    description: "Detects enumeration commands often used for reconnaissance",
    source: """
title: System Information Discovery
id: 56565656-5656-5656-5656-565656565656
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects system information discovery commands commonly used during reconnaissance
references:
    - https://attack.mitre.org/techniques/T1082/
    - https://attack.mitre.org/techniques/T1083/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'systeminfo'
            - 'hostname'
            - 'whoami /all'
            - 'net config'
            - 'net user'
            - 'net group'
            - 'net localgroup'
            - 'dsquery'
            - 'Get-ADUser'
            - 'Get-ADComputer'
    condition: selection
falsepositives:
    - Administrative scripts
    - Legitimate troubleshooting
level: low
tags:
    - attack.discovery
    - attack.t1082
    - attack.t1087
    """,
    enabled: true,
    logsource: %{"category" => "process_creation", "product" => "windows"},
    detection: %{
      "selection" => %{
        "CommandLine|contains" => ["systeminfo", "whoami /all", "net user", "net group"]
      },
      "condition" => "selection"
    },
    tags: ["discovery", "T1082", "T1087", "reconnaissance"]
  },

  # ============================================================================
  # COMMAND AND CONTROL - T1071, T1095
  # ============================================================================

  %{
    name: "Suspicious Outbound Connection to Rare Port",
    description: "Detects outbound connections to uncommon ports",
    source: """
title: Suspicious Outbound Connection to Rare Port
id: 67676767-6767-6767-6767-676767676767
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects outbound network connections to uncommon ports that may indicate C2 communication
references:
    - https://attack.mitre.org/techniques/T1571/
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationPort:
            - 4444
            - 5555
            - 6666
            - 7777
            - 8888
            - 9999
            - 1234
            - 31337
            - 12345
    filter_local:
        DestinationIp|startswith:
            - '10.'
            - '192.168.'
            - '172.16.'
            - '127.'
    condition: selection and not filter_local
falsepositives:
    - Custom applications using these ports
level: medium
tags:
    - attack.command_and_control
    - attack.t1571
    """,
    enabled: true,
    logsource: %{"category" => "network_connection", "product" => "windows"},
    detection: %{
      "selection" => %{
        "Initiated" => "true",
        "DestinationPort" => [4444, 5555, 6666, 7777, 8888, 9999, 31337]
      },
      "condition" => "selection and not filter_local"
    },
    tags: ["command-and-control", "T1571", "network", "rare-port"]
  },

  # ============================================================================
  # LINUX-SPECIFIC RULES
  # ============================================================================

  %{
    name: "Linux Suspicious Shell Execution",
    description: "Detects suspicious shell execution patterns on Linux systems",
    source: """
title: Linux Suspicious Shell Execution
id: 78787878-7878-7878-7878-787878787878
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects suspicious shell command execution patterns commonly used by attackers on Linux
references:
    - https://attack.mitre.org/techniques/T1059/004/
logsource:
    product: linux
    category: process_creation
detection:
    selection_base64:
        CommandLine|contains:
            - 'base64 -d'
            - 'base64 --decode'
    selection_download:
        CommandLine|contains:
            - 'curl '
            - 'wget '
        CommandLine|contains:
            - '| sh'
            - '| bash'
            - '| /bin/sh'
            - '| /bin/bash'
    selection_reverse_shell:
        CommandLine|contains:
            - '/dev/tcp/'
            - 'nc -e'
            - 'ncat -e'
            - 'bash -i'
            - 'python -c'
    condition: selection_base64 or selection_download or selection_reverse_shell
falsepositives:
    - Legitimate administrative scripts
level: high
tags:
    - attack.execution
    - attack.t1059.004
    - linux
    """,
    enabled: true,
    logsource: %{"product" => "linux", "category" => "process_creation"},
    detection: %{
      "selection_reverse_shell" => %{
        "CommandLine|contains" => ["/dev/tcp/", "nc -e", "bash -i"]
      },
      "condition" => "selection_base64 or selection_download or selection_reverse_shell"
    },
    tags: ["execution", "T1059.004", "linux", "reverse-shell"]
  },

  %{
    name: "Linux Credential Access via /etc/passwd or /etc/shadow",
    description: "Detects attempts to access Linux password files",
    source: """
title: Linux Credential Access
id: 89898989-8989-8989-8989-898989898989
status: stable
author: Tamandua Security Team
date: 2024/01/15
description: Detects attempts to read Linux password and shadow files
references:
    - https://attack.mitre.org/techniques/T1003/008/
logsource:
    product: linux
    category: file_access
detection:
    selection:
        TargetFilename:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/master.passwd'
    filter_system:
        Image:
            - '/usr/bin/passwd'
            - '/usr/sbin/useradd'
            - '/usr/sbin/usermod'
    condition: selection and not filter_system
falsepositives:
    - Legitimate user management tools
level: medium
tags:
    - attack.credential_access
    - attack.t1003.008
    - linux
    """,
    enabled: true,
    logsource: %{"product" => "linux", "category" => "file_access"},
    detection: %{
      "selection" => %{
        "TargetFilename" => ["/etc/passwd", "/etc/shadow"]
      },
      "condition" => "selection and not filter_system"
    },
    tags: ["credential-access", "T1003.008", "linux", "password"]
  }
]

# Helper to transform logsource map to individual fields
defmodule SeedHelpers do
  def transform_template(attrs) do
    logsource = Map.get(attrs, :logsource, %{})

    attrs
    |> Map.delete(:logsource)
    |> Map.put(:logsource_category, logsource["category"])
    |> Map.put(:logsource_product, logsource["product"])
    |> Map.put(:logsource_service, logsource["service"])
    |> Map.put(:is_system_template, true)
    |> Map.put(:organization_id, nil)
  end
end

# Insert/update templates
for template_attrs <- sigma_templates do
  # Transform logsource map to individual fields
  transformed = SeedHelpers.transform_template(template_attrs)

  case Repo.get_by(SigmaRule, name: transformed.name, is_system_template: true) do
    nil ->
      %SigmaRule{}
      |> SigmaRule.template_changeset(transformed)
      |> Repo.insert!()
      IO.puts("  Created template: #{transformed.name}")

    existing ->
      existing
      |> SigmaRule.template_changeset(transformed)
      |> Repo.update!()
      IO.puts("  Updated template: #{transformed.name}")
  end
end

# Summary
IO.puts("\n" <> String.duplicate("=", 71))
IO.puts("Sigma Rule TEMPLATES Seeding Summary:")
IO.puts("=" <> String.duplicate("=", 70))

by_tactic = sigma_templates
|> Enum.flat_map(fn template ->
  template.tags
  |> Enum.filter(&String.starts_with?(&1, "T"))
  |> Enum.map(&{&1, template.name})
end)
|> Enum.group_by(fn {technique, _} -> technique end)

IO.puts("\nTemplates by MITRE Technique:")
for {technique, rules} <- Enum.take(Enum.sort(by_tactic), 15) do
  IO.puts("  #{technique}: #{length(rules)} templates")
end

IO.puts("\nTotal Sigma rule TEMPLATES seeded: #{length(sigma_templates)}")
IO.puts("Note: These are system templates that organizations can copy and customize.")
IO.puts("Sigma rule TEMPLATES seeding complete!")
