/*
    Tamandua EDR - ELF Analysis Rules
    Advanced detection using ELF module for Linux/Unix binary analysis.

    These rules detect malware based on ELF characteristics rather than
    just string patterns, making them more resilient to obfuscation.
*/

import "elf"
import "math"

// ============================================================================
// SUSPICIOUS ELF CHARACTERISTICS
// ============================================================================

rule ELF_Packed_UPX
{
    meta:
        description = "Detects UPX packed ELF binaries"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1027.002"

    strings:
        $upx1 = "UPX!"
        $upx2 = "$Info: This file is packed with the UPX"

    condition:
        elf.type == elf.ET_EXEC and
        (any of ($upx*) or
         for any i in (0..elf.number_of_sections - 1): (
            elf.sections[i].name == "UPX0" or
            elf.sections[i].name == "UPX1"
         ))
}

rule ELF_High_Entropy_Section
{
    meta:
        description = "Detects ELF with high entropy sections (packed/encrypted)"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1027.002"

    condition:
        elf.type == elf.ET_EXEC and
        for any i in (0..elf.number_of_sections - 1): (
            elf.sections[i].size > 1024 and
            math.entropy(elf.sections[i].offset, elf.sections[i].size) > 7.5
        )
}

rule ELF_No_Section_Headers
{
    meta:
        description = "Detects ELF without section headers (stripped/obfuscated)"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1027"

    condition:
        elf.type == elf.ET_EXEC and
        elf.number_of_sections == 0
}

rule ELF_Suspicious_Entry_Point
{
    meta:
        description = "Detects ELF with entry point outside .text section"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1055"

    condition:
        elf.type == elf.ET_EXEC and
        for all i in (0..elf.number_of_sections - 1): (
            elf.sections[i].name != ".text" or
            (elf.entry_point < elf.sections[i].address or
             elf.entry_point >= elf.sections[i].address + elf.sections[i].size)
        )
}

rule ELF_Writable_Text_Section
{
    meta:
        description = "Detects ELF with writable .text section (self-modifying code)"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1027"

    condition:
        elf.type == elf.ET_EXEC and
        for any i in (0..elf.number_of_sections - 1): (
            elf.sections[i].name == ".text" and
            (elf.sections[i].flags & elf.SHF_WRITE) != 0
        )
}

// ============================================================================
// LINUX MALWARE PATTERNS
// ============================================================================

rule ELF_Reverse_Shell
{
    meta:
        description = "Detects potential reverse shell in ELF binary"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1059.004"

    strings:
        $socket = "socket" ascii
        $connect = "connect" ascii
        $dup2 = "dup2" ascii
        $execve = "execve" ascii
        $fork = "fork" ascii

        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $shell3 = "/bin/zsh" ascii

        $sh_flag = "-i" ascii
        $sh_cmd1 = "sh -i" ascii
        $sh_cmd2 = "bash -i" ascii

    condition:
        elf.type == elf.ET_EXEC and
        $socket and $connect and $dup2 and
        ($execve or $fork) and
        (any of ($shell*) or any of ($sh_*))
}

rule ELF_Crypto_Miner
{
    meta:
        description = "Detects cryptocurrency miner patterns in ELF"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1496"

    strings:
        $pool1 = "stratum+tcp://" ascii
        $pool2 = "stratum+ssl://" ascii
        $pool3 = "pool.minexmr.com" ascii
        $pool4 = "xmr.pool.minergate" ascii
        $pool5 = "monerohash.com" ascii

        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $algo3 = "ethash" ascii nocase

        $miner1 = "xmrig" ascii nocase
        $miner2 = "ccminer" ascii nocase
        $miner3 = "bfgminer" ascii nocase
        $miner4 = "cpuminer" ascii nocase

    condition:
        elf.type == elf.ET_EXEC and
        (any of ($pool*) or any of ($miner*) or 2 of ($algo*))
}

rule ELF_Rootkit_Indicators
{
    meta:
        description = "Detects rootkit indicators in ELF binary"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1014"

    strings:
        // Kernel module patterns
        $km1 = "init_module" ascii
        $km2 = "cleanup_module" ascii
        $km3 = "module_init" ascii
        $km4 = "module_exit" ascii

        // Syscall hooking
        $hook1 = "sys_call_table" ascii
        $hook2 = "ia32_sys_call_table" ascii
        $hook3 = "__NR_" ascii

        // Process hiding
        $hide1 = "find_task_by_pid" ascii
        $hide2 = "remove_proc_entry" ascii
        $hide3 = "proc_root" ascii

        // Network hiding
        $net1 = "tcp4_seq_show" ascii
        $net2 = "udp4_seq_show" ascii

        // File hiding
        $file1 = "filldir" ascii
        $file2 = "iterate_dir" ascii
        $file3 = "getdents" ascii

    condition:
        elf.type == elf.ET_REL and  // Kernel module
        (2 of ($km*) and (any of ($hook*) or any of ($hide*) or any of ($net*)))
}

rule ELF_LD_PRELOAD_Hijack
{
    meta:
        description = "Detects LD_PRELOAD library injection patterns"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1574.006"

    strings:
        $preload1 = "LD_PRELOAD" ascii
        $preload2 = "/etc/ld.so.preload" ascii

        // Commonly hooked functions
        $hook1 = "readdir" ascii
        $hook2 = "readdir64" ascii
        $hook3 = "read" ascii
        $hook4 = "write" ascii
        $hook5 = "open" ascii
        $hook6 = "stat" ascii
        $hook7 = "lstat" ascii
        $hook8 = "fopen" ascii

        // dlsym for original function lookup
        $dlsym = "dlsym" ascii
        $rtld = "RTLD_NEXT" ascii

    condition:
        elf.type == elf.ET_DYN and  // Shared library
        any of ($preload*) and
        $dlsym and $rtld and
        3 of ($hook*)
}

rule ELF_Backdoor_SSH
{
    meta:
        description = "Detects SSH backdoor patterns"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1556.004"

    strings:
        $ssh1 = "ssh" ascii
        $ssh2 = "sshd" ascii
        $ssh3 = "authorized_keys" ascii
        $ssh4 = "id_rsa" ascii

        $pam1 = "pam_sm_authenticate" ascii
        $pam2 = "pam_unix" ascii

        $cred1 = "password" ascii nocase
        $cred2 = "PAM_AUTHTOK" ascii

        // Backdoor indicators
        $bd1 = "master_password" ascii nocase
        $bd2 = "backdoor" ascii nocase
        $bd3 = "skeleton_key" ascii nocase

    condition:
        elf.type == elf.ET_DYN and
        (any of ($ssh*) or any of ($pam*)) and
        (any of ($cred*) or any of ($bd*))
}

rule ELF_Bot_Client
{
    meta:
        description = "Detects botnet client indicators"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1071.001"

    strings:
        // IRC bot patterns
        $irc1 = "PING" ascii
        $irc2 = "PONG" ascii
        $irc3 = "PRIVMSG" ascii
        $irc4 = "JOIN #" ascii
        $irc5 = "NICK " ascii

        // DDoS capabilities
        $ddos1 = "syn_flood" ascii nocase
        $ddos2 = "udp_flood" ascii nocase
        $ddos3 = "http_flood" ascii nocase
        $ddos4 = "slowloris" ascii nocase
        $ddos5 = "amplification" ascii nocase

        // C2 communication
        $c2_1 = "HTTP/1." ascii
        $c2_2 = "User-Agent" ascii
        $c2_3 = "POST /" ascii
        $c2_4 = "GET /" ascii

        // Bot commands
        $cmd1 = ".ddos" ascii
        $cmd2 = ".attack" ascii
        $cmd3 = ".stop" ascii
        $cmd4 = ".update" ascii
        $cmd5 = ".download" ascii

    condition:
        elf.type == elf.ET_EXEC and
        (3 of ($irc*) or 2 of ($ddos*) or 3 of ($cmd*)) and
        any of ($c2_*)
}

rule ELF_Mirai_Variant
{
    meta:
        description = "Detects Mirai botnet variants"
        author = "Tamandua Security Team"
        severity = "critical"
        mitre_attack = "T1583.005"
        family = "Mirai"

    strings:
        $mirai1 = "/bin/busybox" ascii
        $mirai2 = "REPORT" ascii
        $mirai3 = "PING" ascii
        $mirai4 = "PONG" ascii
        $mirai5 = "DUP" ascii

        // Scanner patterns
        $scan1 = "23" ascii  // Telnet
        $scan2 = "2323" ascii
        $scan3 = "admin" ascii
        $scan4 = "root" ascii
        $scan5 = "password" ascii nocase

        // Kill strings
        $kill1 = "/proc/" ascii
        $kill2 = "/exe" ascii
        $kill3 = "killer" ascii

    condition:
        elf.type == elf.ET_EXEC and
        3 of ($mirai*) and
        3 of ($scan*) and
        2 of ($kill*)
}

// ============================================================================
// PERSISTENCE MECHANISMS
// ============================================================================

rule ELF_Cron_Persistence
{
    meta:
        description = "Detects cron-based persistence patterns"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1053.003"

    strings:
        $cron1 = "/etc/crontab" ascii
        $cron2 = "/etc/cron.d" ascii
        $cron3 = "/var/spool/cron" ascii
        $cron4 = "crontab -" ascii

        $schedule1 = "* * * * *" ascii
        $schedule2 = "@reboot" ascii
        $schedule3 = "@daily" ascii

    condition:
        elf.type == elf.ET_EXEC and
        2 of ($cron*) and any of ($schedule*)
}

rule ELF_Systemd_Persistence
{
    meta:
        description = "Detects systemd-based persistence patterns"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1543.002"

    strings:
        $svc1 = "/etc/systemd/system" ascii
        $svc2 = "/lib/systemd/system" ascii
        $svc3 = "systemctl enable" ascii
        $svc4 = "systemctl start" ascii

        $unit1 = "[Unit]" ascii
        $unit2 = "[Service]" ascii
        $unit3 = "ExecStart=" ascii
        $unit4 = "WantedBy=multi-user.target" ascii

    condition:
        elf.type == elf.ET_EXEC and
        (2 of ($svc*) or 3 of ($unit*))
}

rule ELF_Init_Persistence
{
    meta:
        description = "Detects init script-based persistence"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1037.004"

    strings:
        $init1 = "/etc/init.d" ascii
        $init2 = "/etc/rc.local" ascii
        $init3 = "/etc/rc.d" ascii
        $init4 = "update-rc.d" ascii
        $init5 = "chkconfig" ascii

        $rc1 = "#!/bin/sh" ascii
        $rc2 = "start)" ascii
        $rc3 = "stop)" ascii

    condition:
        elf.type == elf.ET_EXEC and
        2 of ($init*) and any of ($rc*)
}

// ============================================================================
// DEFENSE EVASION
// ============================================================================

rule ELF_Timestomping
{
    meta:
        description = "Detects timestamp manipulation capabilities"
        author = "Tamandua Security Team"
        severity = "medium"
        mitre_attack = "T1070.006"

    strings:
        $ts1 = "utimes" ascii
        $ts2 = "utime" ascii
        $ts3 = "futimens" ascii
        $ts4 = "utimensat" ascii
        $ts5 = "touch -" ascii

    condition:
        elf.type == elf.ET_EXEC and
        2 of them
}

rule ELF_Log_Clearing
{
    meta:
        description = "Detects log clearing capabilities"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1070.002"

    strings:
        $log1 = "/var/log/auth" ascii
        $log2 = "/var/log/secure" ascii
        $log3 = "/var/log/messages" ascii
        $log4 = "/var/log/syslog" ascii
        $log5 = "/var/log/wtmp" ascii
        $log6 = "/var/log/btmp" ascii
        $log7 = "/var/log/lastlog" ascii
        $log8 = ".bash_history" ascii

        $cmd1 = "truncate" ascii
        $cmd2 = "> /var/log" ascii
        $cmd3 = "rm -rf /var/log" ascii

    condition:
        elf.type == elf.ET_EXEC and
        (4 of ($log*) or any of ($cmd*))
}

rule ELF_Anti_Analysis
{
    meta:
        description = "Detects anti-analysis/anti-debugging techniques"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1622"

    strings:
        // Debugger detection
        $dbg1 = "ptrace" ascii
        $dbg2 = "PTRACE_TRACEME" ascii
        $dbg3 = "/proc/self/status" ascii

        // VM detection
        $vm1 = "hypervisor" ascii
        $vm2 = "vmware" ascii nocase
        $vm3 = "virtualbox" ascii nocase
        $vm4 = "qemu" ascii nocase
        $vm5 = "/sys/class/dmi" ascii

        // Sandbox detection
        $sb1 = "strace" ascii
        $sb2 = "ltrace" ascii
        $sb3 = "gdb" ascii

    condition:
        elf.type == elf.ET_EXEC and
        (($dbg1 and $dbg2) or 2 of ($vm*) or 2 of ($sb*))
}
