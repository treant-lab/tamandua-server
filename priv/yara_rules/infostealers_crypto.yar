/*
    Tamandua EDR - Infostealer and Crypto Wallet Theft Detection Rules

    Covers: Lumma, Vidar, RedLine, Raccoon, Mars, Stealc, Rhadamanthys
    Focus: Web3 wallet extensions, browser credentials, session hijacking

    MITRE ATT&CK:
    - T1555.003 - Credentials from Web Browsers
    - T1539 - Steal Web Session Cookie
    - T1528 - Steal Application Access Token
    - T1056.001 - Keylogging
*/

// ============================================================================
// LUMMA STEALER FAMILY
// ============================================================================

rule Infostealer_Lumma_Strings
{
    meta:
        description = "Detects Lumma Stealer by unique string patterns"
        author = "Tamandua Security Team"
        author_pubkey = "TamDevBounty1111111111111111111111111111111"
        severity = "critical"
        family = "Lumma"
        mitre_attack = "T1555.003,T1539"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        date = "2026-05-08"

    strings:
        // Lumma-specific strings
        $lumma1 = "LummaC2" ascii wide nocase
        $lumma2 = "Lumma Stealer" ascii wide nocase
        $lumma3 = "lumma" ascii wide
        $lumma4 = "/c2config" ascii wide
        $lumma5 = "lid=" ascii  // Lumma ID parameter

        // Browser targeting
        $browser1 = "Login Data" ascii wide
        $browser2 = "Web Data" ascii wide
        $browser3 = "Cookies" ascii wide
        $browser4 = "Local State" ascii wide

        // Crypto wallet extensions (Chromium extension IDs)
        $wallet_metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $wallet_phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
        $wallet_solflare = "bhhhlbepdkbapadjdnnojkbgioiodbic" ascii wide
        $wallet_backpack = "aflkmfhebedbjioipglgcbcmnbpgliof" ascii wide
        $wallet_coinbase = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii wide
        $wallet_trust = "egjidjbpglichdcondbcbdnbeeppgdph" ascii wide
        $wallet_exodus = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii wide
        $wallet_brave = "odbfpeeihdkbihmopkbjmoonfanlbfcl" ascii wide

        // C2 communication patterns
        $c2_1 = "/api/data" ascii wide
        $c2_2 = "/gate.php" ascii wide
        $c2_3 = "hwid=" ascii wide
        $c2_4 = "build_id=" ascii wide

        // SQLite operations for credential theft
        $sql1 = "SELECT * FROM logins" ascii wide nocase
        $sql2 = "SELECT * FROM cookies" ascii wide nocase
        $sql3 = "SELECT * FROM autofill" ascii wide nocase
        $sql4 = "origin_url" ascii wide
        $sql5 = "password_value" ascii wide
        $sql6 = "encrypted_value" ascii wide

    condition:
        (any of ($lumma*)) or
        (3 of ($wallet_*) and 2 of ($browser*)) or
        (2 of ($sql*) and 2 of ($wallet_*)) or
        (2 of ($c2_*) and 2 of ($browser*))
}

rule Infostealer_Lumma_Config
{
    meta:
        description = "Detects Lumma Stealer configuration patterns"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Lumma"
        mitre_attack = "T1555.003"
        date = "2026-05-08"

    strings:
        // Config structure markers
        $cfg1 = "stealer_config" ascii wide
        $cfg2 = "grabber_config" ascii wide
        $cfg3 = "loader_config" ascii wide
        $cfg4 = "clipper_config" ascii wide

        // Target paths
        $path1 = "\\AppData\\Local\\Google\\Chrome" ascii wide
        $path2 = "\\AppData\\Local\\Microsoft\\Edge" ascii wide
        $path3 = "\\AppData\\Roaming\\Mozilla\\Firefox" ascii wide
        $path4 = "\\AppData\\Local\\BraveSoftware" ascii wide

        // Crypto-specific
        $crypto1 = "wallet.dat" ascii wide
        $crypto2 = ".solana" ascii wide
        $crypto3 = "solana-wallet" ascii wide
        $crypto4 = "phantom-wallet" ascii wide

    condition:
        (2 of ($cfg*) and 2 of ($path*)) or
        (2 of ($path*) and 2 of ($crypto*))
}

// ============================================================================
// VIDAR STEALER FAMILY
// ============================================================================

rule Infostealer_Vidar
{
    meta:
        description = "Detects Vidar Stealer"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Vidar"
        mitre_attack = "T1555.003,T1539"
        date = "2026-05-08"

    strings:
        $vidar1 = "Vidar" ascii wide nocase
        $vidar2 = "vidar_" ascii
        $vidar3 = "arkei" ascii wide nocase  // Vidar fork of Arkei

        // DLL dependencies
        $dll1 = "freebl3.dll" ascii wide
        $dll2 = "mozglue.dll" ascii wide
        $dll3 = "nss3.dll" ascii wide
        $dll4 = "softokn3.dll" ascii wide
        $dll5 = "sqlite3.dll" ascii wide
        $dll6 = "vcruntime140.dll" ascii wide

        // Browser paths
        $path1 = "\\User Data\\Default\\Login Data" ascii wide
        $path2 = "\\User Data\\Default\\Cookies" ascii wide
        $path3 = "\\User Data\\Default\\Web Data" ascii wide

        // Network patterns
        $net1 = "ip-api.com" ascii wide
        $net2 = "checkip" ascii wide
        $net3 = "/get_config" ascii wide

    condition:
        (any of ($vidar*)) or
        (4 of ($dll*) and 2 of ($path*)) or
        (2 of ($net*) and 3 of ($dll*))
}

// ============================================================================
// REDLINE STEALER FAMILY
// ============================================================================

rule Infostealer_RedLine
{
    meta:
        description = "Detects RedLine Stealer"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "RedLine"
        mitre_attack = "T1555.003,T1539"
        date = "2026-05-08"

    strings:
        $redline1 = "RedLine" ascii wide nocase
        $redline2 = "red_line" ascii wide
        $redline3 = "RedLineTask" ascii wide

        // .NET specific
        $net1 = "StringDecrypt" ascii
        $net2 = "RecordHeaderField" ascii
        $net3 = "FullInfoSender" ascii
        $net4 = "SystemInfoHelper" ascii

        // Target applications
        $app1 = "FileZilla" ascii wide
        $app2 = "Discord" ascii wide
        $app3 = "Telegram" ascii wide
        $app4 = "Steam" ascii wide
        $app5 = "NordVPN" ascii wide
        $app6 = "OpenVPN" ascii wide
        $app7 = "ProtonVPN" ascii wide

        // Crypto wallets
        $wallet1 = "Electrum" ascii wide
        $wallet2 = "Armory" ascii wide
        $wallet3 = "Atomic" ascii wide
        $wallet4 = "Jaxx" ascii wide
        $wallet5 = "Exodus" ascii wide
        $wallet6 = "Guarda" ascii wide

    condition:
        (any of ($redline*)) or
        (3 of ($net*)) or
        (4 of ($app*) and 2 of ($wallet*))
}

// ============================================================================
// RACCOON STEALER FAMILY
// ============================================================================

rule Infostealer_Raccoon
{
    meta:
        description = "Detects Raccoon Stealer v1/v2"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Raccoon"
        mitre_attack = "T1555.003,T1539"
        date = "2026-05-08"

    strings:
        $raccoon1 = "Raccoon" ascii wide nocase
        $raccoon2 = "raccoon_" ascii
        $raccoon3 = "machineId=" ascii wide

        // v2 specific
        $v2_1 = "RecordBreaker" ascii wide
        $v2_2 = "/aN7jD0qO6kT5bR5pCb" ascii  // Known v2 endpoint pattern

        // Telegram exfil
        $tg1 = "api.telegram.org" ascii wide
        $tg2 = "sendDocument" ascii wide
        $tg3 = "bot" ascii wide
        $tg4 = "chat_id" ascii wide

        // File patterns
        $file1 = "passwords.txt" ascii wide
        $file2 = "autofill.txt" ascii wide
        $file3 = "cookies.txt" ascii wide
        $file4 = "cards.txt" ascii wide
        $file5 = "screenshot.png" ascii wide

    condition:
        (any of ($raccoon*)) or
        (any of ($v2_*)) or
        (2 of ($tg*) and 2 of ($file*))
}

// ============================================================================
// RHADAMANTHYS STEALER
// ============================================================================

rule Infostealer_Rhadamanthys
{
    meta:
        description = "Detects Rhadamanthys Stealer"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Rhadamanthys"
        mitre_attack = "T1555.003,T1539,T1528"
        date = "2026-05-08"

    strings:
        $rhada1 = "Rhadamanthys" ascii wide nocase
        $rhada2 = "rhada" ascii wide nocase

        // Crypto clipboard hijacking
        $clip1 = "SetClipboardData" ascii
        $clip2 = "GetClipboardData" ascii
        $clip3 = "OpenClipboard" ascii

        // Crypto address patterns (regex-like)
        $btc = "bc1q" ascii wide  // Bitcoin bech32
        $eth = "0x" ascii wide    // Ethereum
        $sol = /[1-9A-HJ-NP-Za-km-z]{32,44}/ ascii  // Solana base58

        // Web3 targets
        $web3_1 = "ethereum" ascii wide nocase
        $web3_2 = "solana" ascii wide nocase
        $web3_3 = "binance" ascii wide nocase
        $web3_4 = "polygon" ascii wide nocase
        $web3_5 = "avalanche" ascii wide nocase

    condition:
        (any of ($rhada*)) or
        (all of ($clip*) and 2 of ($web3_*)) or
        (3 of ($web3_*) and $sol)
}

// ============================================================================
// STEALC STEALER
// ============================================================================

rule Infostealer_Stealc
{
    meta:
        description = "Detects Stealc Stealer (C-based, Vidar successor)"
        author = "Tamandua Security Team"
        severity = "critical"
        family = "Stealc"
        mitre_attack = "T1555.003,T1539"
        date = "2026-05-08"

    strings:
        $stealc1 = "Stealc" ascii wide nocase
        $stealc2 = "stealc_" ascii

        // Known C2 patterns
        $c2_1 = "/api/" ascii
        $c2_2 = "/gate/" ascii
        $c2_3 = "action=" ascii
        $c2_4 = "token=" ascii

        // Grabber modules
        $grab1 = "FileGrabber" ascii
        $grab2 = "CryptoGrabber" ascii
        $grab3 = "WalletGrabber" ascii
        $grab4 = "BrowserGrabber" ascii

    condition:
        (any of ($stealc*)) or
        (2 of ($c2_*) and 2 of ($grab*))
}

// ============================================================================
// GENERIC CRYPTO WALLET STEALER BEHAVIOR
// ============================================================================

rule Stealer_CryptoWallet_Generic
{
    meta:
        description = "Generic crypto wallet stealer behavior"
        author = "Tamandua Security Team"
        author_pubkey = "TamDevBounty1111111111111111111111111111111"
        severity = "high"
        mitre_attack = "T1528"
        date = "2026-05-08"

    strings:
        // Wallet file targets
        $wallet1 = "wallet.dat" ascii wide
        $wallet2 = "keystore" ascii wide
        $wallet3 = "wallets" ascii wide

        // Browser extension storage
        $ext1 = "Local Extension Settings" ascii wide
        $ext2 = "IndexedDB" ascii wide
        $ext3 = "leveldb" ascii wide

        // Solana-specific
        $sol1 = ".solana" ascii wide
        $sol2 = "id.json" ascii wide  // Solana keypair
        $sol3 = "solana_keypair" ascii wide
        $sol4 = "phantom" ascii wide nocase
        $sol5 = "solflare" ascii wide nocase
        $sol6 = "backpack" ascii wide nocase

        // Ethereum-specific
        $eth1 = "keystore/UTC" ascii wide
        $eth2 = "geth" ascii wide
        $eth3 = "metamask" ascii wide nocase

        // API operations
        $api1 = "private_key" ascii wide nocase
        $api2 = "mnemonic" ascii wide nocase
        $api3 = "seed_phrase" ascii wide nocase
        $api4 = "secret_key" ascii wide nocase

    condition:
        (2 of ($sol*) and 1 of ($api*)) or
        (2 of ($eth*) and 1 of ($api*)) or
        (2 of ($ext*) and 2 of ($wallet*)) or
        (3 of ($api*))
}

// ============================================================================
// SESSION HIJACKING (T1539)
// ============================================================================

rule Stealer_SessionHijack
{
    meta:
        description = "Detects session cookie/token stealing behavior"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1539"
        date = "2026-05-08"

    strings:
        // Session cookie patterns
        $cookie1 = "session_id" ascii wide nocase
        $cookie2 = "auth_token" ascii wide nocase
        $cookie3 = "access_token" ascii wide nocase
        $cookie4 = "refresh_token" ascii wide nocase
        $cookie5 = "JSESSIONID" ascii wide
        $cookie6 = ".AspNetCore.Session" ascii wide
        $cookie7 = "connect.sid" ascii wide

        // Browser cookie databases
        $db1 = "cookies.sqlite" ascii wide
        $db2 = "Cookies" ascii wide
        $db3 = "webappsstore.sqlite" ascii wide

        // Decryption APIs
        $decrypt1 = "CryptUnprotectData" ascii
        $decrypt2 = "BCryptDecrypt" ascii
        $decrypt3 = "AES-GCM" ascii wide
        $decrypt4 = "decrypt" ascii wide nocase

    condition:
        (3 of ($cookie*) and 1 of ($db*)) or
        (2 of ($db*) and 1 of ($decrypt*)) or
        (2 of ($decrypt*) and 2 of ($cookie*))
}

// ============================================================================
// DISCORD/TELEGRAM TOKEN STEALING
// ============================================================================

rule Stealer_DiscordToken
{
    meta:
        description = "Detects Discord token stealing"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1528"
        date = "2026-05-08"

    strings:
        // Discord paths
        $path1 = "\\discord\\Local Storage" ascii wide
        $path2 = "\\discordcanary\\Local Storage" ascii wide
        $path3 = "\\discordptb\\Local Storage" ascii wide

        // Token patterns
        $token1 = /[MN][A-Za-z\d]{23,27}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27}/ ascii
        $token2 = "dQw4w9WgXcQ" ascii  // Common validation pattern

        // LevelDB
        $leveldb1 = "leveldb" ascii wide
        $leveldb2 = ".ldb" ascii wide
        $leveldb3 = ".log" ascii wide

    condition:
        (2 of ($path*) and 1 of ($leveldb*)) or
        ($token1)
}

rule Stealer_TelegramSession
{
    meta:
        description = "Detects Telegram session stealing"
        author = "Tamandua Security Team"
        severity = "high"
        mitre_attack = "T1528"
        date = "2026-05-08"

    strings:
        // Telegram Desktop paths
        $path1 = "\\Telegram Desktop\\tdata" ascii wide
        $path2 = "tdata" ascii wide
        $path3 = "D877F783D5D3EF8C" ascii wide  // Known tdata folder

        // Session files
        $file1 = "map0" ascii wide
        $file2 = "map1" ascii wide
        $file3 = "key_datas" ascii wide

        // Encryption
        $enc1 = "passcode_key" ascii wide
        $enc2 = "encrypted_key" ascii wide

    condition:
        (2 of ($path*) and 1 of ($file*)) or
        (2 of ($file*) and 1 of ($enc*))
}
