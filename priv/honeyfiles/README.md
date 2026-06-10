# Honeyfile Templates

Do not commit generated honeyfiles or static decoy credentials in this directory.

Tamandua should create deception artifacts at runtime through
`TamanduaServer.Deception.BreadcrumbGenerator`, so each deployment receives
unique canary values and no repository snapshot contains material that looks like
live credentials, private keys, wallets, VPN profiles, or database dumps.

If a test needs a fixture, keep it under the test tree with clearly fake content
and avoid provider-specific secret formats that trigger scanners as real keys.
