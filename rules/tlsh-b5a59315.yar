rule Sightlines_tlsh_b5a59315_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b5a59315"
        date = "2026-10-30"
        campaign = "tlsh-b5a59315"
        family = ""
        hash = "1a6683564e1870afac3cd99268d71f40505c44258236b906ec73eb1b5761b454"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b5a59315.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2026 Tensionix, under the [Apache License 2.0](../LICENSE) (see also [NOTICE](../NOTICE)). \"Audion\"" ascii
        $s1 = "Third-party programs (Flowseal, zapret2, ByeDPI Manager) are downloaded from GitHub by your button a" ascii
        $s2 = "[GitHub](https://github.com/Tensionix/dpi-manager)" ascii
        $s3 = "| DNS | The modes GOOGLE, CLOUDFLARE, QUAD9, ADGUARD and OWN (servers and a DoH address in one line)" ascii
        $s4 = "One window for the programs that get round traffic blocking: **Zapret** (Flowseal), **zapret2** (bol" ascii
        $s5 = "| ZAPRET | Install and update Flowseal's package, run a strategy, the service, game and IPSet filter" ascii
        $s6 = "| CONFIGS | The configuration field and a cache of 200 entries (star - pin, cross - delete) |" ascii
        $s7 = "| BYEDPI | Install and update ByeDPI Manager, connect through the system proxy |" ascii
        $s8 = " ZAPRET, ZAPRET 2, BYEDPI, on the right the language, the theme and the font. A switch is a full swi" ascii
        $s9 = "| DIAGNOSTICS | The reasons why the bypass does not work, as a table with fixes |" ascii
        $s10 = "service, parameter tuning, DNS modes, a cache of 200 configurations with pins and deletion." ascii
        $s11 = "| ZAPRET 2 | Install, update and connect zapret2; the preset from its documentation in a field |" ascii
    condition:
        filesize < 1048576 and 12 of them
}
