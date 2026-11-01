rule Sightlines_tlsh_2099d4d6_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2099d4d6"
        date = "2026-10-28"
        campaign = "tlsh-2099d4d6"
        family = "formbook"
        hash = "1177b841f4fa387601d7abcd88439594ad58b361b090a79764152525f75378c0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2099d4d6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mCAsjIRkTdE0NKgt2GwQaDTp4DwxaCBIuJmB1LysKCQNcfhYqOhwAMSpTVywTCnMoIxYGPiIvUSgCPwkAEBRufQIVeFgzH3UAaRR" ascii
        $s1 = "    var PAYLOAD_B64   = \"c2U0ZyUyJC9pbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRRwZxQGcXE" ascii
        $s2 = "xN3t8aW1weQ4QYngYNVNyFW0JeRAKdGsRHFFaGxEJABAUbn0CFXhYMx91AH0RLzQNEQMZNBoJEWNuDnE9KQcmHCZaIx9+bzkJHQU" ascii
        $s3 = "wZxQGcXExN3t8aW1weQ4QYngYNVNyFW0JeRAKdGsRHFFaGxEJABAUbn0CFXhYMx91AGkUcGcUBnFxMTd7fGltcHkOEGJ4GDVTchV" ascii
        $s4 = "oCQsEDys4CAtRFwcWCU0ME24wHhJ4BjEcdFBjFxI1HgUQLzhQAXBacRI2BHcYKSsmCzscQHs0GQYWPiIlDQspBnhWES0YPggVEVE" ascii
        $s5 = "    // STAGE 3: XOR (equivalent to XorDecryptor.decrypt)" ascii
        $s6 = "    // STAGE 9: top-level workflow (equivalent to WorkflowOrchestrator)" ascii
        $s7 = "                \"SELECT * FROM Win32_Process WHERE Name='powershell.exe' OR Name='pwsh.exe'\"" ascii
        $s8 = "    function runPowerShellAndWait(shell, fs, scriptPath) {" ascii
        $s9 = "            var doc = makeActiveX(\"MSXML2.DOMDocument.6.0\");" ascii
        $s10 = "        var innerB64 = xorDecode(xorCipher, XOR_KEY);" ascii
        $s11 = "    function killPowerShellByPath(scriptPath) {" ascii
    condition:
        filesize < 5538146 and 12 of them
}
