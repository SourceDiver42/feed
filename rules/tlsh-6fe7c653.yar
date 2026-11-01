rule Sightlines_tlsh_6fe7c653_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6fe7c653"
        date = "2026-10-24"
        campaign = "tlsh-6fe7c653"
        family = ""
        hash = "018d084a2b65856a2f7fe978c8d006a245f4fa55c189782e01675c6043774882"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6fe7c653.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xN3t8aW1weQ4QYngYNVNyFW0JeRAKdGsRHFFaGxEJdwMpEyMHBwUGNnkTU10YCjINFzk+ODQZKVpQATQXDAs7ASILIydxaCckbQ4" ascii
        $s1 = "wZxQGcXExN3t8aW1weQ4QYngYMFMAD3xvOSMzfSsQHy9TKhIATBUIFCgILB4YORxwU2MTAWcNESUcBSRyMnNOcAsLdgRxBDcteyZ" ascii
        $s2 = "UVSokG3UkGw80BAcTY1UjLhA0MHN8Bi4sdXJ9ES80DRFxPC0wCQNbbgosBAMALRIiISAcYWsoCR10Jg0bURcHFglNDBNuMB4SeBU" ascii
        $s3 = "    var PAYLOAD_B64   = \"AAMuIjE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRRwZxQGcXE" ascii
        $s4 = "6IgAjDygsUncDKRN9AhV4WDMfdQBpFHBnFAZxcTE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRR" ascii
        $s5 = "    // STAGE 3: XOR (equivalent to XorDecryptor.decrypt)" ascii
        $s6 = "    // STAGE 9: top-level workflow (equivalent to WorkflowOrchestrator)" ascii
        $s7 = "                \"SELECT * FROM Win32_Process WHERE Name='powershell.exe' OR Name='pwsh.exe'\"" ascii
        $s8 = "    function runPowerShellAndWait(shell, fs, scriptPath) {" ascii
        $s9 = "            var doc = makeActiveX(\"MSXML2.DOMDocument.6.0\");" ascii
        $s10 = "        var innerB64 = xorDecode(xorCipher, XOR_KEY);" ascii
        $s11 = "    function killPowerShellByPath(scriptPath) {" ascii
    condition:
        filesize < 5507914 and 12 of them
}
