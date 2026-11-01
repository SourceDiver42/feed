rule Sightlines_tlsh_017d8eba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-017d8eba"
        date = "2026-10-30"
        campaign = "tlsh-017d8eba"
        family = ""
        hash = "067c014bc24afd9ad3efed7acaf6616bc6e5133d852bc0da20954f99f2b82b8d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-017d8eba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xN3t8aW1weQ4QYngYNVMFBlB0JxUYCTUUejcJLx1zVQkFJjILFhoNACIETXAFBjUgPwc9OFEdLnB8EiwHdxh0KykxOycLDScSCXE" ascii
        $s1 = "wEAc1cQMoGgkAY24aMDwpByYRUil+JnFrNhptDjoiDwkTEjx7UhkYDCwbBgYXASUXUVgXdTInPAwGIgoZKVtUDjk7HBBxEjYxGhx" ascii
        $s2 = "    var PAYLOAD_B64   = \"AAMuIjE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRRwZxQGcXE" ascii
        $s3 = "8IB9UDw8UVlMQFG59AhV4WDMfdQBpFHBnFAZxcTE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRR" ascii
        $s4 = "    // STAGE 3: XOR (equivalent to XorDecryptor.decrypt)" ascii
        $s5 = "    // STAGE 9: top-level workflow (equivalent to WorkflowOrchestrator)" ascii
        $s6 = "                \"SELECT * FROM Win32_Process WHERE Name='powershell.exe' OR Name='pwsh.exe'\"" ascii
        $s7 = "    function runPowerShellAndWait(shell, fs, scriptPath) {" ascii
        $s8 = "            var doc = makeActiveX(\"MSXML2.DOMDocument.6.0\");" ascii
        $s9 = "        var innerB64 = xorDecode(xorCipher, XOR_KEY);" ascii
        $s10 = "    function killPowerShellByPath(scriptPath) {" ascii
        $s11 = "        var cmd = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
    condition:
        filesize < 5426666 and 12 of them
}
