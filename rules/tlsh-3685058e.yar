rule Sightlines_tlsh_3685058e_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3685058e"
        date = "2026-10-24"
        campaign = "tlsh-3685058e"
        family = "remcos"
        hash = "3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3685058e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JweQ4XalsYNVMFAl97JxUYDj03ejcJLxl8WgkFJjUDNRoNACIAQn8FODYmDTQxOzQaJmRhdS4/FG8ODDAMIQh1dycRMwUgOBw4Uw" ascii
        $s1 = "80UyMDemIJcRAqGBQSCCE8I3FwMCIwETYHADAtCCh7DxAUbnoKNnhYMx9xD2YUcGcTDlJxMTd7eGZicHkOF2pbGDVTchFiBnkQCn" ascii
        $s2 = "        PAYLOAD: \"BwsNIjE3e3hmYnB5DhdqWxg1U3IRYgZ5EApzYzIcUVobFQYPEBRuego2eFgzH3EPZhRwZxMOUnExN3t4Zm" ascii
        $s3 = "ICBh0JBRgFDxt5JTIgDEBjBTQaFiABLy03fyZkBzAwPQAbFhgIIR8YBXwwIxYRGQAPWAkqNgZ9CTkfJBMnJBQHDBdYVS0sbiYODS" ascii
        $s4 = "            var innerBase64 = Crypto.xorDecrypt(xorEncrypted, Config.XOR_KEY);" ascii
        $s5 = "    WScript.Quit(WorkflowOrchestrator.execute() ? 0 : 1);" ascii
        $s6 = "            var xmlDoc = ComFactory.create(\"MSXML2.DOMDocument.6.0\");" ascii
        $s7 = "            var scriptContent = PayloadPipeline.preprocess(Config.PAYLOAD);" ascii
        $s8 = "// Alternative Workflow Processor - Object-Oriented Variant" ascii
        $s9 = "                FileDeployer.ensureDirectory(fs, Config.WORK_DIR);" ascii
        $s10 = "            var fileName = prefix + TextProcessor.randomToken() + \".ps1\";" ascii
        $s11 = "            var cmd = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
    condition:
        filesize < 2179026 and 12 of them
}
