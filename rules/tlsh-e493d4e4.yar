rule Sightlines_tlsh_e493d4e4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e493d4e4"
        date = "2026-10-30"
        campaign = "tlsh-e493d4e4"
        family = ""
        hash = "568efea6410f079966fc0497c5b154955f0a7f7a3156b07c3725d62e29dd5c6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e493d4e4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    var http = new ActiveXObject('MSXML2.XMLHTTP');" ascii
        $s1 = "    var fs = new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s2 = "    var sh = new ActiveXObject('WScript.Shell');" ascii
        $s3 = "        var randPart = Math.random().toString(36).substring(2, 10);" ascii
        $s4 = "        var handle = fs.CreateTextFile(filePath, true);" ascii
        $s5 = "                return runPowerShell(script, config.directory);" ascii
        $s6 = "            writeFile(path, scriptContent);" ascii
        $s7 = "        var name = generateFileName();" ascii
        $s8 = "        handle.Write(content);" ascii
        $s9 = "    this.ScriptAPI = Api;" ascii
        $s10 = "    // Expose globally" ascii
    condition:
        filesize < 1048576 and 11 of them
}
