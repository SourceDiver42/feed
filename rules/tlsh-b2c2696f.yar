rule Sightlines_tlsh_b2c2696f_lxbaserat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b2c2696f"
        date = "2026-10-31"
        campaign = "tlsh-b2c2696f"
        family = "lxbaserat"
        hash = "48c873b27f253c7dc5a0b270bcd183f41dbcdcb3889e2f10e46d7ea22c043074"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b2c2696f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        var appData = shell.ExpandEnvironmentStrings(\"%LOCALAPPDATA%\");" ascii
        $s1 = "        var xmlPath = shell.ExpandEnvironmentStrings(\"%TEMP%\") + \"\\\\\" + Math.floor(Math.random() * 9" ascii
        $s2 = "            \"<Task version=\\\"1.2\\\" xmlns=\\\"http://schemas.microsoft.com/windows/2004/02/mit/task\\\">\"" ascii
        $s3 = "        var net = WScript.CreateObject(String.fromCharCode(87,83,99,114,105,112,116,46,78,101,116,11" ascii
        $s4 = "var fso   = new ActiveXObject(_axOpen.fsoName);" ascii
        $s5 = "        var tmpRoot = shell.ExpandEnvironmentStrings(\"%TEMP%\");" ascii
        $s6 = "            \"<Principals><Principal id=\\\"Author\\\"><UserId>\" + userAccount + \"</UserId><LogonType>Int" ascii
        $s7 = "var shell = new ActiveXObject(_axOpen.shellName);" ascii
        $s8 = "//  Generates outLen bytes from (masterKey, salt, info) using ChaCha20 blocks." ascii
        $s9 = "            \"<Settings><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><DisallowStartIfOnBatteries>fals" ascii
        $s10 = "esPolicy>IgnoreNew</MultipleInstancesPolicy><Enabled>true</Enabled><Hidden>true</Hidden></Settings>\"" ascii
        $s11 = "    var pB = String.fromCharCode(87,83,99,114,105,112,116,46,83,104,101,108,108);" ascii
    condition:
        filesize < 3980942 and 12 of them
}
