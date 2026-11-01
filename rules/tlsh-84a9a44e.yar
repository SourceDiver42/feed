rule Sightlines_tlsh_84a9a44e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84a9a44e"
        date = "2026-10-29"
        campaign = "tlsh-84a9a44e"
        family = ""
        hash = "2f047890e3aa9e85a093351d291e0e1e6ac05ddef2148fa182a6ae548745fb5c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84a9a44e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  if ([System.Text.Encoding]::ASCII.GetString($mk) -ne 'GBZAP1') { $fs.Close(); exit 1 }" ascii
        $s1 = "  $shaShort = [BitConverter]::ToString($sha).Replace('-', '').Substring(0, 12).ToLower()" ascii
        $s2 = "  if ($needOut) { [System.IO.File]::WriteAllBytes($outExe, $payload) }" ascii
        $s3 = "    [System.IO.File]::WriteAllBytes($launchExe, $payload)" ascii
        $s4 = "    if ($needCache) { [System.IO.File]::WriteAllBytes($cacheExe, $payload) }" ascii
        $s5 = "    [System.IO.File]::WriteAllBytes($launchOut, $payload)" ascii
        $s6 = "  $fs = [System.IO.File]::OpenRead($HostPath)" ascii
        $s7 = "  $sha = [System.Security.Cryptography.SHA1]::Create().ComputeHash($payload)" ascii
        $s8 = "      [System.Text.UTF8Encoding]::new($false)" ascii
        $s9 = "    $existing = [System.IO.File]::ReadAllBytes($outExe)" ascii
        $s10 = "  [void]$fs.Seek($start, [System.IO.SeekOrigin]::Begin)" ascii
        $s11 = "  [void]$fs.Seek($n - 8, [System.IO.SeekOrigin]::Begin)" ascii
    condition:
        filesize < 1048576 and 12 of them
}
