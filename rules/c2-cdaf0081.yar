rule Sightlines_c2_cdaf0081_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-cdaf0081"
        date = "2026-10-30"
        campaign = "c2-cdaf0081"
        family = ""
        hash = "16b57b99dc934f4d30b42fecf04c82c716136759e2a85baba4d8fcc528ef4599"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-cdaf0081.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "for /f \"delims=\" %%A in ('powershell -NoProfile -Command \"(Invoke-WebRequest -Uri \\\"%GITHUB_VERSION_" ascii
        $s1 = "    call :PrintRed \"https://github.com/ValdikSS/GoodbyeDPI/issues/541#issuecomment-2661670982\"" ascii
        $s2 = "ACTIVE_*') { Write-Output ('FAKE' + [char]124 + $file.BaseName + [char]124 + (Get-FileHash -LiteralP" ascii
        $s3 = "sc create %SRVCNAME% binPath= \"\\\"%BIN_PATH%winws.exe\\\" !ARGS!\" DisplayName= \"zapret\" start= auto" ascii
        $s4 = "set \"GITHUB_VERSION_URL=https://raw.githubusercontent.com/boymep/zapret/main/.service/version.txt\"" ascii
        $s5 = "URL%\\\" -Headers @{\\\"Cache-Control\\\"=\\\"no-cache\\\"} -UseBasicParsing -TimeoutSec 5).Content.Trim()\" 2^" ascii
        $s6 = "char]124 + (Get-FileHash -LiteralPath $item.Name -Algorithm SHA256).Hash) } }; $files = @(Get-ChildI" ascii
        $s7 = "powershell -NoProfile -Command \"if ('%~dp0' -match '[\\u0430-\\u044F\\u0410-\\u042F\\u0451\\u0401]') { exi" ascii
        $s8 = "echo Changing ports for %~1 (example: 1024-1934,1936-65535, default: 1024-65535)" ascii
        $s9 = "set \"GITHUB_DOWNLOAD_URL=https://github.com/boymep/zapret/releases/latest\"" ascii
        $s10 = "for /f \"delims=\" %%a in ('powershell -NoProfile -Command \"Get-ChildItem -Recurse -Path 'HKLM:System\\" ascii
        $s11 = "{ $_.DohFlags -gt 0 } | Measure-Object | Select-Object -ExpandProperty Count\"') do (" ascii
    condition:
        filesize < 1048576 and 12 of them
}
