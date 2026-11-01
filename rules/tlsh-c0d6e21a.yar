rule Sightlines_tlsh_c0d6e21a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0d6e21a"
        date = "2026-10-30"
        campaign = "tlsh-c0d6e21a"
        family = ""
        hash = "38755d55e5e0fa9cc2cfbae58f45152099cb037ba4f8dcdbc269a7048d5ca550"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0d6e21a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        $best = @([System.IO.File]::ReadAllLines((Join-Path $Script:Runtime 'test-last.txt')) | Wher" ascii
        $s1 = "$wasRunning = (@(Get-OurProcesses).Count -gt 0) -or [bool](Get-OurService | Where-Object { $_.Status" ascii
        $s2 = "try { Start-Transcript -Path (Join-Path $Script:Runtime 'autotune-last.txt') -Force | Out-Null } cat" ascii
        $s3 = "    & (Join-Path $PSScriptRoot 'test.ps1') -NoPrompt -ReportOnly -Full" ascii
        $s4 = "if (-not $Force -and $before -and ((Get-Date) - $before).TotalDays -lt $Script:AutotuneDays) { exit " ascii
        $s5 = "$before = if (Test-Path $rankFile) { (Get-Item $rankFile).LastWriteTime } else { $null }" ascii
        $s6 = "    if ($wasRunning -and @(Get-OurProcesses).Count -eq 0) {" ascii
        $s7 = "$lock = Join-Path $Script:Runtime 'autotune.lock'" ascii
        $s8 = "if (Update-UpstreamCheck -Force:$Force) {" ascii
        $s9 = "if ($Force -or -not (Test-Path $ipsetFile) -or ((Get-Date) - (Get-Item $ipsetFile).LastWriteTime).To" ascii
        $s10 = "    $after = if (Test-Path $rankFile) { (Get-Item $rankFile).LastWriteTime } else { $null }" ascii
        $s11 = "$rankFile = Get-PkgPath $Script:RankFile" ascii
    condition:
        filesize < 1048576 and 12 of them
}
