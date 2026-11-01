rule Sightlines_c2_3f32a392_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-3f32a392"
        date = "2026-10-29"
        campaign = "c2-3f32a392"
        family = ""
        hash = "16454925fc2331d7537bb9fbabda31ea099e9dadc50c36fa75f3b0f76c88d089"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-3f32a392.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    $script:AppMutex = New-Object System.Threading.Mutex($true, 'Global\\ZapretControlGUI', [ref]$scr" ascii
        $s1 = "$tmp = Join-Path $env:TEMP ('zapret_upd_' + [Guid]::NewGuid().ToString('N'))" ascii
        $s2 = "      <Grid x:Name=\"BusyOverlay\" Background=\"#B3040705\" Visibility=\"Collapsed\" Margin=\"0,58,0,0\">" ascii
        $s3 = "    if ([string]::IsNullOrWhiteSpace($body)) { $body = 'domain.example.abc' }" ascii
        $s4 = "    try { [IO.File]::AppendAllText($script:LogFile, ('{0}  {1}{2}' -f (Get-Date -Format 'yyyy-MM-dd " ascii
        $s5 = "    if ($ui.TglUpd.IsChecked) { Set-Content -LiteralPath $flag -Value 'ENABLED' -Encoding ASCII; Log" ascii
        $s6 = "$ui.LnkTg.Add_Click({ try { Start-Process 'https://t.me/masiuniv' } catch {} })" ascii
        $s7 = "      <Grid x:Name=\"DialogOverlay\" Background=\"#99040705\" Visibility=\"Collapsed\">" ascii
        $s8 = "HH:mm:ss'), $msg, [Environment]::NewLine), [Text.Encoding]::UTF8) } catch {}" ascii
        $s9 = "11.5\" Foreground=\"{StaticResource TextMid}\" Margin=\"7,0,22,0\"/>" ascii
        $s10 = "$DotGlow.Color = [System.Windows.Media.ColorConverter]::ConvertFromString('#34D399')" ascii
        $s11 = "\" FontSize=\"12.5\" FontWeight=\"Medium\" Foreground=\"{StaticResource TextMid}\" Margin=\"7,0,0,0\"/>" ascii
    condition:
        filesize < 1048576 and 12 of them
}
