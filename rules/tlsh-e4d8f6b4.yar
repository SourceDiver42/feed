rule Sightlines_tlsh_e4d8f6b4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e4d8f6b4"
        date = "2026-10-30"
        campaign = "tlsh-e4d8f6b4"
        family = ""
        hash = "295f3c135ff9aa98d95648bc3d3b240e1cd10bd5de1151dbd66081f882dcc2e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e4d8f6b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "call service.bat load_game_filter" ascii
        $s1 = "call service.bat check_updates" ascii
        $s2 = "call service.bat status_zapret" ascii
        $s3 = "set \"LISTS=%~dp0lists\\\"" ascii
        $s4 = "set \"BIN=%~dp0bin\\\"" ascii
        $s5 = "chcp 65001 > nul" ascii
        $s6 = "@echo off" ascii
    condition:
        filesize < 1048576 and 7 of them
}
