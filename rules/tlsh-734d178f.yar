rule Sightlines_tlsh_734d178f_ironrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-734d178f"
        date = "2026-10-27"
        campaign = "tlsh-734d178f"
        family = "ironrat"
        hash = "47a9e572a1062abd16b0a0df256ba0c4b6b4660125844ca8ddbf22714f6beb30"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-734d178f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69a1e33" ascii
        $s1 = "WinHttpQueryDataAvailable" ascii
        $s2 = ".?AVGdiplusBase@Gdiplus@@" ascii
        $s3 = "internal query planner error" ascii
        $s4 = ".?AVBitmap@Gdiplus@@" ascii
        $s5 = ".?AVImage@Gdiplus@@" ascii
        $s6 = "WinHttpReceiveResponse" ascii
        $s7 = "WinHttpQueryHeaders" ascii
        $s8 = "WinHttpSendRequest" ascii
        $s9 = "WinHttpOpenRequest" ascii
        $s10 = "WinHttpReadData" ascii
        $s11 = "WinHttpConnect" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3369374 and 12 of them
}
