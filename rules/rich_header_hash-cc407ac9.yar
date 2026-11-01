rule Sightlines_rich_header_hash_cc407ac9_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-cc407ac9"
        date = "2026-11-01"
        campaign = "rich_header_hash-cc407ac9"
        family = "prometei"
        hash = "0cb4cfb991e82c52a7904bc6cee3c10eac1adb6bf84cbbfd0b2629d0aa35781a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-cc407ac9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Host Process for Windows Service" wide
        $s1 = "abnormal program termination" ascii
        $s2 = "- floating point not loaded" ascii
        $s3 = "GAIsProcessorFeaturePresent" ascii
        $s4 = "GetLogicalDriveStringsA" ascii
        $s5 = "Copyright (C) 2016" wide
        $s6 = "IsBadWritePtr" ascii
        $s7 = "IsBadCodePtr" ascii
        $s8 = "\\dH1#)AGp{2" ascii
        $s9 = "sqhost.exe" wide
        $s10 = "okmLCS[]<" ascii
        $s11 = "5 eDCV;," ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
