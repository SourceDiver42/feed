rule Sightlines_tlsh_2b6f5268_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2b6f5268"
        date = "2026-10-31"
        campaign = "tlsh-2b6f5268"
        family = ""
        hash = "2da76eb281740be485b5637da8c60fe0ce12bc2848d1a1a81ce144fa74313e18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2b6f5268.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "NSystem.IO.Compression.ZipFileExtensions+<ExtractRelativeToDirectoryAsync>d__20" ascii
        $s1 = "<System.IO.Compression.ZipFile+<ExtractToDirectoryAsync>d__42" ascii
        $s2 = "<System.IO.Compression.ZipFile+<ExtractToDirectoryAsync>d__46" ascii
        $s3 = "ASystem.IO.Compression.ZipFileExtensions+<ExtractToFileAsync>d__19" ascii
        $s4 = "GSystem.IO.Compression.ZipFile+<CreateZipArchiveFromDirectoryAsync>d__30" ascii
        $s5 = "FSystem.IO.Compression.ZipFileExtensions+<ExtractToDirectoryAsync>d__11" ascii
        $s6 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s7 = "?System.IO.Compression.ZipFile+<DoCreateFromDirectoryAsync>d__28" ascii
        $s8 = "?System.IO.Compression.ZipFile+<DoCreateFromDirectoryAsync>d__29" ascii
        $s9 = "HSystem.IO.Compression.ZipFileExtensions+<DoCreateEntryFromFileAsync>d__7" ascii
        $s10 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s11 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
