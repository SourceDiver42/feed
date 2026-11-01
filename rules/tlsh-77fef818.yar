rule Sightlines_tlsh_77fef818_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-77fef818"
        date = "2026-10-25"
        campaign = "tlsh-77fef818"
        family = ""
        hash = "21b26e4435c0c6d8212ed91a5e70c13710d41faf912474d2d17ef21fa13ab361"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-77fef818.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "if ([System.Environment]::Is64BitProcess)" ascii
        $s1 = "[System.IO.Pipes.PipeOptions]::None);" ascii
        $s2 = "[Parameter( Position = 1 )]" ascii
        $s3 = "[Parameter( Position = 0)]" ascii
        $s4 = "[OutputType([Type])]" ascii
        $s5 = "return $false;" ascii
        $s6 = "return $null;" ascii
        $s7 = "} finally {" ascii
        $s8 = "    return" ascii
        $s9 = "catch {}" ascii
    condition:
        filesize < 1274118 and 10 of them
}
