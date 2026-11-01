rule Sightlines_contacted_0ad9e3c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0ad9e3c5"
        date = "2026-10-31"
        campaign = "contacted-0ad9e3c5"
        family = ""
        hash = "1a6accff44320788df5d4aaa5befd1aa524ca24715f76155eaf9558b5acdb0d0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0ad9e3c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"10.0.0.0\" processorArchitecture=\"amd64\" name=\"Contoso.BackgroundUpdate\"" ascii
        $s1 = "      <supportedOS Id=\"{4f476546-937d-4f2f-b4bf-9f40a04d5b62}\"/>" ascii
        $s2 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s3 = "  <description>Background Update Service</description>" ascii
        $s4 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s5 = "Partial loss of significance (PLOSS)" ascii
        $s6 = "Total loss of significance (TLOSS)" ascii
        $s7 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s8 = "Overflow range error (OVERFLOW)" ascii
        $s9 = "Argument domain error (DOMAIN)" ascii
        $s10 = "Argument singularity (SIGN)" ascii
        $s11 = "NtAllocateVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11019884 and 12 of them
}
