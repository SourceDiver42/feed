rule Sightlines_contacted_f1a4ad7c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-f1a4ad7c"
        date = "2026-10-22"
        campaign = "contacted-f1a4ad7c"
        family = ""
        hash = "2a52182780bed76b574635a9aa621fb628e949d0f4d400c72cf49525edc6e96d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-f1a4ad7c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "NetworkIsolationGetAppContainerConfig" ascii
        $s1 = "NetworkIsolationSetAppContainerConfig" ascii
        $s2 = "NetworkIsolationEnumAppContainers" ascii
        $s3 = "NetworkIsolationFreeAppContainers" ascii
        $s4 = "FirewallAPI.pdb" ascii
        $s5 = "FirewallAPI.dll" ascii
        $s6 = "AWAVATVWUSf" ascii
        $s7 = "D$@H9D$0t" ascii
        $s8 = "AWAVATVWSL" ascii
        $s9 = "AWAVVWSfH" ascii
        $s10 = "AWAVVWUSI" ascii
        $s11 = "L$HH9L$8t" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 18285568 and 6 of them
}
