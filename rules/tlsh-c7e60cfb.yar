rule Sightlines_tlsh_c7e60cfb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c7e60cfb"
        date = "2026-10-20"
        campaign = "tlsh-c7e60cfb"
        family = ""
        hash = "e81352990490771d7ead9e1e6efe47e16cab5947cf0b265df8844d7eba827062"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c7e60cfb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2081792 and 4 of them
}
