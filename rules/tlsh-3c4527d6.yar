rule Sightlines_tlsh_3c4527d6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3c4527d6"
        date = "2026-10-30"
        campaign = "tlsh-3c4527d6"
        family = ""
        hash = "91a9cba11343143452576e51bfc6a407cfb2b0cfc5252dfa2ce8b800f92ee58f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3c4527d6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "multiLocalizedUnicodeType of len != 12 is not supported." ascii
        $s1 = "Unsupported number of channels for VCGT '%d'" ascii
        $s2 = "Wrong position of PCS. 1..255 expected, %d found." ascii
        $s3 = "Wrong number of profiles. 1..255 expected, %d found." ascii
        $s4 = "Too many input channels (%d channels, max=%d)" ascii
        $s5 = "Unsupported interpolation (%d->%d channels)" ascii
        $s6 = "LUT with different samples per dimension not suitable to be saved as LUT16" ascii
        $s7 = "(internal) %d Channels are not supported on PatchLUT" ascii
        $s8 = "Channel count doesn't match. Profile is corrupted" ascii
        $s9 = "(internal) Attempt to PatchLUT on non-lut stage" ascii
        $s10 = "Cannot save floating point data, CLUT are 8 or 16 bit only" ascii
        $s11 = "'%s' Inconsistent number of items: expected %d, got %d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
