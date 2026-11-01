rule Sightlines_tlsh_21588f40_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21588f40"
        date = "2026-10-30"
        campaign = "tlsh-21588f40"
        family = ""
        hash = "673796ea5cecdfac68f8a2895faf94136863d944dc176dc9cccf1efca5c180ad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21588f40.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_jdk_internal_jimage_NativeImageBuffer_getNativeMap" ascii
        $s1 = "Failure, expecting %llu but getting %llu" ascii
        $s2 = ".?AVSharedStringDecompressor@@" ascii
        $s3 = "JIMAGE_PackageToModule" ascii
        $s4 = ".?AVImageDecompressor@@" ascii
        $s5 = "JIMAGE_ResourceIterator" ascii
        $s6 = ".?AVZipDecompressor@@" ascii
        $s7 = "JIMAGE_FindResource" ascii
        $s8 = ".?AVSwappingEndian@@" ascii
        $s9 = "JIMAGE_GetResource" ascii
        $s10 = ".?AVNativeEndian@@" ascii
        $s11 = "ZIP_InflateFully" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
