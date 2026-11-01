rule Sightlines_imphash_c7478a25_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c7478a25"
        date = "2026-10-28"
        campaign = "imphash-c7478a25"
        family = ""
        hash = "086e083da4e7a46438aff3188beb2c0d14cb38af216c62a880cd8209dfcfcca8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c7478a25.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV_Null_resource@?1??null_memory_resource@@YAPEAVmemory_resource@pmr@std@@XZ@" ascii
        $s1 = ".?AV_Unaligned_new_delete_resource_impl@pmr@std@@" ascii
        $s2 = ".?AV_Aligned_new_delete_resource_impl@pmr@std@@" ascii
        $s3 = ".?AV_Identity_equal_resource@pmr@std@@" ascii
        $s4 = "_Unaligned_get_default_resource" ascii
        $s5 = "_Unaligned_set_default_resource" ascii
        $s6 = ".?AVmemory_resource@pmr@std@@" ascii
        $s7 = "_Aligned_get_default_resource" ascii
        $s8 = "_Aligned_set_default_resource" ascii
        $s9 = " C Runtime Library _1" wide
        $s10 = "MSVCP140_1.dll" ascii
        $s11 = "msvcp140_1.dll" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
