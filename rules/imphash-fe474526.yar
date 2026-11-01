rule Sightlines_imphash_fe474526_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fe474526"
        date = "2026-10-22"
        campaign = "imphash-fe474526"
        family = ""
        hash = "1d50b83cbb74f6f7ca0498005ae1391405766b67e20b9ea521a3fc8006826d87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fe474526.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D:\\Projects\\pay\\tools\\wework_loader_go\\downloads\\zstd-src\\zstd-1.5.6\\lib\\dictBuilder\\divsufsort.c" wide
        $s1 = "WARNING: The maximum dictionary size %u is too large compared to the source size %u! size(source)/si" ascii
        $s2 = "warning : ZSTD_compressBegin_usingCDict failed " ascii
        $s3 = "ze(dictionary) = %f, but it should be >= 10! This may lead to a subpar dictionary! We recommend trai" ascii
        $s4 = "?Draw@CxImage@@QAEJPAUHDC__@@JJJJPAUtagRECT@@_N@Z" ascii
        $s5 = "!  consider increasing the number of samples (total size : %u MB)" ascii
        $s6 = "FASTCOVER must have at least one input file" ascii
        $s7 = "ning on sources at least 10x, and preferably 100x the size of the dictionary! " ascii
        $s8 = "Selected dict at position %u, of length %u : saves %u (ratio: %.2f)  " ascii
        $s9 = "FSE_normalizeCount error with matchLengthCount " ascii
        $s10 = "!  warning : selected content significantly smaller than requested (%u < %u) " ascii
        $s11 = "ZSTD_CCtxParams_registerSequenceProducer" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1252352 and 12 of them
}
