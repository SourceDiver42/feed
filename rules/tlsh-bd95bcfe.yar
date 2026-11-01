rule Sightlines_tlsh_bd95bcfe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bd95bcfe"
        date = "2026-10-30"
        campaign = "tlsh-bd95bcfe"
        family = ""
        hash = "98635d214b33c5123136feccb41cd86c5ecb11355d3520ee1528795d867e9d3d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bd95bcfe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INFLATER_inflateFully: Compressed data corrupted" ascii
        $s1 = "INFLATER_inflateFully: Unexpected end of stream" ascii
        $s2 = "zlib returned Z_VERSION_ERROR: compile time and runtime zlib implementations differ" ascii
        $s3 = "ZIP_Read: corrupt zip file: invalid entry size" ascii
        $s4 = "invalid CEN header (bad compression method)" ascii
        $s5 = "Java_java_util_zip_CRC32_updateByteBuffer0" ascii
        $s6 = "invalid END header (bad central directory offset)" ascii
        $s7 = "Java_java_util_zip_Inflater_setDictionaryBuffer" ascii
        $s8 = "invalid END header (bad central directory size)" ascii
        $s9 = "Java_java_util_zip_Adler32_updateByteBuffer" ascii
        $s10 = "Java_java_util_zip_Deflater_setDictionaryBuffer" ascii
        $s11 = "unknown error in checkDeflateStatus, setParams case" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
