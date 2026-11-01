rule Sightlines_imphash_34ef860b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-34ef860b"
        date = "2026-11-01"
        campaign = "imphash-34ef860b"
        family = ""
        hash = "4c53f3efa13abbfb3d49e3775b0ee53e4bff5287afdcc020d021006ef08fbaea"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-34ef860b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%LOCALAPPDATA%\\RuneLite\\jre;C:\\Users\\%USERNAME%\\AppData\\Local\\RuneLite\\jre;C:\\Program Files\\RuneLite" ascii
        $s1 = "com/google/common/hash/AbstractNonStreamingHashFunction$ExposedByteArrayOutputStream.classPK" ascii
        $s2 = "ch/qos/logback/core/rolling/SizeAndTimeBasedFNATP$Usage.classPK" ascii
        $s3 = "ch/qos/logback/core/joran/action/NestedComplexPropertyIA$1.classPK" ascii
        $s4 = "com/google/common/collect/FilteredEntryMultimap$AsMap$1EntrySetImpl$1.classPK" ascii
        $s5 = "com/google/common/hash/Murmur3_128HashFunction$Murmur3_128Hasher.classPK" ascii
        $s6 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$1.classPK" ascii
        $s7 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$2.classPK" ascii
        $s8 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$3.classPK" ascii
        $s9 = "org/slf4j/helpers/BasicMDCAdapter$1.classPK" ascii
        $s10 = "com/google/common/hash/LittleEndianByteArray$JavaLittleEndianBytes$1.classPK" ascii
        $s11 = "com/google/common/collect/FilteredEntryMultimap$AsMap$1EntrySetImpl.classPK" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5312762 and 12 of them
}
