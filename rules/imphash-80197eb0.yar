rule Sightlines_imphash_80197eb0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-80197eb0"
        date = "2026-10-31"
        campaign = "imphash-80197eb0"
        family = ""
        hash = "4d174b78aa8b3516c7e3cec0355dfe9ae570894055c377d2e5565d077a9a7a1e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-80197eb0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\native\\net10.0-windows-Release-x64\\System.IO.Compression.Na" ascii
        $s1 = " deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler " ascii
        $s2 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
        $s3 = "tive\\System.IO.Compression.Native.pdb" ascii
        $s4 = "BrotliEncoderDestroyPreparedDictionary" ascii
        $s5 = "BrotliEncoderAttachPreparedDictionary" ascii
        $s6 = "BrotliSharedDictionaryDestroyInstance" ascii
        $s7 = "_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET" ascii
        $s8 = "BrotliSharedDictionaryCreateInstance" ascii
        $s9 = "CompressionNative_InflateReset2_" ascii
        $s10 = "BrotliDecoderSetMetadataCallbacks" ascii
        $s11 = "_ERROR_FORMAT_EXUBERANT_META_NIBBLE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1876512 and 12 of them
}
