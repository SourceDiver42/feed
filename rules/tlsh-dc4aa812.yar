rule Sightlines_tlsh_dc4aa812_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dc4aa812"
        date = "2026-10-25"
        campaign = "tlsh-dc4aa812"
        family = ""
        hash = "0087739da28e1f670edb454af547a3153507bd0fa5ebeb019892b2c660bbaedb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dc4aa812.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dgdgfe`c`cba\\_\\_^]X[X[ZYTWTWVUPSPSRQLOLONMHKHKJIDGDGFE@C@CBA<?<?>=8;8;:9474765030321,/,/.-(+(+*)$'$'" ascii
        $s1 = "@Srqpmlkhgfcba_^][ZYWVUSRQONMKJIHGFEDCA@?=<;987543210/.-+*)'&%#\"!" ascii
        $s2 = "Cannot load `vkGetInstanceProcAddr` symbol from libraryPIPELINECOMMAND_BUFFERRENDER_PASSNOT_READYINS" ascii
        $s3 = "  gl_Position = vec4(TRIANGLE_POS[gl_VertexID], 0.0, 1.0);" ascii
        $s4 = ". As the device does not support `DownlevelFlags::BUFFER_BINDINGS_NOT_16_BYTE_ALIGNED`, the type mus" ascii
        $s5 = "urred, due to an implementation or application bugUNDEFINEDR4G4_UNORM_PACK8R4G4B4A4_UNORM_PACK16B4G4" ascii
        $s6 = "ed.HackRegularSourceFoundry: Hack: 2018Hack RegularVersion 3.003;[3114f1256]-release; ttfautohint (v" wide
        $s7 = "8 is not aligned to block size or `COPY_BUFFER_ALIGNMENT`" ascii
        $s8 = "DEVICEDESCRIPTOR_BUFFER_CAPTURE_REPLAY_EXTDESCRIPTOR_SETCommand completed successfullyA fence or que" ascii
        $s9 = "Punycode overflows should not be possible due to PUNYCODE_ENCODE_MAX_INPUT_LENGTH" ascii
        $s10 = "#(emptyvulkanmetaldx12glwebgpuREDGREENBLUEALPHACOLORALL" ascii
        $s11 = "v samples are supported by this format. With the TEXTURE_ADAPTER_SPECIFIC_FORMAT_FEATURES feature yo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 22767616 and 5 of them
}
