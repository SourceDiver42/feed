rule Sightlines_imphash_8788d05d_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8788d05d"
        date = "2026-10-30"
        campaign = "imphash-8788d05d"
        family = "rustystealer"
        hash = "08b33500f347d31f5bebd70147c2a7be6ee7fd43ed486c2e881a86ced5e1fb28"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8788d05d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "g_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP" ascii
        $s1 = "ig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NO" ascii
        $s2 = "Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcde" ascii
        $s3 = "onfig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef" ascii
        $s4 = "_Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcd" ascii
        $s5 = "0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_P" ascii
        $s6 = "123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_PA" ascii
        $s7 = "fig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_N" ascii
        $s8 = "23456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_PAD" ascii
        $s9 = "nfig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_" ascii
        $s10 = "a_Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abc" ascii
        $s11 = "_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 30695448 and 12 of them
}
