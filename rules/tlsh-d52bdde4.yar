rule Sightlines_tlsh_d52bdde4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d52bdde4"
        date = "2026-10-28"
        campaign = "tlsh-d52bdde4"
        family = ""
        hash = "033e075426fe475870ccca9cc9caebdfb34206461ca900cecfb8cfa9ec5ff3df"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d52bdde4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s1 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
        $s2 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE" ascii
        $s3 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE" ascii
        $s4 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE" ascii
        $s5 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE" ascii
        $s6 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE" ascii
        $s7 = "basic_filebuf::underflow codecvt::max_length() is not valid" ascii
        $s8 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIwEE" ascii
        $s9 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIcEE" ascii
        $s10 = "*NSt13__facet_shims12_GLOBAL__N_112collate_shimIwEE" ascii
        $s11 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIcEE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3034112 and 11 of them
}
