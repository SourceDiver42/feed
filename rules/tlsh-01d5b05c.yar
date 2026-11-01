rule Sightlines_tlsh_01d5b05c_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01d5b05c"
        date = "2026-10-29"
        campaign = "tlsh-01d5b05c"
        family = "asyncrat"
        hash = "0aed713fcc46ad5d537aea9708d505eb2a1801df24f922d246f5a64c2bd67409"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01d5b05c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s1 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
        $s2 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE" ascii
        $s3 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE" ascii
        $s4 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE" ascii
        $s5 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE" ascii
        $s6 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE" ascii
        $s7 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIwEE" ascii
        $s8 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIcEE" ascii
        $s9 = "*NSt13__facet_shims12_GLOBAL__N_112collate_shimIwEE" ascii
        $s10 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIcEE" ascii
        $s11 = "NSt7__cxx119money_putIwSt19ostreambuf_iteratorIwSt11char_traitsIwEEEE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2302192 and 12 of them
}
