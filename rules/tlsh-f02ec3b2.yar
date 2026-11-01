rule Sightlines_tlsh_f02ec3b2_nanocore
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f02ec3b2"
        date = "2026-11-01"
        campaign = "tlsh-f02ec3b2"
        family = "nanocore"
        hash = "17ed40dea218bde06337f32e3d3443d07fd24cad9b0da82d6d890716ac6308ff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f02ec3b2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "#=qtlZnL8mho$rv1eTFz0Mw9UYFC_yCabEZ0xtVePn6wR5aSHE7ti3UfKg2l7D0_xk8" ascii
        $s1 = "#=qgbI51haY38WJ4NumXDqnLC_uKv$aRHAyD63c9HgGYzlsFjikAASqT8RCSswEMouz" ascii
        $s2 = "#=qF4e058OW__NtTzhWOs1UXEJiHrTSwnIZ3q2u9UaLbo49AZaoog8nMfoDeA9BGVvy" ascii
        $s3 = "#=qVCHxDTr$$bwFMb6i9vBKRZciaa69edA3gsLNOty0RAzCorWRBUh2v0PgySYBEvZ0" ascii
        $s4 = "#=qCGokdf0OOxeMJLDkXSfc3NPmwygIQ29RjKQWj$wbNGB9C1pPgma_891QiNyTRXcA" ascii
        $s5 = "#=qK4wGebauvtmTKO0oAyLFzHLhr9rU3HNJmU_ur7Zop$YvLzV4HzmIQ45YslW_q1Vc" ascii
        $s6 = "#=qXjNBjXFhVcOvrRAG8alfq96_gJ4jOa0wwNOaztY3QjLWnMT6wXGDzBnHuUkef5N0" ascii
        $s7 = "#=qyEH54IW$f9fUJb7FOR8r3vj6e$onLGrpm2VGycjbl9TZJEqkwtA4y4bL9ExOWpiA" ascii
        $s8 = "#=q3TG8MLoZf1Y44PREVW$6m76IGmuYE_BOhC_OTjkQJFtYWwRtSeFqevP9hiteuLfz" ascii
        $s9 = "#=qQkx1bBZns8hPde7$PcvfUl2fAairj6t_H8ve7nJO2s3BIB3t7PXd4ZR9h0JHyxrX" ascii
        $s10 = "#=q6Aboe3ONIkez7GgqcdWPi0_vrT_i53_89HUeagGM6MThXvFkvl8hpSeHO1UJawKN" ascii
        $s11 = "#=qenWi8guqQrvoGB55djo0ka_844yTmViBn5_Fr2X6HAceO7AJErk_Rh7nfkfqtUbq" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
