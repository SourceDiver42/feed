rule Sightlines_tlsh_dca7dcdc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dca7dcdc"
        date = "2026-10-23"
        campaign = "tlsh-dca7dcdc"
        family = ""
        hash = "5143aa3e277c58918935281938d99e668ed3bdddf80578b17a0ad16d4556bf15"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dca7dcdc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Mrgpcvkml\"amorngvgf\"qwaagqqdwnn{" ascii
        $s1 = "Dbttrddqb{{n7zxs~q~rs7erp~dcen9" ascii
        $s2 = "Amo1Amo5Amo;Amo\"Amo+Amo/AmoSAmo[AmoLAmoyAmoaAmo" ascii
        $s3 = "@mo0@mo3@mo8@mo?@mo,@moY@moE@mov@mo`@mo" ascii
        $s4 = "soo3soo:soo#soo'soo+sooSsooDsooqsooysoolsoo" ascii
        $s5 = "0looPhoo8loo)looXlooGlooyloojloo" ascii
        $s6 = "roo0roo7roo$rooQroo]rooNrooxrookroo" ascii
        $s7 = "aoo6aoo aoo'aoo@aooDaooGaooNaoo~aoo" ascii
        $s8 = "eoo2eoo:eoo#eoo.eooYeooFeooreoo~eoo" ascii
        $s9 = "ioo8ioo ioo)iooTioo_iooLiooxioodioo" ascii
        $s10 = "moo;moo'mooRmooZmooCmooNmooymoofmoo" ascii
        $s11 = "`oo4`oo#`oo^`ooC`ooJ`ooy`oo``ook`oo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3244032 and 12 of them
}
