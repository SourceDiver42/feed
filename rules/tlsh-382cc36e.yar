rule Sightlines_tlsh_382cc36e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-382cc36e"
        date = "2026-11-01"
        campaign = "tlsh-382cc36e"
        family = "mirai"
        hash = "000764ec08dd7412613a6335337696010bdd7026ef61b26dd19ea5ac6cb7d7e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-382cc36e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s4 = "qQSRVSWTXUYVZW[" ascii
        $s5 = "BcAR2a3f&g" ascii
        $s6 = "/s`miCWDX" ascii
        $s7 = "509=:efg`" ascii
        $s8 = "g3amA|1Qf" ascii
        $s9 = "h.d^cba|1" ascii
        $s10 = "5::=1fdef" ascii
        $s11 = ".-50efg`" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
