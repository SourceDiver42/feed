rule Sightlines_tlsh_ac4305cd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ac4305cd"
        date = "2026-10-28"
        campaign = "tlsh-ac4305cd"
        family = ""
        hash = "3ea06f0ee098b4823cb79599df3780e7f23cce52c19aac31d2a0d47efe33a5e9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ac4305cd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "boost::math::expint_continued_fraction<%1%>(unsigned,%1%)" ascii
        $s1 = "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z" ascii
        $s2 = "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ" ascii
        $s3 = "boost::math::expint_series<%1%>(unsigned,%1%)" ascii
        $s4 = "?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z" ascii
        $s5 = "boost::math::bessel_jy<%1%>(%1%,%1%) in temme_jy" ascii
        $s6 = "Cause unknown: error caused by bad argument with value %1%" ascii
        $s7 = "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ" ascii
        $s8 = "boost::math::bessel_ik<%1%>(%1%,%1%) in temme_ik" ascii
        $s9 = "?getloc@ios_base@std@@QEBA?AVlocale@2@XZ" ascii
        $s10 = "boost::math::sph_bessel_j_small_z_series<%1%>(%1%,%1%)" ascii
        $s11 = "Series evaluation exceeded %1% iterations, giving up now." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
