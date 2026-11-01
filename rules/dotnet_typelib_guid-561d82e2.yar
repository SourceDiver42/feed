rule Sightlines_dotnet_typelib_guid_561d82e2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-561d82e2"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-561d82e2"
        family = ""
        hash = "0f0bdd9f64eea46f1e78279189cc709473c10b1a5b5e405c42791a8babfd4811"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-561d82e2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "`Gets or sets the SWN p value (probability of casual) for switching algorithm (Floyd 0--p--1 BFS)" ascii
        $s2 = "CThe third parameter of the distribution (shape c, xMin, xMax, k, v)" ascii
        $s3 = "]The probability of transmission per single sexual intercourse from Male to Male, (homosexual)" ascii
        $s4 = "2The fourth parameter of the distribution (xMax, w)" ascii
        $s5 = "7Is the group's population (graph vertices) initialised." ascii
        $s6 = "%System.Globalization.NumberFormatInfo!" ascii
        $s7 = "jThe second parameter of the distribution. (scale b, shape c, xMin, xMax, degree of freedom df, d, p" ascii
        $s8 = "_Gets or sets the maximum size for numerical calculation of the network efficiency (path length)" ascii
        $s9 = "]Gets or sets the number of initial infected individuals for Temporal and Conditional warm-up." ascii
        $s10 = "VGets or sets the probability of concurrent partnerships during the simulation warm-up." ascii
        $s11 = "2Gets or Sets the simulation warm-up configuration." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5315584 and 12 of them
}
