rule Sightlines_dotnet_typelib_guid_3ca58c93_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-3ca58c93"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-3ca58c93"
        family = ""
        hash = "1fbf0c7a8e4c7371af8fc016b1e25099a78b673a42342f43367c42f98cb0c5b6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-3ca58c93.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "RegExPatternsDropDownList.DefaultModifiers" wide
        $s2 = "]Regular Expression Pattern to use for validation.  See accompanied regular expression bank..." ascii
        $s3 = "'System.Globalization.DateTimeFormatInfo+" ascii
        $s4 = "lType of comparison to perform with ValueToCompare.  Default is data type checking if DataType is no" ascii
        $s5 = "+System.Globalization.GregorianCalendarTypes" ascii
        $s6 = "2Message to display/return iwhen validation failed." ascii
        $s7 = "AI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchestr" wide
        $s8 = "_Highest value the control can have.  Remember to set DataType when range is not of type String." ascii
        $s9 = "<Case sensitivity validation works best with String DataType." ascii
        $s10 = "iAI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchest" ascii
        $s11 = "^Lowest value the control can have.  Remember to set DataType when range is not of type String." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2161664 and 12 of them
}
