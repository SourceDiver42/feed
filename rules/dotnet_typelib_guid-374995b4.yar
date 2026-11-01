rule Sightlines_dotnet_typelib_guid_374995b4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-374995b4"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-374995b4"
        family = ""
        hash = "0860d7f619373d259bd682e7d10f07f2373ab56d333e9b56157e2a8c508509a2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-374995b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/Microsoft.VisualBasic.Core/Release/net10.0-windows/Microsoft.VisualBasi" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "     ue/falseshort daort datelong datong datelong timong timecurrencystandard" wide
        $s6 = " medium dium datemedium tium time        scientifientific     " wide
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "&2^<NEBNRXNaBj&t&x\"}2" ascii
        $s9 = "*2~<NEBN~XNaBj&t&x6" ascii
        $s10 = "  short tiort time    " wide
        $s11 = "&92@FHBP&TrcVpf" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2388592 and 12 of them
}
