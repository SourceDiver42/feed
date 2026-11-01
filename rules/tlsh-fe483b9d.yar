rule Sightlines_tlsh_fe483b9d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fe483b9d"
        date = "2026-10-31"
        campaign = "tlsh-fe483b9d"
        family = ""
        hash = "1d6691eee72ab1bd3924d8bc2ece16ff4f7aa1c2cc946d9b01344b55bff9538a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fe483b9d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<GetSecurityInfoByName>g____PInvoke|19_0" ascii
        $s4 = "<SetSecurityInfoByHandle>g____PInvoke|18_0" ascii
        $s5 = "<SetSecurityInfoByName>g____PInvoke|20_0" ascii
        $s6 = "<AdjustTokenPrivileges>g____PInvoke|25_0" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.Security.AccessControl/Release/net10.0-windows/System.Security.A" ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = "0Only single dimension arrays are supported here.o" ascii
        $s10 = "<DuplicateTokenEx>g____PInvoke|26_0" ascii
        $s11 = "<OpenProcessToken>g____PInvoke|23_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
