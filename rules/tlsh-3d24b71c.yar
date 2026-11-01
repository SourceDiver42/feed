rule Sightlines_tlsh_3d24b71c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3d24b71c"
        date = "2026-10-31"
        campaign = "tlsh-3d24b71c"
        family = ""
        hash = "5758c463a2a0df0d10656eb61f1465bf4b14754e9c395112e47a2f0de75a0c4b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3d24b71c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<RegexGenerator_g>FCDFAA894408A4BE52DB36407A8838158E1347B18C8E6D1FBD1331CEC2A9DD6BE__Utilities" ascii
        $s1 = "<RegexGenerator_g>FCDFAA894408A4BE52DB36407A8838158E1347B18C8E6D1FBD1331CEC2A9DD6BE__CreateConnectio" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "System.Diagnostics.CodeAnalysis.RequiresDynamicCodeAttribute, System.Private.CoreLib, Version=10.0.0" ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = "System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute, System.Private.CoreLib, Version=1" ascii
        $s7 = "System.ComponentModel.ExpandableObjectConverter, System.ComponentModel.TypeConverter, Version=10.0.0" ascii
        $s8 = "wDBNowDBNullNestedInnDataSetCaseSensensitiveRemotingngFormatDataTypeAttributttributeA" wide
        $s9 = "/_/src/runtime/artifacts/obj/System.Data.Common/Release/net10.0/System.Data.Common.pdb" ascii
        $s10 = "+Value '{1}' is invalid for attribute '{0}'.N" ascii
        $s11 = "ther occur in RequiresUnreferencedCode scopes, or have individually justified suppressions.!" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5542416 and 12 of them
}
