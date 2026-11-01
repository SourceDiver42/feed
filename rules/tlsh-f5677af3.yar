rule Sightlines_tlsh_f5677af3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f5677af3"
        date = "2026-10-31"
        campaign = "tlsh-f5677af3"
        family = ""
        hash = "61d1189f1f99d27ec4e68dd00075874e67580c57e0f4c3f04a77db926a0fef00"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f5677af3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "<RuntimeOps_CreateRuntimeVariables_ObjectArray_Int64Array>k__BackingField" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "<CreateObjectArrayDelegateRefEmit>g__ForceAllowDynamicCode|19_1" ascii
        $s4 = "<CreateObjectArrayDelegateRefEmit>g__CreateForceAllowDynamicCodeScope|19_0" ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = "System.Diagnostics.CodeAnalysis.RequiresDynamicCodeAttribute, System.Runtime, Version=10.0.0.0, Cult" ascii
        $s7 = "<MethodInfo_CreateDelegate_Type_Object>k__BackingField" ascii
        $s8 = "2System.Linq.Expressions.CanEmitObjectArrayDelegate" ascii
        $s9 = "/_/src/runtime/artifacts/obj/System.Linq.Expressions/Release/net10.0/System.Linq.Expressions.pdb" ascii
        $s10 = "<Closure_ObjectArray_ObjectArray>k__BackingField" ascii
        $s11 = "<DictionaryOfStringInt32_Ctor_Int32>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7279136 and 12 of them
}
