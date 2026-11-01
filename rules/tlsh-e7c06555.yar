rule Sightlines_tlsh_e7c06555_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e7c06555"
        date = "2026-10-31"
        campaign = "tlsh-e7c06555"
        family = ""
        hash = "2000912f2fc52e0c64ed893d79f4e7b143502540fb7170b5ae5fcea7099ba431"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e7c06555.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/Microsoft.CSharp/Release/net10.0-windows/Microsoft.CSharp.pdb" ascii
        $s4 = "WThe 'dynamic' feature requires runtime-code generation, which is incompatible with AOT." ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "Justification`We can't annotate static constructors on structs, but everything else in this type is " ascii
        $s7 = "__StaticArrayInitTypeSize=104_Align=4" ascii
        $s8 = "246FFE5A442AD743A5B5E3472C0ECADD52C388FA25D68953C6B26AB7B7983C674" ascii
        $s9 = "C93CEDF33C42465BF6B93ED66FC9147EFCDE83274B61A58782B4E323D343AE3B4" ascii
        $s10 = "BuiltInInteropVariantExtensions" ascii
        $s11 = "<7>__BindLiftedBoolBitwiseOp" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1962608 and 12 of them
}
