rule Sightlines_tlsh_bb9e17cf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bb9e17cf"
        date = "2026-10-31"
        campaign = "tlsh-bb9e17cf"
        family = ""
        hash = "5f8361ca138b76d410edaa5ccfa765b808dd99a1db72b6cbe0942ecb52601fab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bb9e17cf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Text.Encodings.Web/Release/net9.0-windows/System.Text.Encodings." ascii
        $s4 = "DTextEncoder does not implement MaxOutputCharsPerInputChar correctly.c" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "580978A21F179B0480F4AC4BBAA7E699110F4C9E1282B63758A7E9653CA0EDE42" ascii
        $s7 = "E37440A8AB7EB4535BCC7DFC9F09735C5ED2828279F0FBD940C91A3F74C6ED7E" ascii
        $s8 = "97392397B3101DFB6D6C3B25E1D26343B91808D7BBF6EB7CA5AD3D4D98AF105F" ascii
        $s9 = "7533ADF00A145D285CDFDCD7A63332C731915F01A2A9BB101362BB8D0CF847C42" ascii
        $s10 = "__StaticArrayInitTypeSize=62_Align=2" ascii
        $s11 = "40DFDA6D4ED43D4879E2A200D2471641FC15E1C25DAB5D4D491BD811F7727FCC2" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
