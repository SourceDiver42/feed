rule Sightlines_tlsh_24d9bbf0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-24d9bbf0"
        date = "2026-10-31"
        campaign = "tlsh-24d9bbf0"
        family = ""
        hash = "10519351ed44c8519ef28fd57d7668bfb67f771905dd8216706cdcbc8abc93d0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-24d9bbf0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ComponentModel.Annotations/Release/net10.0/System.ComponentModel" ascii
        $s4 = "3The value for property '{0}' must be of type '{1}'.{" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "to discover the type of the instance being validated in order to resolve the DisplayNameAttribute wh" ascii
        $s7 = "Constructing a ValidationContext without a display name is not trim-safe because it uses reflection " ascii
        $s8 = "Constructors that trigger this codepath are marked with RequiresUnreferencedCode. Constructor that t" ascii
        $s9 = "akes the display name as an argument is trim-safe." ascii
        $s10 = "en a display name is not provided." ascii
        $s11 = ".NETCoreApp,Version=v10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
