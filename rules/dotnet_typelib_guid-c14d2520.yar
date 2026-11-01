rule Sightlines_dotnet_typelib_guid_c14d2520_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c14d2520"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-c14d2520"
        family = ""
        hash = "664d77cc2163f40e80ac0e1ee4ed84b3a5c21c580a277dd63fdd4e448e55a3f7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c14d2520.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<ExceptionToUnmanagedMarshaller>k__BackingField" ascii
        $s4 = "FType of managed object is not supported for marshalling as ComVariant." ascii
        $s5 = "get_ComVariantMarshaller_UnmanagedTypeNotSupported" ascii
        $s6 = "get_ComVariantMarshaller_ManagedTypeNotSupported" ascii
        $s7 = "OType of unmanaged variant is not supported for marshalling to a managed object." ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = "Invalid combination of unmanaged variant type and managed object type." wide
        $s10 = "#Access to the path '{0}' is denied.r" ascii
        $s11 = "TryCreateOleVariantForInterfaceWrapper" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
