rule Sightlines_tlsh_4b0663dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4b0663dc"
        date = "2026-10-31"
        campaign = "tlsh-4b0663dc"
        family = ""
        hash = "025905a371a3dc17ce26518a281315fd0428f4c579600f8ebfc7df106bca54d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4b0663dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<RegexGenerator_g>F3846317665D1ABF3801AE2FE0960EF8ACBF58466C53082BD1467D37A02DDB4B6__FullSRSInternal" ascii
        $s1 = "<RegexGenerator_g>F3846317665D1ABF3801AE2FE0960EF8ACBF58466C53082BD1467D37A02DDB4B6__Utilities" ascii
        $s2 = "<TypeOfXmlSchemaProviderAttribute>k__BackingField" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = "<TypeOfIDictionaryEnumerator>k__BackingField" ascii
        $s7 = "<TypeOfKnownTypeAttribute>k__BackingField" ascii
        $s8 = "<TypeOfExtensionDataObject>k__BackingField" ascii
        $s9 = "<TypeOfEnumMemberAttribute>k__BackingField" ascii
        $s10 = "<TypeOfIExtensibleDataObject>k__BackingField" ascii
        $s11 = "<TypeOfXmlFormatClassWriterDelegate>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4125296 and 12 of them
}
