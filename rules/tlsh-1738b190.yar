rule Sightlines_tlsh_1738b190_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1738b190"
        date = "2026-10-31"
        campaign = "tlsh-1738b190"
        family = ""
        hash = "10565660f78e642c000f3a4bf78f07eff29e10db4a3158e2510b79ceb2288478"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1738b190.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2Method's type signature is not PInvoke compatible._Method '%1.%2' cannot be marked with both DllImp" wide
        $s1 = "Could not get PINVOKE information for method '%3' in type '%1' from assembly '%2'.]Array of type '%1" wide
        $s2 = "(Could not load file or assembly '%1'. %2$Signature is not Interop compatible.|Invalid managed/unman" wide
        $s3 = "WInvalid managed/unmanaged type combination (Int64/UInt64 must be paired with I8 or U8).\\Invalid man" wide
        $s4 = "-implemented method with non-zero RVA./Internal call method '%1.%3' with non-zero RVA.&Abstract meth" wide
        $s5 = "BCould not create a pointer to a ByRef. Type: '%1'. Assembly: '%2'.`InlineArrayAttribute cannot be a" wide
        $s6 = "aged type combination (String[] must be paired with an ArraySubType of LPStr, LPWStr, BStr, or LPTSt" wide
        $s7 = "not supported with UnsafeAccessorTypeAttribute.RType '%1' from assembly '%2' is attempting to implem" wide
        $s8 = "2'.bInlineArrayAttribute cannot be applied to a type with explicit layout. Type: '%1'. Assembly: '%2" wide
        $s9 = "uAll named parameters must be specified as [DISPID=XXX] when invoking on a standard members specifie" wide
        $s10 = "d as [DISPID=XXX}.cVariant returned from an Invoke call with a DISPID of -4 does not contain a valid" wide
        $s11 = "aged/unmanaged type combination (Int/UInt must be paired with SysInt or SysUInt).KInvalid managed/un" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
