rule Sightlines_tlsh_b5da7814_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b5da7814"
        date = "2026-10-31"
        campaign = "tlsh-b5da7814"
        family = ""
        hash = "060bcc88a688e687ff1404b83b5fb5cf17e19ec57f33d5b8a48ab494da83c134"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b5da7814.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%$'&(&)&+*,*21316575?>@>HGJIKIXWZY[Y\\Y]Y^Y_Y`YaYbYcYdYeYfYgYontsus{z}|" wide
        $s1 = "<EmitTryMatchAtCurrentPosition>g__CanEmitIndexOf|324_29" ascii
        $s2 = "<SpanLastIndexOfAnyExceptCharMethod>k__BackingField" ascii
        $s3 = "<SpanLastIndexOfAnyExceptSearchValuesMethod>k__BackingField" ascii
        $s4 = "<SpanLastIndexOfAnyExceptCharCharMethod>k__BackingField" ascii
        $s5 = "<SpanLastIndexOfAnySearchValuesMethod>k__BackingField" ascii
        $s6 = "<SpanIndexOfAnyExceptSearchValuesMethod>k__BackingField" ascii
        $s7 = "<EmitTryFindNextPossibleStartingPosition>g__EmitIndexOf_RightToLeft|323_2" ascii
        $s8 = "<SpanLastIndexOfAnyExceptCharCharCharMethod>k__BackingField" ascii
        $s9 = "<EmitTryFindNextPossibleStartingPosition>g__EmitIndexOfString_LeftToRight|323_1" ascii
        $s10 = "<SpanLastIndexOfAnyCharCharMethod>k__BackingField" ascii
        $s11 = "<SpanIndexOfAnyExceptCharMethod>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2077200 and 12 of them
}
