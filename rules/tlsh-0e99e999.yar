rule Sightlines_tlsh_0e99e999_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0e99e999"
        date = "2026-10-27"
        campaign = "tlsh-0e99e999"
        family = ""
        hash = "3bca84d031e1c20d8319bdd9123ce08a844ea507bd3613b80d5f2501d7795869"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0e99e999.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "k6ztI/8FJ0+pFD7fkSIP5QE0Z7U0h6k2JUThmRYlZMEUPt1FgQf/CZkWJUWBNi1FoTQ+v4k0DYRjrA0Ux5EiJXCRgSIlUJDhIiXQ" ascii
        $s1 = "Ii1UIxMKr9sJNAdbEQqP2w00R30mD0ABJD6/USQHHSRHQTYnqTYnzTYn8SYPkA02J/UmD5fxNicZND6zHAknB6AJNAepNEfNJg9Q" ascii
        $s2 = "SdSVIg8cQSDnHcuZIicfzD28IZg90yGYP19EPvNJ1CEnHAP/////DSCn3SAHXSYk4w0iF23TpSI1GEGap8A90GfMPbw5mD3TIZg/" ascii
        $s3 = "v/MTC+/bTSQHGSRHXSItVCMTCq/bCTQHWxEKj9sNNEd9Jg9AASQ+v1EkBx0kR0E2J6k2J802J/EmD5ANNif1Jg+X8TYnGTQ+sxwJ" ascii
        $s4 = "R10iLRQhJicBJ9+JJAcZIg9IASYnSSItFCEn340kBx0iD0gBND6/ETQHXSRHQTYnqTYnzTYn8SYPkA02J/UmD5fxNicZND6zHAkn" ascii
        $s5 = "JidfEQpP28k0Pr/zEwvv200kBxkkR10iLVQjEwqv2wk0B1sRCo/bDTRHfSYPQAEkPr9RJAcdJEdBNiepNifNNifxJg+QDTYn9SYP" ascii
        $s6 = "JjXAQZvfG8A8PhFL9///zQQ9vCEiNdBfxScfBEAAAAEkpwWYPH4QAAAAAAGaQZg86YQ8MTDnJdhhMAc9IOfdy7WYPOmFO/wxMOcl" ascii
        $s7 = "BSItVAEmJ18RCk/byTQ+v/MTC+/bTSQHGSRHXSItVCMTCq/bCTQHWxEKj9sNNEd9Jg9AASQ+v1EkBx0kR0E2J6k2J802J/EmD5AN" ascii
        $s8 = "Ii0UISYnASffiSQHGSIPSAEmJ0kiLRQhJ9+NJAcdIg9IATQ+vxE0B10kR0E2J6k2J802J/EmD5ANNif1Jg+X8TYnGTQ+sxwJJweg" ascii
        $s9 = "Jx0n34kmJxUmJ1kiLRQBJ9+NND6/8SQHGSRHXSItFCEmJwEn34kkBxkiD0gBJidJIi0UISffjSQHHSIPSAE0Pr8RNAddJEdBNiep" ascii
        $s10 = "WSItFAEn3400Pr/xJAcZJEddIi0UISYnASffiSQHGSIPSAEmJ0kiLRQhJ9+NJAcdIg9IATQ+vxE0B10kR0E2J6k2J802J/EmD5AN" ascii
        $s11 = "34kkBxkiD0gBJidJIi0UISffjSQHHSIPSAE0Pr8RNAddJEdBNiepNifNNifxJg+QDTYn9SYPl/E2Jxk0PrMcCScHoAk0B6k0R80m" ascii
    condition:
        filesize < 31707744 and 9 of them
}
