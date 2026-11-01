rule Sightlines_imphash_65a3d861_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-65a3d861"
        date = "2026-10-23"
        campaign = "imphash-65a3d861"
        family = ""
        hash = "22387bf1bd80fb80d3b7379d37219449f06b0e445c38eca17cd7edb8891c6aaa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-65a3d861.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.11 Copyright 1995-2017 Mark Adler " ascii
        $s1 = "    name=\"CompanyName.ProductName.YourApp\"" ascii
        $s2 = "Floating-point stack overflow or underflow" wide
        $s3 = "Floating-point underflow (exponent too small)" wide
        $s4 = "Floating-point overflow (exponent to great)" wide
        $s5 = "Exception handler returned unknown value" wide
        $s6 = "Exception handler tried to continue after non-continuable exception" wide
        $s7 = "Division by zero (floating-point)" wide
        $s8 = "        processorArchitecture=\"X86\"" ascii
        $s9 = "Invalid floating-point operation" wide
        $s10 = "Denormal floating-point operand" wide
        $s11 = "Inexact floating-point result" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
