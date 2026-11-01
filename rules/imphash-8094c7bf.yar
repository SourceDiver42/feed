rule Sightlines_imphash_8094c7bf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8094c7bf"
        date = "2026-10-20"
        campaign = "imphash-8094c7bf"
        family = ""
        hash = "0059a3866d1902467dd4fe64108aefd5c7fd2856a794a251c2b28004a92257b9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8094c7bf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "random_device::random_device(const std::string&): unsupported token" ascii
        $s2 = "random_device::random_device(const std::string&): device not available" ascii
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "basic_string::_S_construct null not valid" ascii
        $s5 = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >" ascii
        $s6 = "basic_string: construction from null is not valid" ascii
        $s7 = "only http:// urls are supported for downloads" ascii
        $s8 = "std::basic_iostream<char, std::char_traits<char> >" ascii
        $s9 = "std::basic_ostream<char, std::char_traits<char> >" ascii
        $s10 = "only http:// urls are supported for the geo lookup" ascii
        $s11 = "the network helper is missing required exports" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
