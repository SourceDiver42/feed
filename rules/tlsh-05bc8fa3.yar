rule Sightlines_tlsh_05bc8fa3_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05bc8fa3"
        date = "2026-10-26"
        campaign = "tlsh-05bc8fa3"
        family = "remusstealer"
        hash = "27637ce02ac144ce1e7d29919f722f85cb53ad89a8bf1f634ab7d73cac83a0f7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05bc8fa3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "      <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s3 = "random_device::random_device(const std::string&): unsupported token" ascii
        $s4 = "random_device::random_device(const std::string&): device not available" ascii
        $s5 = "cannot create std::vector larger than max_size()" ascii
        $s6 = "basic_string::_M_construct null not valid" ascii
        $s7 = "basic_string::_S_construct null not valid" ascii
        $s8 = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >" ascii
        $s9 = "std::basic_iostream<char, std::char_traits<char> >" ascii
        $s10 = "std::basic_ostream<char, std::char_traits<char> >" ascii
        $s11 = "std::basic_istream<char, std::char_traits<char> >" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
