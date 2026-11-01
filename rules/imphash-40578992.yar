rule Sightlines_imphash_40578992_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-40578992"
        date = "2026-10-31"
        campaign = "imphash-40578992"
        family = ""
        hash = "1134b8284dc1a434cf004e3ad7a1dd025c81b1a6aa265cad2118448d0419b63d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-40578992.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s1 = "Invoking fx resolver [%s] hostfxr_main_bundle_startupinfo" wide
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\win-x64.Release\\corehost\\apphost\\standalone\\apphost.pdb" ascii
        $s4 = "The required library %s could not be found. Search location options [0x%x]" wide
        $s5 = "CreateActCtxW failed using manifest '%s'. Error code: %d" wide
        $s6 = "Invoking fx resolver [%s] hostfxr_main_startupinfo" wide
        $s7 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" wide
        $s8 = "gThe app-relative .NET path is longer than the max allowed length (%d)" wide
        $s9 = "Bundle header version compatibility check failed." wide
        $s10 = "The managed DLL bound to this executable is: '%s'" wide
        $s11 = "Error: [%s] does not contain any version-numbered child folders" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1165312 and 12 of them
}
