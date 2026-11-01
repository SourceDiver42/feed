rule Sightlines_imphash_945e812e_nikrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-945e812e"
        date = "2026-10-30"
        campaign = "imphash-945e812e"
        family = "nikrat"
        hash = "09ac4a095622cc699022c5ecb83234df2b7dbf3035f1dc6fb439dc1e0059a480"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-945e812e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "SPLASH: length of Tk module directory path exceeds maximum path length!" ascii
        $s8 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s9 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s10 = "SPLASH: length of Tcl module directory path exceeds maximum path length!" ascii
        $s11 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20651632 and 12 of them
}
