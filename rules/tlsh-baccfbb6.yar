rule Sightlines_tlsh_baccfbb6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-baccfbb6"
        date = "2026-10-28"
        campaign = "tlsh-baccfbb6"
        family = ""
        hash = "621ed067e8214758b584df19b7f9726559d32af16267e6217f878d0b96378a29"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-baccfbb6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CloudKit.framework/Versions/A/CloudKit" ascii
        $s1 = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" ascii
        $s2 = "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics" ascii
        $s3 = "/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore" ascii
        $s4 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s5 = "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation" ascii
        $s6 = "/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText" ascii
        $s7 = "n limit (e.g. symlink loop)stale network file handleinvalid input parameterinvalid datatimed outwrit" ascii
        $s8 = "/System/Library/Frameworks/CoreImage.framework/Versions/A/CoreImage" ascii
        $s9 = "invalid stack size...failed to write the buffered datamust specify at least one of read, write, or a" ascii
        $s10 = "xceededfile too largeresource busyexecutable file busydeadlockcross-device link or renametoo many li" ascii
        $s11 = "*incomplete utf-8 byte sequence from index " ascii
    condition:
        filesize < 4121888 and 12 of them
}
