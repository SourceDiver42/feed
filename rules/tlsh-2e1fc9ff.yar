rule Sightlines_tlsh_2e1fc9ff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2e1fc9ff"
        date = "2026-10-18"
        campaign = "tlsh-2e1fc9ff"
        family = ""
        hash = "6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2e1fc9ff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "C3$24C5$26C7$28C9$!" ascii
        $s3 = "Ka7TaggtiTGXlllS" ascii
        $s4 = "J#Paok1EPum$U/" ascii
        $s5 = "h fil]or.Xir`" ascii
        $s6 = "-TCjX flSYAK" ascii
        $s7 = "mgRTFSuBPX[\\" ascii
        $s8 = "_;mulkxYcp-Y" ascii
        $s9 = "BwiAeUQ2o[}" ascii
        $s10 = "TAL: kerm4l" ascii
        $s11 = "?rGKkmeo0B" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
