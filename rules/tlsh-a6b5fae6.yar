rule Sightlines_tlsh_a6b5fae6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a6b5fae6"
        date = "2026-10-31"
        campaign = "tlsh-a6b5fae6"
        family = ""
        hash = "6246f5fe726fbf612ca621961fd90a440425d64e9f4e51b7bb7adb80651032fa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a6b5fae6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[conn][%1] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLO" wide
        $s1 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_winuser.c" ascii
        $s2 = "[sett] StreamMultiReceiveEnabled  = %hhu" ascii
        $s3 = "C:\\__w\\1\\s\\msquic\\artifacts\\bin\\winuser\\cmakeouttemp\\msquic.pdb" ascii
        $s4 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw_xdp_win.c" ascii
        $s5 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw_socket.c" ascii
        $s6 = "C:\\__w\\1\\s\\msquic\\src\\platform\\platform_winuser.c" ascii
        $s7 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw_win.c" ascii
        $s8 = "C:\\__w\\1\\s\\msquic\\src\\platform\\platform_worker.c" ascii
        $s9 = "C:\\__w\\1\\s\\msquic\\src\\platform\\tls_schannel.c" ascii
        $s10 = "C:\\__w\\1\\s\\msquic\\src\\core\\packet_builder.c" ascii
        $s11 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw.c" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1074800 and 12 of them
}
