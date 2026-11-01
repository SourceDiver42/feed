rule Sightlines_tlsh_91f431a3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-91f431a3"
        date = "2026-10-21"
        campaign = "tlsh-91f431a3"
        family = "mirai"
        hash = "18b5057e1f21d9999af1799e1a18f1fb21a2d043d303f67563f4fd4bd8dcca42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-91f431a3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "(atomic/exe) Killed process: %s, PID: %d" ascii
        $s2 = "(atomic/maps) Killed Process: %s, PID: %d" ascii
        $s3 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s4 = "/usr/libexec/openssh/sftp-server" ascii
        $s5 = "HOST: 255.255.255.255:1900" ascii
        $s6 = "/usr/lib/systemd/systemd" ascii
        $s7 = "MAN: \"ssdp:discover\"" ascii
        $s8 = "M-SEARCH * HTTP/1.1" ascii
        $s9 = "/usr/compress/bin/" ascii
        $s10 = "/root/dvr_gui/" ascii
        $s11 = "/root/dvr_app/" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
