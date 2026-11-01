rule Sightlines_tlsh_82a27dbf_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-82a27dbf"
        date = "2026-10-23"
        campaign = "tlsh-82a27dbf"
        family = "mirai"
        hash = "000d8b06db0f227f54e426f21534ea718d61d7381fd1c3a054ce0d354fd3d423"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-82a27dbf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "R_ARM_PC24: Compile shared libraries with -fPIC!" ascii
        $s2 = "update-rc.d S99ksync defaults 2>/dev/null || chkconfig --add S99ksync 2>/dev/null || insserv S99ksyn" ascii
        $s3 = "GCC: (Buildroot 2021.11-12449-g1bef613319) 13.3.0" ascii
        $s4 = "for exe in '%s' \"$HOME/libkys.so\" /data/local/tmp/libkys.so /data/local/.libkys.so /data/local/tmp/k" ascii
        $s5 = "for exe in '%s' /data/local/tmp/libkys.so /usr/bin/.ksync; do" ascii
        $s6 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s7 = "%s: '%s' is not an ELF executable for ARM" ascii
        $s8 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s9 = "@reboot root sleep 20 && nohup %s %s >/dev/null 2>&1 &" ascii
        $s10 = "cannot create TLS data structures: ABORT" ascii
        $s11 = "%s: cannot apply additional memory protection after relocation" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
