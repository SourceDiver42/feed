rule Sightlines_tlsh_f00349fb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f00349fb"
        date = "2026-11-01"
        campaign = "tlsh-f00349fb"
        family = "mirai"
        hash = "0e7ef938ce64d70f296e4fcba5280ded09b83f0350f3365b7d271e5c841b565e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f00349fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
        $s2 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s5 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s6 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s7 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s8 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
        $s11 = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
