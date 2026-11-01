rule Sightlines_tlsh_022db377_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-022db377"
        date = "2026-11-01"
        campaign = "tlsh-022db377"
        family = "mirai"
        hash = "04256374f18eab92bd40e60b340d509606b768322e080d485e766f402a7efae1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-022db377.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s4 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s5 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s6 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s7 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s8 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
        $s11 = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1111288 and 12 of them
}
