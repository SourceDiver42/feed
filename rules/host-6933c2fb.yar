rule Sightlines_host_6933c2fb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-6933c2fb"
        date = "2026-10-20"
        campaign = "host-6933c2fb"
        family = ""
        hash = "05cebfa73485dadf802c473571183eda70aecd9766136c7c1af666987bcb6461"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-6933c2fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nohup bash \"$TARGET_DIR/tokenlinux.sh\" > /dev/null 2>&1 &" ascii
        $s1 = "mv \"$TARGET_DIR/end_activator\" \"$TARGET_DIR/end.sh\"" ascii
        $s2 = "chmod +x \"$TARGET_DIR/start.sh\" \"$TARGET_DIR/end.sh\"" ascii
        $s3 = "mv \"$TARGET_DIR/start_activator\" \"$TARGET_DIR/start.sh\"" ascii
        $s4 = "chmod +x \"$TARGET_DIR/tokenlinux.sh\"" ascii
        $s5 = "bash \"$TARGET_DIR/start.sh\"" ascii
        $s6 = "TARGET_DIR=\"$HOME/.cache\"" ascii
        $s7 = "echo \"Authenticated\"" ascii
        $s8 = "#!/bin/bash" ascii
        $s9 = "  exit 1" ascii
    condition:
        filesize < 1048576 and 10 of them
}
