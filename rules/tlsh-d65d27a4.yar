rule Sightlines_tlsh_d65d27a4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d65d27a4"
        date = "2026-11-01"
        campaign = "tlsh-d65d27a4"
        family = ""
        hash = "8644e30837c543e29155684053c890bc6791aeffb76d5aa896ad2f413f2f8a57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d65d27a4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect" ascii
        $s1 = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(" ascii
        $s2 = "if command -v python3 > /dev/null 2>&1; then" ascii
        $s3 = "if command -v bash > /dev/null 2>&1; then" ascii
        $s4 = "if command -v python > /dev/null 2>&1; then" ascii
        $s5 = "if command -v perl > /dev/null 2>&1; then" ascii
        $s6 = "if command -v sh > /dev/null 2>&1; then" ascii
        $s7 = "if command -v nc > /dev/null 2>&1; then" ascii
        $s8 = "## https://www.revshells.com/ ##" ascii
        $s9 = "ty; pty.spawn(\"/bin/bash\")'" ascii
        $s10 = "#!/bin/bash" ascii
    condition:
        filesize < 1048576 and 11 of them
}
