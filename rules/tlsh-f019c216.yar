rule Sightlines_tlsh_f019c216_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f019c216"
        date = "2026-11-01"
        campaign = "tlsh-f019c216"
        family = ""
        hash = "44746262b132edfa0a8e69e254bca4d273c7349b655d527bf44b7d83d1da4342"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f019c216.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$CArqSessionT@VCUdpSocket@@V1@@@" ascii
        $s1 = "input ack: sn=%lu rtt=%ld rto=%ld" ascii
        $s2 = "input psh: sn=%lu ts=%lu" ascii
        $s3 = ".?AVCKernelManager@@" ascii
        $s4 = ".?AVISocketBase@@" ascii
        $s5 = ".?AVCUdpSocket@@" ascii
        $s6 = ".?AVCTcpSocket@@" ascii
        $s7 = "[RO] %ld bytes" ascii
        $s8 = "input wins: %lu" ascii
        $s9 = ".?AVCManager@@" ascii
        $s10 = "[RI] %d bytes" ascii
        $s11 = ".?AVCBuffer@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
