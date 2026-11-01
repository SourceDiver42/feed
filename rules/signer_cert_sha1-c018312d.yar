rule Sightlines_signer_cert_sha1_c018312d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-c018312d"
        date = "2026-10-27"
        campaign = "signer_cert_sha1-c018312d"
        family = ""
        hash = "019d3ee00b5bdd92618659e6ee0ab8388930be361a5ba30fcb150b1b4f8b0351"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-c018312d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "UTN-USERFirst-Object0" ascii
        $s1 = "Salt Lake City1" ascii
        $s2 = "190709184036Z0" ascii
        $s3 = "151231000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7480048 and 4 of them
}
