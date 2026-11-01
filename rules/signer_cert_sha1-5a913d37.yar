rule Sightlines_signer_cert_sha1_5a913d37_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-5a913d37"
        date = "2026-10-27"
        campaign = "signer_cert_sha1-5a913d37"
        family = ""
        hash = "5fd1bf62b065bd9a8bcbf8552d9ffd24f96341c10a4b93c5be0282a2f704fb2e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-5a913d37.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "250911201114Z0t1" ascii
        $s1 = "230012+5029230" ascii
        $s2 = "240912201114Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3244096 and 3 of them
}
