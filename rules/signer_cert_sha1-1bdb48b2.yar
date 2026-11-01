rule Sightlines_signer_cert_sha1_1bdb48b2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-1bdb48b2"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-1bdb48b2"
        family = ""
        hash = "060bcc88a688e687ff1404b83b5fb5cf17e19ec57f33d5b8a48ab494da83c134"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-1bdb48b2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = "10.0.12+95017c711e6afc1085133d440e42b4bd78155701" wide
        $s4 = "Microsoft Code Signing PCA 20240" ascii
        $s5 = ".NETCoreApp,Version=v10.0" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "270415185739Z0c1" ascii
        $s8 = "360322221304Z0W1" ascii
        $s9 = "260416185739Z" ascii
        $s10 = "464223+5076060" ascii
        $s11 = "240808205418Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9229984 and 8 of them
}
