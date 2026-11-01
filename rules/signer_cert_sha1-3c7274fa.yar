rule Sightlines_signer_cert_sha1_3c7274fa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-3c7274fa"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-3c7274fa"
        family = ""
        hash = "0749d8fc8e944d0576e1bb47120f87add8f875e5cd8968995633063fc79256f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-3c7274fa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = "10.0.12+95017c711e6afc1085133d440e42b4bd78155701" wide
        $s4 = "Microsoft Code Signing PCA 20240" ascii
        $s5 = ".NETCoreApp,Version=v10.0" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "270415185741Z0c1" ascii
        $s8 = "360322221304Z0W1" ascii
        $s9 = "464223+5075960" ascii
        $s10 = "260416185741Z" ascii
        $s11 = "240808205418Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4184656 and 8 of them
}
