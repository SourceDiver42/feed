rule Sightlines_imphash_da99e2f6_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-da99e2f6"
        date = "2026-11-01"
        campaign = "imphash-da99e2f6"
        family = "silentnet"
        hash = "0b349a5b1a1d1d40b3fbaf1a794c94f569770ce5a9a4bdf8cbeb198627a9da12"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-da99e2f6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Unable to dump stack trace: debug info stripped" ascii
        $s1 = "CertificateSignatureAlgorithmUnsupported" ascii
        $s2 = "CertificateSignatureNamedCurveUnsupported" ascii
        $s3 = "CertificateSignatureUnsupportedBitCount" ascii
        $s4 = "CertificateSignatureAlgorithmMismatch" ascii
        $s5 = "getrandom() failed to provide entropy" ascii
        $s6 = "TlsAlertBadCertificateStatusResponse" ascii
        $s7 = "CertificateHasUnrecognizedObjectId" ascii
        $s8 = "Panicked during a panic. Aborting." ascii
        $s9 = "CertificateFieldHasWrongDataType" ascii
        $s10 = "CertificateSignatureInvalidLength" ascii
        $s11 = "CertificateAuthorityBundleTooBig" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2279424 and 12 of them
}
