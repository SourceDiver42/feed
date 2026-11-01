rule Sightlines_tlsh_3cc9c623_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3cc9c623"
        date = "2026-10-30"
        campaign = "tlsh-3cc9c623"
        family = ""
        hash = "051e355666d8d242827c7969b70f6da6b7f27aa23fcd5c36fcb0c81bc25a6856"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3cc9c623.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "X25519+ML-KEM-768 TLS hybrid implementation" ascii
        $s1 = "Negative big numbers are unsupported for OSSL_PARAM_UNSIGNED_INTEGER" ascii
        $s2 = "assertion failed: !EVP_CIPHER_CTX_get0_cipher(self.as_ptr()).is_null()" ascii
        $s3 = "cryptography.x509.extensions_CRLREASONFLAGS" ascii
        $s4 = "P-384+ML-KEM-1024 TLS hybrid implementation" ascii
        $s5 = "Valid PEM but no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?Incor" ascii
        $s6 = "P-256+ML-KEM-768 TLS hybrid implementation" ascii
        $s7 = "X448+ML-KEM-1024 TLS hybrid implementation" ascii
        $s8 = "assertion failed: !pctx.is_null()C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b" ascii
        $s9 = "assertion failed: niv >= 0 && niv <= EVP_MAX_IV_LENGTH" ascii
        $s10 = "RSA-SM3:sm3WithRSAEncryption:1.2.156.10197.1.504" ascii
        $s11 = "Valid PEM but no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this is " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19870720 and 12 of them
}
