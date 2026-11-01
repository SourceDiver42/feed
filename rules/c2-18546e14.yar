rule Sightlines_c2_18546e14_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-18546e14"
        date = "2026-10-26"
        campaign = "c2-18546e14"
        family = "mirai"
        hash = "192604729aada8ede20a961fb125e2acb62f692413177754baf7068a3e654412"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-18546e14.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Fbi5sy8EgLy+wUMDd15mGNMbHZZWPoU/N8xnYxLz2FAyMjeFW6IGKDa610AbQeEVPDVloZPsfxz4uu/7iDqmwP9OvTV2gzRE4PYQ" ascii
        $s1 = "ziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPg" ascii
        $s2 = "qmC6u074sckgPERhS6c4135wEdNP+6bONEDzxYCuJI+E99nie4UJSXkHNeE8Y62ltzBB45bo+7cqhziJW/f9kbarbtb/FRibYGLZ" ascii
        $s3 = "2uTnWe1DhnMvetK4RW+OZ5ktObmrgEGuu82OUP/7OEtlpL9PkqL9ZeZ8ZbWbUc+PeGu6dvIdjsSBdvHxA+VulDm3AkKsVYTJQZ/d" ascii
        $s4 = "QC/aWFGdjOvBEes5AHBbcrw29SyQ+1x0rpoVxz9gaN2tVYZfmg7UtxqdGWNXIlsv" ascii
        $s5 = "+qcDsiMFnUSLDrl2K2m7+8rTyccPlqzWJ5bT+FEx3pK70cqj4tnOVzDvSKFXYqSgwt5bF1HWZYpeILz6F82AEPwOm2GG2p7HgqEA" ascii
        $s6 = "KAwsHY0QYzpMqFUm90Yg+LNEWY/dGfnVclVijGeFtgLsIAUZ1LzP/q4kyhxruvLB" ascii
        $s7 = "Acwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXx" ascii
        $s8 = "OizZiN51Z3k6j5xTNlO2yD22KUIrl7UKTGxFgT2IDft6bJfaipUwNrehHR2ugoJzFwVhtiZTPKnBnv1Lv880s2Gin7sSwnrUJVOO" ascii
        $s9 = "yQIg+1tCppMZumIXp5EV1z14wZLS9eHThRtPYJ7iYYMVr4gKK478aLIhY4WJlirBByBKU26o2liJ1KKnR+WErV2KK0Q2M6dSC/wW" ascii
        $s10 = "IDQ1cyAmJiBwa2lsbCAtOSBydW4gJiYgcGtpbGwgLTkgdG9wICYmIHBraWxsIC05IGt0aHJlYWRhZGQKZXhpdCAw\" | base64 -" ascii
        $s11 = "bCAyPjEmCnNsZWVwIDIwbSAmJiBjZCAuLjsgL3RtcC8uWDI5MS11bml4Ly5yc3luYy9pbml0YWxsIDI+MSYKZXhpdCAw\" | base" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5202384 and 12 of them
}
