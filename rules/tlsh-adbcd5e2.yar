rule Sightlines_tlsh_adbcd5e2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-adbcd5e2"
        date = "2026-10-30"
        campaign = "tlsh-adbcd5e2"
        family = ""
        hash = "692b58911f7e0d793b735b4141e7a48555c79a095fc85a201efaa9b068c3b888"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-adbcd5e2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  \"signature\": \"h2IBN9F1vbHaEupR607T7sENtak56DQ/swFTfWfYV/GC7pUMgZ3rXOf9v1MjBPEbANILugwthcCV5/ezhc/g" ascii
        $s1 = "<RSAKeyValue><Modulus>x43zwaHqbxWvjGJnuMtMw5ljKJSPAZYOyDaXW6USRC0rWkSzPC1BGbEWEXg/7LwTWDj6fJp6/bnieq" ascii
        $s2 = "e3FyAILqv41WCzEbbWObPjoQ4lWY/JrgrNI6LV7yc0aAYQpGF6p+oHwmRoBZqb4IG92ACgau7GTUsRxOhM+KLTCRTBOIC14JeonX" ascii
        $s3 = "feBH6OtO8ie4j8WyUUbSGypwjQlGNqGFk6Xp/WeMGBME3PBKiYVBA6o81KiCZ/jauESfxLgHHTJc4+pwvSsMidyn1pLZryLBdz9h" ascii
        $s4 = "Dls7NcHwEjZADkLz+dn2NpVnSSCTkib48KO1K195ZLYWfVkN5bj86eoXLl9TQd3nYdYWFzg6B7+/d3wKAhXmDmyhbQoyYMMJCzid" ascii
        $s5 = "IYp3bslhn63/6YA28HkoGMs8r5HgK5Obv0Z+wzicEvMST94qiicoX0S5PzRDKyM2Bc0ZXqiRh+M1GwVTcAQGZraidllSge/fuw2a" ascii
        $s6 = "5JNeMWjWe+ZZ1X1SR9Kspa0ELRoIXSuzK80wHv6dIvEMlSvahWyxC1m4nl/7CA3NVAvXWZycAQhvHu65jByC2QY6MUbYaajydUUi" ascii
        $s7 = "j69C+OZwJ6ONPpxKwk/XVIPhpajvNhSzMG3TAdaJF4g7nZg9J34R+8ejbuQtwqmfQqGmTemU5KLmIAZYIjaU04GKxQzpUYjIn4IH" ascii
        $s8 = "+rnGSc9Hy/e2mo+n5LlPdj+tICGQ3rRXMvmsfWcRNMCCC1NV4HhYndBfJ3o1SMirpwI/S8QIN3BZ+Fmu4tyyQWG+7y5qSbkrpL75" ascii
        $s9 = "1qlwcXuG0lcEXBmIOlvwqty0shX31HW9xZsogG5qqNPkkOu5ZPzUtGqe8ukpjRuk/sId3o0ljWhWQJNqbb1qNS7xEhdzDjD3OKAr" ascii
        $s10 = "xNjc0Y2M1NDBmM2E1NmUiLCJwYXRoIjoiYmluL3F1aWNfaW5pdGlhbF80cGRhX3RvLmJpbiIsInNpemUiOjEyNTB9LHsic2hhMjU" ascii
        $s11 = "wN2QyNSIsInBhdGgiOiJnZW5lcmFsIChBTFQ0KS5iYXQiLCJzaXplIjozODg3fSx7InNoYTI1NiI6ImE4MWMyNzZlY2FlMzRjM2M" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2279424 and 12 of them
}
