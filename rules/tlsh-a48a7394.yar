rule Sightlines_tlsh_a48a7394_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a48a7394"
        date = "2026-11-01"
        campaign = "tlsh-a48a7394"
        family = "prometei"
        hash = "3a69569f3152708d11d38e958094d7041a0ea5d54a50c39447886fccef99c1b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a48a7394.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Signal CommandId=\"5F0F16A6-39FD-442E-838B-D5197A1BECD7\"><rsp:Code>http://schemas.microsoft.com/wbem/" ascii
        $s1 = "In FIPS mode MD5 is not allowed.Try ssh_get_publickey_hash() withSSH_PUBLICKEY_HASH_SHA256" ascii
        $s2 = "chemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action><w:OptionSet><w:Option Name=\"WINRS_NOPROFILE" ascii
        $s3 = "powershell $f='%s;$o='%s';$data=[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($f)" ascii
        $s4 = "hellId\">95A11240-151C-4382-8E3D-C3F34A856496</w:Selector></w:SelectorSet></env:Header><env:Body><rsp" ascii
        $s5 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s6 = ":Receive><rsp:DesiredStream CommandId=\"690DC335-1B71-4130-93F7-C0810771E5BC\">stdout stderr</rsp:Desi" ascii
        $s7 = "ize><a:MessageID>uuid:b67abbba-03e4-4276-9f60-680e2b8d5770</a:MessageID><w:Locale mustUnderstand=\"fa" ascii
        $s8 = "\">FALSE</w:Option><w:Option Name=\"WINRS_CODEPAGE\">437</w:Option></w:OptionSet></env:Header><env:Body" ascii
        $s9 = "_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2" ascii
        $s10 = "ize><a:MessageID>uuid:dbc420a3-a7d8-4f02-a80b-97a00e77a931</a:MessageID><w:Locale mustUnderstand=\"fa" ascii
        $s11 = "ellId\">7A2067DB-664B-457D-B941-C9F1D1449CA9</w:Selector></w:SelectorSet></env:Header><env:Body><rsp:" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 8568672 and 12 of them
}
