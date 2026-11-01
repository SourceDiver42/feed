rule Sightlines_tlsh_8530c0b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8530c0b5"
        date = "2026-10-28"
        campaign = "tlsh-8530c0b5"
        family = ""
        hash = "050f000ac9f1f2b730569bf6818b3cb3340a8afa6b8ef517184aec7d050571c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8530c0b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilter% --w" ascii
        $s1 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=hostfakesplit --" ascii
        $s2 = "esync-fake-unknown-udp=\"%BIN%quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2" ascii
        $s3 = "--filter-tcp=80,443,%GameFilter% --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-excl" ascii
        $s4 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt" ascii
        $s5 = "--filter-udp=443 --hostlist=\"%LISTS%list-general.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" -" ascii
        $s6 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --ip-id=zero --dpi-desync=hostfakesplit --dpi-d" ascii
        $s7 = "-desync-fooling=ts,md5sig --dpi-desync-hostfakesplit-mod=host=ozon.ru --new ^" ascii
        $s8 = "-quic=\"%BIN%quic_initial_www_google_com.bin\" --new ^" ascii
        $s9 = "--filter-udp=443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" --ipset" ascii
        $s10 = "-exclude=\"%LISTS%ipset-exclude.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=" ascii
        $s11 = "\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --dpi-desync=hostfakesplit --dpi-desync-repeats=4 --dpi" ascii
    condition:
        filesize < 1048576 and 8 of them
}
