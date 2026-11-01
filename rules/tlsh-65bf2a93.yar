rule Sightlines_tlsh_65bf2a93_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-65bf2a93"
        date = "2026-10-30"
        campaign = "tlsh-65bf2a93"
        family = ""
        hash = "1403ddd3979715ba14fa8899ac2c537478dfdd911b21d6322959f726a93d795a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-65bf2a93.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "* nfqws2, zapret-lib: (LUA_COMPAT_VER=6) fix wrong spelling : WRITEABLE -> WRITABLE" ascii
        $s1 = "* nfqws2: (LUA_COMPAT_VER=4) support 48-bit arithmetics" ascii
        $s2 = "* blockcheck2: MULTIDISORDER=multidisorder_legacy" ascii
        $s3 = "* nfqws2: do not start if NFQWS2_COMPAT_VER unexpected" ascii
        $s4 = "* init.d: 50-dht4all NFQWS_OPT_DHT_PKT_OUT" ascii
        $s5 = "* nfqws2: gracefully shutdown on SIGINT and SIGTERM" ascii
        $s6 = "* nfqws2: desync function can explicitly return nil as a synonym of VERDICT_PASS" ascii
        $s7 = "* builder_linux: optional build with zlib-ng : set ZLIB_NG=1 variable" ascii
        $s8 = "* nfqws2: solved inability to get SSID using nl80211 on kernels 5.19+" ascii
        $s9 = "* nfqws2: bu8,bu16,bu24,bu32,swap16,swap32 functions now work with negative int" ascii
        $s10 = "* nfqws2: fix issues with 32-bit lua_Integer in lua<5.3 on 32-bit platforms" ascii
        $s11 = "* actions: build nfqws2 x86 binary with LUA 5.4, not with luajit" ascii
    condition:
        filesize < 1048576 and 12 of them
}
