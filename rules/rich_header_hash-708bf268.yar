rule Sightlines_rich_header_hash_708bf268_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-708bf268"
        date = "2026-11-01"
        campaign = "rich_header_hash-708bf268"
        family = ""
        hash = "72167a84e4cb877beab3f19a65804bcb47007cf584ccaa17e2ace13a8addbbcf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-708bf268.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$d=[Environment]::GetFolderPath('Desktop');$p=\"$d\\Zapret Manager v2.lnk\";$s=(New-Object -ComObject W" ascii
        $s1 = "CHANNEL__:${this.id}`}toJSON(){return this[d]()}}async function l(t,e={},s){return window.__TAURI_IN" ascii
        $s2 = "ed(e){return this.listen(d.WINDOW_THEME_CHANGED,e)}}var D,S,O,A,W;async function z(e,t){await a(\"plu" ascii
        $s3 = "NALS__)&&void 0!==n?n:{}}var Z,K=Object.freeze({__proto__:null,clearMocks:function(){\"object\"==typeo" ascii
        $s4 = "IEYzOEE1MEJGMDIxNENEM0MKUldROHpSUUN2MUNLODZtWEpDUHZGY25vRHcwV2RScDhIUXZlNVl4Y2hHZFpCZHYxektMQTArbWcK" ascii
        $s5 = "SHA384_ASN1ECDSA_P384_SHA384_FIXEDassertion failed: key.len() <= digest_alg.block_len() / 2" ascii
        $s6 = ")?t(i,r):e(i,r)},window.__TAURI_INTERNALS__.transformCallback=function(e,n=!1){const t=window.crypto" ascii
        $s7 = "  Object.defineProperty(window.__TAURI_INTERNALS__, 'transformCallback', {" ascii
        $s8 = "  Object.defineProperty(window.__TAURI_INTERNALS__, 'unregisterCallback', {" ascii
        $s9 = "Object.defineProperty(window.__TAURI_INTERNALS__.plugins, 'path', {" ascii
        $s10 = "plugin:__TAURI_CHANNEL__|fetch// Copyright 2019-2024 Tauri Programme within The Commons Conservancy" ascii
        $s11 = ",i()}}async onScaleChanged(e){return this.listen(d.WINDOW_SCALE_FACTOR_CHANGED,e)}async onThemeChang" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 21489664 and 12 of them
}
