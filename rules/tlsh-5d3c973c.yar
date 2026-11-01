rule Sightlines_tlsh_5d3c973c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5d3c973c"
        date = "2026-10-24"
        campaign = "tlsh-5d3c973c"
        family = ""
        hash = "0a575410df7bb5c5d13aa46acdff196c566e748533c9b4be0d64af1213050a20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5d3c973c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "MsZCksRC5vcGVuKChbMTI2LCAxMjQsIDEwOV0ubWFwKHggPT4ge3JldHVybiBTdHJpbmcuZnJvbUNoYXJDb2RlKHggXiA1Nyk7fS" ascii
        $s1 = "VuY3Rpb24gTihNLEkpe3JldHVybiBNPj4+SXxNPDwzMi1JfWNvbnN0IEQ9TWF0aC5wb3csZz1EKDIsMzIpLFQ9KFs4OSwgODAsID" ascii
        $s2 = "BjPU1hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsVCg1LDEwKSksZD1UKDAsMSk7Zy5zZWFyY2hQYXJhbXMuc2V0KG" ascii
        $s3 = "ExJiYoZVtNXT1uZXcgRnVuY3Rpb24oYXRvYihJKSkoKSl9fTs=\"))();const fqMaGkN7=globalThis.obChTK.hPL3On([119" ascii
        $s4 = "onst T=fqMaGkN7.Ot(R);T&&(R=new XMLHttpRequest,V=T+[69,31,71].map(V=>String.fromCharCode(122^V)).joi" ascii
        $s5 = "kxLCA4MiwgNjUsIDkzXS5tYXAoeCA9PiB7cmV0dXJuIFN0cmluZy5mcm9tQ2hhckNvZGUoeCBeIDUzKTt9KS5qb2luKCIiKSk7bG" ascii
        $s6 = "1NfSxlVzRfX0g6ZnVuY3Rpb24oTSl7ZS5wPU19LGhQTDNPbjpjLFpLdkQwZTphc3luYyBmdW5jdGlvbihNKXtpZihNIGluIGU9PS" ascii
        $s7 = "Q8PCgzLWMpJTQqOH1mb3IoTFtMW1RdXT1iL2d8MCxMW0xbVF1dPWIsZD0wO2Q8TFtUXTspe2NvbnN0IE09TC5zbGljZShkLGQrPT" ascii
        $s8 = "V0IGMsZDtjb25zdCBMPVtdLGI9OCpNW1RdO2xldCBpPUlNLmg9SU0uaHx8W107Y29uc3QgeT1JTS5rPUlNLmt8fFtdO2xldCBDPX" ascii
        $s9 = "Y4MDYwNCk7Yys9TSlYW2NdPU07aVtDXT1EKE0sLjUpKmd8MCx5W0MrK109RChNLDEvMykqZ3wwfWZvcihNKz0igCI7TVtUXSU2NC" ascii
        $s10 = "01NjspTSs9IlwwIjtmb3IoYz0wO2M8TVtUXTtjKyspe2lmKGQ9TS5jaGFyQ29kZUF0KGMpLGQ+PjgpcmV0dXJuO0xbYz4+Ml18PW" ascii
        $s11 = "].map(V=>String.fromCharCode(45^V)).join(\"\")).zn.Nn.LJ1EuL?T=!0:globalThis.obChTK.hPL3On([75,78,76,7" ascii
    condition:
        filesize < 1048576 and 12 of them
}
