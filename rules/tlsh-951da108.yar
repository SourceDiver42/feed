rule Sightlines_tlsh_951da108_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-951da108"
        date = "2026-10-21"
        campaign = "tlsh-951da108"
        family = ""
        hash = "0120990444ff05bbbe7d31f874319b23d43e2376052840e7f42696c69638206c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-951da108.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ngs.rsfn5+fiBJTkMgUmFuc29tIH5+fn4KCi0tLS0tPiBZb3VyIGRhdGEgaXMgc3RvbGVuIGFuZCBlbmNyeXB0ZWQuCklmIHlvdS" ascii
        $s1 = "BhdHRhY2tzLiAKCi0tLS0tPiBEb24ndCBnbyB0byByZWNvdmVyeSBjb21wYW5pZXMhClRoZXkgYXJlIGVzc2VudGlhbGx5IGp1c3" ascii
        $s2 = "BheWthYmpxYzJtdGR4cTZjMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuanNzeDZxa2lkLm9uaW9uLwoKWW91ciBwZXJzb25hbC" ascii
        $s3 = "BJRDoKCSVpZCUKCi0tLS0tPiBXYXJuaW5nISBEb24ndCBkZWxldGUgb3IgbW9kaWZ5IGVuY3J5cHRlZCBmaWxlcywgaXQgd2lsbC" ascii
        $s4 = "IgaHR0cHM6Ly90d2l0dGVyLmNvbS9oYXNodGFnL2luY3JhbnNvbT9mPWxpdmUKCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IH" ascii
        $s5 = "9hZC5vbmlvbi8KCkxpbmsgZm9yIG5vcm1hbCBicm93c2VyOgoJaHR0cDovL2luY2Jsb2cuc3UvCgkKLS0tLS0+IFdoYXQgZ3Vhcm" ascii
        $s6 = "BheSB0aGUgc2FsYXJpZXMgb2YgeW91ciBzeXN0ZW0gYWRtaW5pc3RyYXRvcnMuIEdldCBvdmVyIGl0IGFuZCBwYXkgZm9yIGl0Lg" ascii
        $s7 = "BjYXNlcyB3aGVyZSByZWNvdmVyeSBjb21wYW5pZXMgdGVsbCB5b3UgdGhhdCB0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2xsYX" ascii
        $s8 = "JzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIHVzIGZvciAkMU0uCklmIHlvdSBhcHByb2FjaGVkIH" ascii
        $s9 = "Jyb3dzZXIgTGluazoKCWh0dHA6Ly9pbmNibG9nNnF1NHk0bW00enZ3NW5ybXVlNnFid3RnanN4cHc2YjdpeHpzc3UzNnRzYWpsZG" ascii
        $s10 = "lvdSB3aWxsIHF1aWNrbHkgcmVzdG9yZSB5b3VyIHN5c3RlbXMgYW5kIG1ha2UgZXZlbiBtb3JlIG1vbmV5LgpUcmVhdCB0aGlzIH" ascii
        $s11 = "RlbnMgb2YgY29tcGFuaWVzIGFyb3VuZCB0aGUgd29ybGQuCgpUb3IgQnJvd3NlciBMaW5rIGZvciBjaGF0OgoJaHR0cDovL2luY3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2249456 and 12 of them
}
