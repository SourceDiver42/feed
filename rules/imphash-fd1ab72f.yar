rule Sightlines_imphash_fd1ab72f_inc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fd1ab72f"
        date = "2026-10-21"
        campaign = "imphash-fd1ab72f"
        family = "inc"
        hash = "0ae4447d755593ee1931170d4187a07a29bf0690179acc39b7400a4c65cd07c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fd1ab72f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "uZXIgeW91ciBjb21wYW55IHdpbGwgYmUgc2FmZS4NCg0KVG9yIEJyb3dzZXIgTGluazoNCglodHRwOi8vaW5jYmxvZzZxdTR5NG1" ascii
        $s1 = "jMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuanNzeDZxa2lkLm9uaW9uLw0KDQpZb3VyIHBlcnNvbmFsIElEOg0KCSVpZCUNCg0" ascii
        $s2 = "sYXJzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIHVzIGZvciAkMU0uDQpJZiB5b3UgYXBwcm9hY2h" ascii
        $s3 = "yb3VuZCB0aGUgd29ybGQuDQoNClRvciBCcm93c2VyIExpbmsgZm9yIGNoYXQ6DQoJaHR0cDovL2luY3BheWthYmpxYzJtdGR4cTZ" ascii
        $s4 = "0dGFja3MuIA0KDQotLS0tLT4gRG9uJ3QgZ28gdG8gcmVjb3ZlcnkgY29tcGFuaWVzIQ0KVGhleSBhcmUgZXNzZW50aWFsbHkganV" ascii
        $s5 = "tNHp2dzVucm11ZTZxYnd0Z2pzeHB3NmI3aXh6c3N1MzZ0c2FqbGRvYWQub25pb24vDQoNCkxpbmsgZm9yIG5vcm1hbCBicm93c2V" ascii
        $s6 = "zaHRhZy9pbmNyYW5zb20/Zj1saXZlDQoNCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IHVzIG9uIFRPUiBkYXJrbmV0IHNpdGV" ascii
        $s7 = "wdWJsaXNoZWQgb24gb3VyIFRPUiBkYXJrbmV0IHNpdGVzLg0KVGhlIHNvb25lciB5b3UgcGF5IHRoZSByYW5zb20sIHRoZSBzb29" ascii
        $s8 = "vZiBjYXNlcyB3aGVyZSByZWNvdmVyeSBjb21wYW5pZXMgdGVsbCB5b3UgdGhhdCB0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2x" ascii
        $s9 = "yOg0KCWh0dHA6Ly9pbmNibG9nLnN1Lw0KCQ0KLS0tLS0+IFdoYXQgZ3VhcmFudGVlcyBhcmUgdGhhdCB3ZSB3b24ndCBmb29sIHl" ascii
        $s10 = "vdT8NCldlIGFyZSBub3QgYSBwb2xpdGljYWxseSBtb3RpdmF0ZWQgZ3JvdXAgYW5kIHdlIHdhbnQgbm90aGluZyBtb3JlIHRoYW4" ascii
        $s11 = "tb3N0IGNhc2VzLCB3ZSBmaW5kIHRoaXMgaW5mb3JtYXRpb24gYW5kIGRvd25sb2FkIGl0Lg0KDQotLS0tLT4gSWYgeW91IGRvIG5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4412416 and 12 of them
}
