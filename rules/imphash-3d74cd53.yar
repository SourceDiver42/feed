rule Sightlines_imphash_3d74cd53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3d74cd53"
        date = "2026-10-30"
        campaign = "imphash-3d74cd53"
        family = ""
        hash = "56bb65dd4756314a643b270a77fe67f6b44219d7258ef5900fbc01618da3f76a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3d74cd53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SkNCiB9Ow0KICRiYXRjaEV4ZWN1dGVkPSgkc2V0dGluZ3MuYWRtaW5ydW4gLWVxICR0cnVlKTsNCiBpZiAoLW5vdCAkYmF0Y2hFe" ascii
        $s1 = "W5ncy5hZG1pbnJ1bj0kdHJ1ZTsNCiAgICAgJGJhdGNoRmlsZVBhdGg9IiRlbnY6QXBwRGF0YVwkcmFuZG9tU3RyaW5nLmJhdCI7D" ascii
        $s2 = "y1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkRmlsZSgnaHR0cHM6Ly9naXRodWIuY29tL3Rob21zb24xMDEvd" ascii
        $s3 = "G9tc29uMTAxL3Rob21zb24xMDEvcmVsZWFzZXMvZG93bmxvYWQvUm9sZS9zb3VyY2UuYmF0JywgJGJhdGNoRmlsZVBhdGgpOw0KI" ascii
        $s4 = "QogICAgIChOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZEZpbGUoJ2h0dHBzOi8vZ2l0aHViLmNvbS90a" ascii
        $s5 = "F06OkdldFJhbmRvbUZpbGVOYW1lKCkuUmVwbGFjZSgiLiIsICIiKTsNCiBpZiAoJHNldHRpbmdzLldEKSB7DQogICAgICRzZXR0a" ascii
        $s6 = "W5ncz0oJ3sgIldEIjogZmFsc2UsICJhZG1pbnJ1biI6IGZhbHNlIH0nIHwgQ29udmVydEZyb20tSnNvbik7DQogJGV4Y2x1c2lvb" ascii
        $s7 = "GVjdXRlZCkgew0KICAgICAkYmF0Y2hGaWxlUGF0aD0iJGVudjpBcHBEYXRhXCRyYW5kb21TdHJpbmcuYmF0IjsNCiAgICAgKE5ld" ascii
        $s8 = "GhvbXNvbjEwMS9yZWxlYXNlcy9kb3dubG9hZC9Sb2xlL3NvdXJjZS5iYXQnLCAkYmF0Y2hGaWxlUGF0aCk7DQogICAgIFN0YXJ0L" ascii
        $s9 = "VByb2Nlc3MgLUZpbGVQYXRoICRiYXRjaEZpbGVQYXRoIC1XaW5kb3dTdHlsZSBIaWRkZW4gLVdhaXQgLVZlcmIgUnVuQXMNCiB9O" ascii
        $s10 = "U1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUHJvY2VzcyAkb3V0cHV0UGF0aDsNCiAkcmFuZG9tU3RyaW5nPVtTeXN0ZW0uSU8uUGF0a" ascii
        $s11 = "lBhdGg9JGVudjpBcHBEYXRhOw0KIEFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblBhdGggJGV4Y2x1c2lvblBhdGg7DQogQWRkL" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
