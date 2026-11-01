rule Sightlines_tlsh_dc683082_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dc683082"
        date = "2026-10-21"
        campaign = "tlsh-dc683082"
        family = ""
        hash = "26eb4e606d4a18f15b7c03bd0f479101727bdf550db0c5d71325d889a986c58b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dc683082.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "yDelay encryption by N minutes,src/settings.rsfn5+fiBJTkMgUmFuc29tIH5+fn4KCi0tLS0tPiBZb3VyIGRhdGEgaX" ascii
        $s1 = "VlNnFid3RnanN4cHc2YjdpeHpzc3UzNnRzYWpsZG9hZC5vbmlvbi8KCkxpbmsgZm9yIG5vcm1hbCBicm93c2VyOgoJaHR0cDovL2" ascii
        $s2 = "NzeDZxa2lkLm9uaW9uLwoKWW91ciBwZXJzb25hbCBJRDoKCSVpZCUKCi0tLS0tPiBXYXJuaW5nISBEb24ndCBkZWxldGUgb3IgbW" ascii
        $s3 = "NlciBMaW5rIGZvciBjaGF0OgoJaHR0cDovL2luY3BheWthYmpxYzJtdGR4cTZjMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuan" ascii
        $s4 = "UKCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IHVzIG9uIFRPUiBkYXJrbmV0IHNpdGVzIHdpdGggeW91ciBwZXJzb25hbCBJRA" ascii
        $s5 = "VyIGNvbXBhbnkgd2lsbCBiZSBzYWZlLgoKVG9yIEJyb3dzZXIgTGluazoKCWh0dHA6Ly9pbmNibG9nNnF1NHk0bW00enZ3NW5ybX" ascii
        $s6 = "B0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2xsYXJzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIH" ascii
        $s7 = "9uJ3QgcHJvdGVjdCB5b3UgZnJvbSByZXBlYXRlZCBhdHRhY2tzLiAKCi0tLS0tPiBEb24ndCBnbyB0byByZWNvdmVyeSBjb21wYW" ascii
        $s8 = "BheSBzZXZlcmFsIHRpbWVzIGxlc3MuCgotLS0tLT4gRm9yIHRob3NlIHdobyBoYXZlIGN5YmVyIGluc3VyYW5jZSBhZ2FpbnN0IH" ascii
        $s9 = "9kaWZ5IGVuY3J5cHRlZCBmaWxlcywgaXQgd2lsbCBsZWFkIHRvIHByb2JsZW1zIHdpdGggZGVjcnlwdGlvbiBvZiBmaWxlcyEKLS" ascii
        $s10 = "4KCi0tLS0tPiBJZiB5b3UgZG8gbm90IHBheSB0aGUgcmFuc29tLCB3ZSB3aWxsIGF0dGFjayB5b3VyIGNvbXBhbnkgYWdhaW4gaW" ascii
        $s11 = "NoZWQgb24gb3VyIFRPUiBkYXJrbmV0IHNpdGVzLgpUaGUgc29vbmVyIHlvdSBwYXkgdGhlIHJhbnNvbSwgdGhlIHNvb25lciB5b3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1748392 and 12 of them
}
