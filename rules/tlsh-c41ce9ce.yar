rule Sightlines_tlsh_c41ce9ce_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c41ce9ce"
        date = "2026-10-27"
        campaign = "tlsh-c41ce9ce"
        family = ""
        hash = "30d708ca4e2a3dde71855741fd40c581c5a639817798fecffbbd81bb4be3fe39"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c41ce9ce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "return DateKit.padTwo(when.getHours()) + \":\" + DateKit.padTwo(when.getMinutes());" ascii
        $s1 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s2 = "var b = DateKit.startOfDay(second).getTime();" ascii
        $s3 = "NumKit.buildRange = function (start, stop, step) {" ascii
        $s4 = "MoveNext: function () { i++; return i < self.Inner.length; }," ascii
        $s5 = "NumKit.percentOf = function (part, whole) {" ascii
        $s6 = "var childAttribute = new LxKit.Element();" ascii
        $s7 = "NumKit.clamp = function (value, low, high) {" ascii
        $s8 = "var ImportRecursionMode = { Stubs: \"Stubs\", Recursive: \"Recursive\" };" ascii
        $s9 = "var normalized = text.split(\"\\r\\n\").join(\"\\n\");" ascii
        $s10 = "NumKit.roundTo = function (value, digits) {" ascii
        $s11 = "elem = this.Inner[index] = elem.Owner.OnStubRequest(elem.ID);" ascii
    condition:
        filesize < 3079096 and 12 of them
}
