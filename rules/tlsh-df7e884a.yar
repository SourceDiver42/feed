rule Sightlines_tlsh_df7e884a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-df7e884a"
        date = "2026-10-23"
        campaign = "tlsh-df7e884a"
        family = ""
        hash = "55e752670ec450ecb29c3c21f3f683e13ce7d51d0025fcff2c5f7d70ee045487"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-df7e884a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dev/krypton/native/x86_64-windowsPK" ascii
        $s1 = "assets/minecraft/shaders/post-process/PK" ascii
        $s2 = "dev/krypton/native/x86_64-windows<" ascii
        $s3 = "assets/krypton/shaders/post-process/PK" ascii
        $s4 = "krypton-render.mixins.jsonPK" ascii
        $s5 = "assets/minecraft/shaders/PK" ascii
        $s6 = "dev/krypton/diddy/mixin/PK" ascii
        $s7 = "assets/krypton/shaders/PK" ascii
        $s8 = "assets/krypton/fonts/PK" ascii
        $s9 = "dev/krypton/xative/PK" ascii
        $s10 = "javazoom/jl/decoder/PK" ascii
        $s11 = "dev/krypton/native/PK" ascii
    condition:
        filesize < 11806636 and 12 of them
}
