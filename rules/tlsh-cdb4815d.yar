rule Sightlines_tlsh_cdb4815d_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cdb4815d"
        date = "2026-10-27"
        campaign = "tlsh-cdb4815d"
        family = "silentnet"
        hash = "1488081eee0a4dce77a71e615fb0879193168ef4a81e25dab2d1caa674535480"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cdb4815d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "net/anubis/client/gui/HudRenderer$SpotifyGlyph.classPK" ascii
        $s1 = "net/anubis/client/gui/HudRenderer$SpotifyLook.classPK" ascii
        $s2 = "net/anubis/client/module/impl/client/SpotifyHudModule$TrackLyrics.classPK" ascii
        $s3 = "net/anubis/client/module/impl/client/SpotifyHudModule$LyricHighlight.classPK" ascii
        $s4 = "net/anubis/client/module/impl/render/BlockEntityDebugModule$1.classPK" ascii
        $s5 = "net/anubis/client/module/ModuleRegistry$TypeIndex.classPK" ascii
        $s6 = "net/anubis/client/module/impl/combat/CrystalAuraModule$Fight.classPK" ascii
        $s7 = "net/anubis/client/module/impl/combat/CrystalOptimizerModule$AttackProbe.classPK" ascii
        $s8 = "net/anubis/client/gui/HudRenderer$SpotifyColors.classPK" ascii
        $s9 = "net/anubis/client/gui/HudRenderer$SpotifyCard.classPK" ascii
        $s10 = "net/anubis/client/module/impl/combat/CrystalOptimizerModule$Ghost.classPK" ascii
        $s11 = "net/anubis/client/module/impl/misc/AntiVanishModule$ObservationType.classPK" ascii
    condition:
        filesize < 40856028 and 12 of them
}
