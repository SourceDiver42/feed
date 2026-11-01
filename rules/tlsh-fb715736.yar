rule Sightlines_tlsh_fb715736_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fb715736"
        date = "2026-10-20"
        campaign = "tlsh-fb715736"
        family = ""
        hash = "04f32dd4e681959fb26a3d11aa58874680d1a867b2ca5770670c2fdf91736a04"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fb715736.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/odtheking/odin/features/impl/skyblock/QuiverDisplay$quiverHud$2.classPK" ascii
        $s1 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$STARTS_WITH.classPK" ascii
        $s2 = "com/odtheking/odin/features/impl/boss/WitherDragonsEnumKt$handleSpawnPacket$2$1.classPK" ascii
        $s3 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$NUMBERS.classPK" ascii
        $s4 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$overflowManaHud$2.classPK" ascii
        $s5 = "com/odtheking/odin/utils/network/WebUtils$sam$java_util_function_BiConsumer$0.classPK" ascii
        $s6 = "com/odtheking/odin/features/impl/boss/termGUI/MelodyGui$buildTerminal$1$1.classPK" ascii
        $s7 = "com/odtheking/odin/features/impl/skyblock/ChatCommands$partyAllInvite$2.classPK" ascii
        $s8 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideOverflow$2.classPK" ascii
        $s9 = "com/odtheking/odin/features/impl/dungeon/InvincibilityTimer$equippedMaskColor$2.classPK" ascii
        $s10 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideZeroSF$2.classPK" ascii
        $s11 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$MELODY.classPK" ascii
    condition:
        filesize < 7770436 and 12 of them
}
