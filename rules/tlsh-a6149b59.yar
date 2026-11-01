rule Sightlines_tlsh_a6149b59_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a6149b59"
        date = "2026-10-20"
        campaign = "tlsh-a6149b59"
        family = ""
        hash = "77283baa36cee15b9d4d5f9ae252fc2bbd2e0e7ff3dae0994786ecb338c6f81d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a6149b59.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$ENTITY.classPK" ascii
        $s1 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$BLOCK.classPK" ascii
        $s2 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$AIR.classPK" ascii
        $s3 = "com/github/noamm9/features/impl/dev/FEAT_WebSocket$init$6$1.classPK" ascii
        $s4 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$ENTITY.classPK" ascii
        $s5 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$BLOCK.classPK" ascii
        $s6 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$AIR.classPK" ascii
        $s7 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK.classPK" ascii
        $s8 = "com/github/noamm9/features/impl/floor7/LeapCounter$REGION$updateCounter$1.classPK" ascii
        $s9 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK.classPK" ascii
        $s10 = "com/github/noamm9/features/impl/floor7/LeapCounter$REGION.classPK" ascii
        $s11 = "com/github/noamm9/features/impl/dungeon/solvers/puzzles/WaterBoardSolver$LEVER$Companion.classPK" ascii
    condition:
        filesize < 27263666 and 12 of them
}
