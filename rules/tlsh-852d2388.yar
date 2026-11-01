rule Sightlines_tlsh_852d2388_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-852d2388"
        date = "2026-10-30"
        campaign = "tlsh-852d2388"
        family = ""
        hash = "232617200d1f8ebce1226839ca305e976a0b00f797a331886dac553e115b2e42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-852d2388.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_sun_nio_fs_WindowsNativeDispatcher_CreateSymbolicLink0" ascii
        $s1 = "Java_sun_nio_ch_Net_canUseIPv6OptionsWithIPv4LocalAddress0" ascii
        $s2 = "Java_sun_nio_fs_WindowsNativeDispatcher_CopyFileEx0" ascii
        $s3 = "Java_sun_nio_fs_WindowsNativeDispatcher_LookupPrivilegeValue0" ascii
        $s4 = "Java_sun_nio_ch_Net_shouldSetBothIPv4AndIPv6Options0" ascii
        $s5 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetDiskFreeSpaceEx0" ascii
        $s6 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetFileAttributesEx0" ascii
        $s7 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetFinalPathNameByHandle" ascii
        $s8 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetFullPathName0" ascii
        $s9 = "Java_sun_nio_ch_WindowsAsynchronousServerSocketChannelImpl_updateAcceptContext" ascii
        $s10 = "Java_sun_nio_ch_WindowsAsynchronousSocketChannelImpl_write0" ascii
        $s11 = "Java_sun_nio_fs_WindowsNativeDispatcher_AdjustTokenPrivileges" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
