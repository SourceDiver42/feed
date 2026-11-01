rule Sightlines_tlsh_e2b22837_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e2b22837"
        date = "2026-10-30"
        campaign = "tlsh-e2b22837"
        family = ""
        hash = "3b87e6a5e57e3c548a7ea1ffa1a756a027fee0efc92ce829b07a12b8c1765bef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e2b22837.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_MixinApplication197&RenderProxyBox&_RenderTheaterMixin&RenderObjectWithLayoutCallbackMixin@18353248" ascii
        $s1 = "_MixinApplication94&RenderBox&RelayoutWhenSystemFontsChangeMixin@18353248." ascii
        $s2 = "_MixinApplication61&StandardFabLocation&FabCenterOffsetX&FabDockedOffsetY@18353248" ascii
        $s3 = "_MixinApplication63&StandardFabLocation&FabEndOffsetX&FabDockedOffsetY@18353248" ascii
        $s4 = "_MixinApplication169&ValueNotifier&WidgetsBindingObserver@18353248" ascii
        $s5 = "_MixinApplication50&StandardFabLocation&FabEndOffsetX&FabTopOffsetY@18353248" ascii
        $s6 = "_MixinApplication52&StandardFabLocation&FabMiniOffsetAdjustment&FabEndOffsetX&FabTopOffsetY@18353248" ascii
        $s7 = "__Float32ArrayView&_TypedListView&_DoubleListMixin@8027147" ascii
        $s8 = "_MixinApplication46&StandardFabLocation&FabCenterOffsetX&FabTopOffsetY@18353248" ascii
        $s9 = "_MixinApplication59&StandardFabLocation&FabStartOffsetX&FabDockedOffsetY@18353248" ascii
        $s10 = "_MixinApplication64&StandardFabLocation&FabMiniOffsetAdjustment&FabEndOffsetX&FabDockedOffsetY@18353" ascii
        $s11 = "__getCallbackFromHandle$Method$FfiNative@37065589" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 12846864 and 12 of them
}
