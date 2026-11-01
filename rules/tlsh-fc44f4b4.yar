rule Sightlines_tlsh_fc44f4b4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fc44f4b4"
        date = "2026-10-31"
        campaign = "tlsh-fc44f4b4"
        family = ""
        hash = "538b69cc037ccab32129f3983113f80bed9d4903dc2fdddc134df0c3432b46fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fc44f4b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading.Channels/Release/net10.0/System.Threading.Channels.pdb" ascii
        $s4 = "TryDequeueAndReserveCompletionIfCancelable" ascii
        $s5 = "<SetCompletionAndInvokeContinuation>b__27_0" ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = ",Another continuation was already registered.c" ascii
        $s8 = "<get_CancellationCallbackDelegate>b__13_0" ascii
        $s9 = "<get_CancellationCallbackDelegate>b__16_0" ascii
        $s10 = "<get_CancellationCallbackDelegate>b__18_0" ascii
        $s11 = "<CancellationCallbackDelegate>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
