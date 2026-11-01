rule Sightlines_imphash_7fa38c68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7fa38c68"
        date = "2026-10-20"
        campaign = "imphash-7fa38c68"
        family = ""
        hash = "4fc04b64ff9fe77be60ebf30dec9bf876ccc5eff4e344f8f23cddaeeb4485957"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7fa38c68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96" ascii
        $s1 = "ortedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s3 = "ndentAssembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedP" ascii
        $s4 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s5 = "-4fbd-8e2d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s6 = "ependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\"" ascii
        $s7 = "ity></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supp" ascii
        $s8 = "RMDir: RemoveDirectory invalid input(\"%s\")" wide
        $s9 = "File: overwriteflag=%d, allowskipfilesflag=%d, name=\"%s\"" wide
        $s10 = "rivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></secur" ascii
        $s11 = "ExecShell: warning: error (\"%s\": file:\"%s\" params:\"%s\")=%d" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2696016 and 12 of them
}
