rule Sightlines_rich_header_hash_765116da_guloader
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-765116da"
        date = "2026-10-30"
        campaign = "rich_header_hash-765116da"
        family = "guloader"
        hash = "27cb385ffdd96c18ac7bcfd42a121e5cc4b526da818a7e3694b72655e4d5142a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-765116da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2" ascii
        $s1 = "d=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"" ascii
        $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s3 = "mbly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii
        $s4 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s5 = "stInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS I" ascii
        $s6 = "><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=" ascii
        $s7 = "d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s8 = "><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></tru" ascii
        $s9 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s10 = "Installer integrity check has failed. Common causes include" wide
        $s11 = "Error writing temporary file. Make sure your temp folder is valid." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2555904 and 12 of them
}
