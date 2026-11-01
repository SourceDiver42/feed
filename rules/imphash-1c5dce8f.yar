rule Sightlines_imphash_1c5dce8f_aokigaharastealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1c5dce8f"
        date = "2026-11-01"
        campaign = "imphash-1c5dce8f"
        family = "aokigaharastealer"
        hash = "1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1c5dce8f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "%s\\Packages\\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\\LocalCache\\Roaming\\ChatGPT" ascii
        $s2 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s3 = "Software\\Microsoft\\Office\\%s\\Outlook\\Profiles\\%s\\9375CFF0413111d3B88A00104B2A6676" ascii
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s5 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s6 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s7 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s8 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s9 = "C:\\Program Files (x86)\\Mozilla Thunderbird" ascii
        $s10 = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0" ascii
        $s11 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
