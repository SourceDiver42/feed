rule Sightlines_imphash_e902016c_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e902016c"
        date = "2026-11-01"
        campaign = "imphash-e902016c"
        family = "valleyrat"
        hash = "016143621e08cb0e50eef27249ff0ab605cf6912ee15fecba9a14103cb287b0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e902016c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[!] STATUS_OBJECT_NAME_COLLISION: Service/object name already exists." ascii
        $s1 = "[%u:%u.%u]: DriverEntry(DriverObject=0x%p; RegistryPath=\"%wZ\")" ascii
        $s2 = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
        $s3 = "[!] STATUS_IMAGE_ALREADY_LOADED: Driver was already in memory." ascii
        $s4 = "SELECT displayName FROM AntiVirusProduct" wide
        $s5 = "[%u:%u.%u]: RemoveClient(DeviceExtension=0x%p; ProcessId=0x%p)" ascii
        $s6 = "[%u:%u.%u]: FindClient(DeviceExtension=0x%p; ProcessId=0x%p)" ascii
        $s7 = "[%u:%u.%u]: _FlushDpcRoutine(Dpc=0x%p, Arg1=0x%p, Arg2=0x%p, Arg3=0x%p)" ascii
        $s8 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $s9 = "[%u:%u.%u]: ProcessCallback(Process=0x%p; ProcessId=0x%p; CreateInfo=0x%p)" ascii
        $s10 = "_SaveBootDebugRequest: ZwCreateFile(\"%wZ\"): 0x%x" ascii
        $s11 = "D:\\_work\\75\\s\\Safetica\\Endpoint\\Compiled\\x64\\Release\\ProcessMonitorDriver.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
