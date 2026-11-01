rule Sightlines_tlsh_bd96c2c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bd96c2c5"
        date = "2026-10-22"
        campaign = "tlsh-bd96c2c5"
        family = ""
        hash = "408bed94fb0961193dbea6bebc82b9a8ff5fe645e9dd5a095296969e55757c27"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bd96c2c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "                'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\' + CONFIG.REG_VALUE_NAME," ascii
        $s1 = "            taskService.GetFolder('\\\\').GetTask(CONFIG.TASK_NAME);" ascii
        $s2 = "        var path = CONFIG.TEMP_DIR + randomName(CONFIG.SCRIPT_EXT);" ascii
        $s3 = "    var fso = new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s4 = "        if (fso.FolderExists(CONFIG.TEMP_DIR)) return true;" ascii
        $s5 = "    var wsh = new ActiveXObject('WScript.Shell');" ascii
        $s6 = "        REG_VALUE_NAME: 'SystemHealthMonitor'," ascii
        $s7 = "        var xhr = new ActiveXObject('MSXML2.XMLHTTP');" ascii
        $s8 = "            def.RegistrationInfo.Description = CONFIG.DESCRIPTION;" ascii
        $s9 = "        DESCRIPTION: 'Windows System Maintenance Utility'" ascii
        $s10 = "    function registerScheduledTask(scriptPath) {" ascii
        $s11 = "    var taskService = new ActiveXObject('Schedule.Service');" ascii
    condition:
        filesize < 1048576 and 12 of them
}
