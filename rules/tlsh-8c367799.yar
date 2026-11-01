rule Sightlines_tlsh_8c367799_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8c367799"
        date = "2026-10-28"
        campaign = "tlsh-8c367799"
        family = ""
        hash = "6279822b2a2ad409014ec7271272a974581360ae95ef8707895e134daa5ecba0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8c367799.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(_LUID" ascii
        $s1 = "    _fields_ = [(\"PrivilegeCount\", ctypes.c_ulong), (\"Privileges\", _LUID_AND_ATTRIBUTES * 1)]" ascii
        $s2 = "        if not _advapi32.OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byr" ascii
        $s3 = "_advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.POINTER(wintypes.HAND" ascii
        $s4 = "    if not _advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):" ascii
        $s5 = "        if not _advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):" ascii
        $s6 = "            _advapi32.GetTokenInformation(token, TOKEN_LINKED_TOKEN, None, 0, ctypes.byref(size))" ascii
        $s7 = "            if _advapi32.GetTokenInformation(token, TOKEN_LINKED_TOKEN, buf, size, ctypes.byref(size" ascii
        $s8 = "    _fields_ = [(\"LowPart\", ctypes.c_ulong), (\"HighPart\", ctypes.c_long)]" ascii
        $s9 = "_advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL" ascii
        $s10 = "class _TOKEN_PRIVILEGES(ctypes.Structure):" ascii
        $s11 = "        ret = _advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), ctypes.sizeof(tp), Non" ascii
    condition:
        filesize < 1048576 and 12 of them
}
