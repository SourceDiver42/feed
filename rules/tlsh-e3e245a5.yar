rule Sightlines_tlsh_e3e245a5_blakcseestealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e3e245a5"
        date = "2026-10-20"
        campaign = "tlsh-e3e245a5"
        family = "blakcseestealer"
        hash = "554fb593a7e086360b68f90dfcee8aef9bd9a25659dedae188a85bd756b3ea87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e3e245a5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_68e3b65500009b224cfd4b39ddd88c46>@@XAEBV?$basic_string@DU?$char_t" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_2bd2efc0f489c80c64f6c76a3f06661d>@@XAEBV?$basic_string@DU?$char_t" ascii
        $s2 = "GetElevationKey: FINAL RESULT - COM decryption failed (empty result)" ascii
        $s3 = "Payload DLL: CLSIDFromString failed, hr=0x%08X, clsid=%s" ascii
        $s4 = "Payload DLL: CoCreateInstance(Edge) failed, hr=0x%08X, err=%lu" ascii
        $s5 = "(match_len >= TDEFL_MIN_MATCH_LEN) && (match_dist >= 1) && (match_dist <= TDEFL_LZ_DICT_SIZE)" wide
        $s6 = "Payload DLL: DecryptData FAILED, hr=0x%08X, COM_lastErr=%lu, GetLastErr=%lu" ascii
        $s7 = "Payload DLL: IIDFromString failed, hr=0x%08X, iid=%s" ascii
        $s8 = "DecryptDPAPI: CryptUnprotectData FAILED, error=0x%08X (%lu)" ascii
        $s9 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $s10 = "CallCOMDecryptData: Bootstrap TIMEOUT or FAILED, result=%d" ascii
        $s11 = "SendFileToServer: shutdown(SD_SEND), waiting for response..." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1811456 and 9 of them
}
