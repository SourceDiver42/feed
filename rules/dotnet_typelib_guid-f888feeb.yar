rule Sightlines_dotnet_typelib_guid_f888feeb_quasarrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f888feeb"
        date = "2026-10-28"
        campaign = "dotnet_typelib_guid-f888feeb"
        family = "quasarrat"
        hash = "0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f888feeb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerM" ascii
        $s1 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide
        $s2 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "SELECT Caption FROM Win32_OperatingSystem" wide
        $s5 = "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />Log created on " wide
        $s6 = "]Please use RuntimeTypeModel.Default.InferTagFromNameDefault instead (or on a per-model basis)" ascii
        $s7 = "System.Collections.Generic.IEnumerator<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.get_Current" ascii
        $s8 = "System.Collections.Generic.IEnumerable<Gma.System.MouseKeyHook.KeyPressEventArgsExt>.GetEnumerator" ascii
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "<style>.h { color: 0000ff; display: inline; }</style>" wide
        $s11 = "ProtoBuf.IProtoInput<System.Byte[]>.Deserialize" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10258432 and 6 of them
}
