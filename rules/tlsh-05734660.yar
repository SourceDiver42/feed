rule Sightlines_tlsh_05734660_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05734660"
        date = "2026-10-27"
        campaign = "tlsh-05734660"
        family = "formbook"
        hash = "13e589b57234b7eb7b0023cae55629f474051f3c3aaaa3df65b083f8156cb860"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05734660.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Data Source=DESKTOP-BH4JOH6;Initial Catalog=QL_KARAOKE;User ID=sa;Password=123456;Integrated Securit" wide
        $s1 = "Data Source=DESKTOP-BH4JOH6;Initial Catalog=QL_KARAOKE;Integrated Security= True" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "BaoCaoNMCNPM_KARAOKE.frm_khachHang.resources" ascii
        $s4 = "BaoCaoNMCNPM_KARAOKE.frm_quanLy.resources" ascii
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "BaoCaoNMCNPM_KARAOKE.form_DangNhap.resources" ascii
        $s7 = "BaoCaoNMCNPM_KARAOKE.frm_phong.resources" ascii
        $s8 = "BaoCaoNMCNPM_KARAOKE.frm_nhanVien.resources" ascii
        $s9 = "select count(*) from PHONG where MAPHONG='" wide
        $s10 = "BaoCaoNMCNPM_KARAOKE.fm_thanhToan.resources" ascii
        $s11 = "select count(*) from TAIKHOAN where username='" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1690624 and 12 of them
}
