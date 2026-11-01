rule Sightlines_dotnet_typelib_guid_68c1cd29_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-68c1cd29"
        date = "2026-10-20"
        campaign = "dotnet_typelib_guid-68c1cd29"
        family = ""
        hash = "0e3020607aec6a3d096692f24f1e390c44073f6b0e31c3260f21beced5e9bcce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-68c1cd29.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "select sum(SoLuong) from ChiTietHD where MaCTHD = '" wide
        $s1 = "select count(*) from KhachHang where SoDienThoai = '" wide
        $s2 = "select count(*) from TaiKhoan where MANV is null and TenTK = '" wide
        $s3 = "select * from KhachHang where SoDienThoai like '%'+'" wide
        $s4 = "select * from KhachHang where HoTen like N'%'+'" wide
        $s5 = "select count(*) from HoaDon where ThoiGian is not null and MaHD = '" wide
        $s6 = "select HoTen FROM KhachHang where SoDienThoai = '" wide
        $s7 = "select * from KhachHang where GioiTinh = N'" wide
        $s8 = "select MANV from TaiKhoan where TenTK ='" wide
        $s9 = "select LinkHinh from SanPham where MaSP = '" wide
        $s10 = "select DiaChi from KhachHang where SoDienThoai = '" wide
        $s11 = "select count(*) from HoaDon where MaHD = '" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2701312 and 12 of them
}
