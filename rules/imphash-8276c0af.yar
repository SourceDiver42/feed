rule Sightlines_imphash_8276c0af_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8276c0af"
        date = "2026-11-01"
        campaign = "imphash-8276c0af"
        family = ""
        hash = "1bec46428cbd7887a6e17b51610876330daccdcb62c367520078ae965a9c2825"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8276c0af.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "drive.usercontent.google.com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=" ascii
        $s1 = "0J7EFGABCeuvdDK489SEV56ewf332Nd123sfeW4werf5FDGwYZRtwz" ascii
        $s2 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZM" ascii
        $s3 = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1" ascii
        $s4 = "The program can't start because MSVCP140.dll is missing from your computer. Try reinstalling the pro" ascii
        $s5 = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8" ascii
        $s6 = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0" ascii
        $s7 = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, i" ascii
        $s8 = "FileHeader.Machine != HOST_MACHINE!" ascii
        $s9 = "Signature != IMAGE_NT_SIGNATURE!" ascii
        $s10 = "alignedImageSize != AlignValueUp!" ascii
        $s11 = "4$4,44484<4@4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
