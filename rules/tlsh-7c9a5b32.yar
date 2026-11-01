rule Sightlines_tlsh_7c9a5b32_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7c9a5b32"
        date = "2026-10-31"
        campaign = "tlsh-7c9a5b32"
        family = ""
        hash = "2d51acdec5b982fb3181f661642cf6d628b162dd12e93b32008a3a2469461347"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7c9a5b32.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ",+-+/.0.2143657598;:<:?>A@B@DCECJIRQSRTRUQVQWQXQYQZQ^]_]`]a]b]cbd]e]onpnqnrn" wide
        $s1 = "ESystem.IO.Compression.ZipArchiveEntry+<ThrowIfNotOpenableAsync>d__137" ascii
        $s2 = "PSystem.IO.Compression.Zip64EndOfCentralDirectoryLocator+<TryReadBlockAsync>d__10" ascii
        $s3 = "NSystem.IO.Compression.ZipArchive+<TryReadZip64EndOfCentralDirectoryAsync>d__80" ascii
        $s4 = "TSystem.IO.Compression.ZipArchiveEntry+<LoadLocalHeaderExtraFieldIfNeededAsync>d__134" ascii
        $s5 = "VSystem.IO.Compression.ZipArchiveEntry+<WriteLocalFileHeaderAndDataIfNeededAsync>d__142" ascii
        $s6 = "?System.IO.Compression.DeflateStream+<<FlushAsync>g__Core|37_0>d" ascii
        $s7 = "OSystem.IO.Compression.Zip64EndOfCentralDirectoryRecord+<TryReadBlockAsync>d__18" ascii
        $s8 = "DSystem.IO.Compression.ZipHelper+<SeekBackwardsToSignatureAsync>d__12" ascii
        $s9 = "PSystem.IO.Compression.ZipArchiveEntry+<WriteCrcAndSizesInLocalHeaderAsync>d__143" ascii
        $s10 = "GSystem.IO.Compression.ZipArchiveEntry+<WriteLocalFileHeaderAsync>d__141" ascii
        $s11 = "ISystem.IO.Compression.ZipEndOfCentralDirectoryBlock+<ReadBlockAsync>d__19" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
