rule Sightlines_tlsh_d3bce0aa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d3bce0aa"
        date = "2026-10-31"
        campaign = "tlsh-d3bce0aa"
        family = ""
        hash = "743910e92ed832d96d003461df578633245755cd92dc4859feccf10b03794be7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d3bce0aa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3 8!9\":#;$<%=&>'?(@)G*H+I,J-K.L/M0N1O2P3Q4R5S6T7U8V9W:^;_<i=j>k?l@mAnBoCpDqErFsGtHuIvJwKxLyMzN{O|P}Q" wide
        $s1 = "9System.Linq.AsyncEnumerable+<<RightJoin>g__Impl|125_0>d`4" ascii
        $s2 = "9System.Linq.AsyncEnumerable+<<RightJoin>g__Impl|126_0>d`4" ascii
        $s3 = "=System.Linq.AsyncEnumerable+<<ToLookupAsync>g__Impl|189_0>d`2" ascii
        $s4 = "=System.Linq.AsyncEnumerable+<<ToLookupAsync>g__Impl|192_0>d`3" ascii
        $s5 = "6System.Linq.AsyncEnumerable+<<GroupBy>g__Impl|71_0>d`4" ascii
        $s6 = "8System.Linq.AsyncEnumerable+<<GroupJoin>g__Impl|73_0>d`4" ascii
        $s7 = "9System.Linq.AsyncEnumerable+<<TakeWhile>g__Impl|175_0>d`1" ascii
        $s8 = "9System.Linq.AsyncEnumerable+<<TakeWhile>g__Impl|176_0>d`1" ascii
        $s9 = "9System.Linq.AsyncEnumerable+<<TakeWhile>g__Impl|178_0>d`1" ascii
        $s10 = "7System.Linq.AsyncEnumerable+<<UnionBy>g__Impl|196_0>d`2" ascii
        $s11 = "BSystem.Linq.AsyncEnumerable+<<FirstOrDefaultAsync>g__Impl|59_0>d`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2585104 and 12 of them
}
