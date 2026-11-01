rule Sightlines_tlsh_acc41f66_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-acc41f66"
        date = "2026-10-30"
        campaign = "tlsh-acc41f66"
        family = "prometei"
        hash = "aa39b28aa15bfb60099a0a9421529fda51426415443da2cbb9fc567a45375f08"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-acc41f66.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = ".ab'Wr%Wcde%Wr%fgr%WrhijWr%Wklm%Wr%nor%WrpqrWr%Wstu%Wr%vwr%WrxyzWr%WABC%Wr%DEr%WrFGHWr%WIJK%Wr%LMr%W" ascii
        $s3 = "NQRSTNNNNUVWXNNNNYZ[\\NNNN]^_`NNNNabcdNNNNefghNNNNijklNNNNmnopNNNNqrstNNNNuvwxNNNNyz{|NNNN}~" ascii
        $s4 = "9QRST9999VWXY9999Z[\\]9999^_`a9999bcde9999fghi9999jklm9999nopq9999rstu9999vwxy9999z{|}9999~" ascii
        $s5 = " 9999!\"#$9999%&'(9999)*+,9999-./0999912349999567899999:;<9999=>?@9999ABCD9999EFGH9999IJKL9999MNOP999" ascii
        $s6 = " NNNN!\"#$NNNN%&'(NNNN)*+,NNNN-./0NNNN1234NNNN5678NNNN9:;<NNNN=>?@NNNNABCDNNNNEFGHNNNNIJKLNNNNMNOPNNN" ascii
        $s7 = " rrrr\"$%&rrrr/567rrrr9:<DrrrrGHI_rrrr`abczrrr" ascii
        $s8 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s9 = "w`GtvRsdC7PYqIEXKfs@7" ascii
        $s10 = "GCC: (Ubuntu 9.3.0-17u" ascii
        $s11 = "rNOPWr%WQRS%Wr%TUr%WrVWX" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
