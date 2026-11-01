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
