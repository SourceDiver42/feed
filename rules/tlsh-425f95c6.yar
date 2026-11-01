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
