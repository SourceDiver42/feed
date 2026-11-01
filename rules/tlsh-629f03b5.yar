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
