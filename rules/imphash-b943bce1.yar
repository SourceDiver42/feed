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
