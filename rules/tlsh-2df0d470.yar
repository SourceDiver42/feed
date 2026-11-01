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
