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
