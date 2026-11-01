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
