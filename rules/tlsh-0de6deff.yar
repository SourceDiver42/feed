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
