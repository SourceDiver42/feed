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
