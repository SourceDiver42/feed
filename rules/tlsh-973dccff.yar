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
