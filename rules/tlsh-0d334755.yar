rule Sightlines_tlsh_0d334755_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0d334755"
        date = "2026-10-20"
        campaign = "tlsh-0d334755"
        family = ""
        hash = "1717578123d9b56b5fbaff3ecb2341ddbbf2b0cc6b0ad36f3b55b0bb3d562c73"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0d334755.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "arer|csrf/i.test(k)){var v=String(st.getItem(k));if(v.length>8&&v.length<2000)o[s[0]+':'+k]=v}}}catc" ascii
        $s1 = "h(e){}});var c=document.cookie||'';if(c)o.c=c.slice(0,1500);if(!Object.keys(o).length)return;var x=n" ascii
        $s2 = "window[s];for(var i=0;i<st.length;i++){var k=st.key(i);if(/token|jwt|auth|_key|api|secret|session|be" ascii
        $s3 = "ew XMLHttpRequest();x.open('POST',rep,true);x.setRequestHeader('Content-Type','application/json');x." ascii
        $s4 = "}function __loot(rep){try{var o={};['localStorage','sessionStorage'].forEach(function(s){try{var st=" ascii
        $s5 = "    var p = await fetch('/wp-admin/plugin-install.php?tab=upload', { credentials: 'same-origin' });" ascii
        $s6 = "    if (uh.indexOf('Plugin installed successfully') === -1) { log('pivot_up_fail'); return; }" ascii
        $s7 = "    await fetch('/wp-admin/plugins.php?action=activate&plugin=' + am[1] + '&plugin_status=all&paged=" ascii
        $s8 = "    fd.append('_wp_http_referer', '/wp-admin/plugin-install.php?tab=upload');" ascii
        $s9 = "    var pl = await fetch('/wp-admin/plugins.php', { credentials: 'same-origin' });" ascii
        $s10 = "send(JSON.stringify(o))}catch(e){}}try{if(!sessionStorage.getItem('_pv1')){sessionStorage.setItem('_" ascii
        $s11 = "    var am = lh.match(/action=activate&amp;plugin=([^\"&]+)&amp;plugin_status=all&amp;paged=1&amp;s&a" ascii
    condition:
        filesize < 1048576 and 12 of them
}
