rule Sightlines_tlsh_4e2a2ff6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4e2a2ff6"
        date = "2026-10-17"
        campaign = "tlsh-4e2a2ff6"
        family = ""
        hash = "30a27eaf23cbec3ad0817f339ac43655aed23c96d047d0791d5d8a5db1fba2a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4e2a2ff6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        'W47dN09jW4nAhSkkBvLJzCoAlu9lW5dcQ3KhjWNcL1nvWRjuW5H7nZddVCoPW6rlvCkWWQG'," ascii
        $s1 = "        'yCo6W6LbW73dUbBcPSkHWQNdTCo7W5VcVcZcHLBcLSk6W6NdRNddS8kYW5ZdKwXokCoIWQjgW4uLr1TRW5O'," ascii
        $s2 = "_0x14d7c0] = _0x38d82e, _0x3821ba += String['fromCharCode'](_0x1daf17['charCodeAt'](_0x3479ca) ^ _0x" ascii
        $s3 = "        'wdFdP27cO0RcL8oLiSo7n2b0BmkkzCk0W5KNW5ldR8k1W7/cTfvy'," ascii
        $s4 = "0x1140ba, _0x242679++ % 0x4) ? _0x238764 += String['fromCharCode'](0xff & _0x11774c >> (-0x2 * _0x24" ascii
        $s5 = "XObject(_0x1714ab(0x25)), _0x377284 = new ActiveXObject(_0x522091(0x27));" ascii
        $s6 = "        'qSo2W6XnW7/dVXFcRCkQW6VcNCo3W4/cVf/dKKVcJCkVWQtcJhFdQCo3W53dNa'," ascii
        $s7 = "h[_0x1484f9(0x50, 'mY!u')]()['toString'](0x24)[_0x1af0aa(0x23)](0x2, 0xa)[_0x37da08(0x1d)]();" ascii
        $s8 = "    _0xbe362c[_0x59725f(0x7, 'KsBQ')](), this[_0x522091(0x13)] = _0xbe362c;" ascii
        $s9 = "_0x5bb3e4 = _0x2f60['tEkoJG'](_0x5bb3e4, _0x2f6070), _0x2f60['LwDoBx'][_0x1aa0d4] = _0x5bb3e4) : _0x" ascii
        $s10 = "    var _0x3e91be = _0x4de8a3, _0x136d28 = new ActiveXObject(_0x522091(0x4)), _0x20cea2 = new Active" ascii
        $s11 = "function _0x5d5e(_0x180d4f, _0x38978a) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}
