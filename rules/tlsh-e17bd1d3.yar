rule Sightlines_tlsh_e17bd1d3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e17bd1d3"
        date = "2026-10-23"
        campaign = "tlsh-e17bd1d3"
        family = ""
        hash = "269b268ad54168172f307ae50896b64735e3164946f4abc91c2e8257b0fb6300"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e17bd1d3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "N[C?K4WdL2A$?L38H*4D'OZEWaNWdMJV@SaEBR39I+?L3VaMfo]=H3amWdoYkub" ascii
        $s1 = "?qt_qFindChild_helper@@YAPEAVQObject@@PEBV1@AEBVQString@@AEBUQMetaObject@@V?$QFlags@W4FindChildOptio" ascii
        $s2 = "?glDiscardFramebufferEXT@QOpenGLExtensions@@QEAAXIHPEBI@Z" ascii
        $s3 = "?mouseDoubleClickEvent@QGraphicsProxyWidget@@MEAAXPEAVQGraphicsSceneMouseEvent@@@Z" ascii
        $s4 = "?modifiers@QGraphicsSceneContextMenuEvent@@QEBA?AV?$QFlags@W4KeyboardModifier@Qt@@@@XZ" ascii
        $s5 = "?qInstallMessageHandler@@YAP6AXW4QtMsgType@@AEBVQMessageLogContext@@AEBVQString@@@ZP6AX012@Z@Z" ascii
        $s6 = "?qt_metacall@QGraphicsDropShadowEffect@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z" ascii
        $s7 = "?d_func@QGraphicsPolygonItem@@AEBAPEBVQGraphicsPolygonItemPrivate@@XZ" ascii
        $s8 = "?isObscuredBy@QGraphicsPolygonItem@@UEBA_NPEBVQGraphicsItem@@@Z" ascii
        $s9 = "?modifiers@QGraphicsSceneDragDropEvent@@QEBA?AV?$QFlags@W4KeyboardModifier@Qt@@@@XZ" ascii
        $s10 = "?match@QRegularExpression@@QEBA?AVQRegularExpressionMatch@@AEBVQString@@HW4MatchType@1@V?$QFlags@W4M" ascii
        $s11 = "?boundingRect@QGraphicsPolygonItem@@UEBA?AVQRectF@@XZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11161600 and 12 of them
}
