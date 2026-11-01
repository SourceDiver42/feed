rule Sightlines_tlsh_95091757_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95091757"
        date = "2026-10-25"
        campaign = "tlsh-95091757"
        family = ""
        hash = "00436a440caaf87f038abf67f023658b8e17be98ded878fe0bc24a5d47bddbd8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95091757.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" wide
        $s1 = "Bits index out of range*Can't write to a read-only resource streamECheckSynchronize called from thre" wide
        $s2 = "List index out of bounds (%d)+Out of memory while expanding memory stream" wide
        $s3 = "%s5Could not convert variant of type (%s) into type (%s)=Overflow while converting variant of type (" wide
        $s4 = "Invalid property value List capacity out of bounds (%d)" wide
        $s5 = "No help found for %s#No context-sensitive help installed$No topic-based help system installed" wide
        $s6 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii
        $s7 = "%s.Seek not implemented$Operation not allowed on sorted list$%s not in a class registration group" wide
        $s8 = "Invalid stream format$''%s'' is not a valid component name" wide
        $s9 = "Invalid variant operation%Invalid variant operation (%s%.8x)" wide
        $s10 = " - Dock zone has no control\"Unable to find a Table of Contents" wide
        $s11 = "l16 tI6(lA60TY68LQ6@Ti6HLa6P4y6X,q6`4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1327648 and 12 of them
}
