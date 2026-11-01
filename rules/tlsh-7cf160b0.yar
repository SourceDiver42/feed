rule Sightlines_tlsh_7cf160b0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cf160b0"
        date = "2026-10-21"
        campaign = "tlsh-7cf160b0"
        family = "mirai"
        hash = "15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cf160b0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s5 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s6 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s7 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s9 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s10 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
        $s11 = "POST /wanipcn.xml?service=WANIPConn1 HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1079504 and 12 of them
}
