rule Sightlines_tlsh_95457ab8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-95457ab8"
        date = "2026-10-20"
        campaign = "tlsh-95457ab8"
        family = "mirai"
        hash = "2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-95457ab8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DMCCRe7HaAgEeoZzN31Fu9LjO/wl9ngRG3jRpXKRSzds+N4GSOL/NymOIlRTL+R1QakC03hcj1Zqoi2FyPBmiVCnxlbgqpYkum1N" ascii
        $s1 = "v+6LOO5aoJrn0qJRcQ5rbpb4IKVjRrOrHMNShtRRLdWAZ3UiMvpDyOoO7a6PIpGk4hRP89NqZQldou3t6KTUhUKqFNc/JXYzyZj2" ascii
        $s2 = "wSbUApq6npt6MrE/917Hc3efVV93zbHgLh1CFWYass8cJ8OZ17c4KTtmDZtKY+q/9ZOya6Q0PPTo6BchnNzEQQIDAQAB" ascii
        $s3 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmmFi2EB5BpqTSnj66P5Sd5CX+2p+eelmwR0PUuf7paUg9o7KBvAFPM0p" ascii
        $s4 = "ZSWireGuard v1 zx2c4 Jason@zx2c4.comNoise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s5 = "OAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping x" ascii
        $s6 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" S" ascii
        $s7 = "GET /setup.cgi?todo=ping_test&next_file=diagping.htm&c4_IPAddr=;%s HTTP/1.1" ascii
        $s8 = "GET /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard&var:subpage=wiz_wan_,;%s" ascii
        $s9 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(%s)</language>" ascii
        $s10 = "GET /adv,/cgi-bin/weblogin.cgi?username=admin';%s;' HTTP/1.1" ascii
        $s11 = "GET /cgi-bin/masterCGI?ping=nomip&user=;%s; HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
