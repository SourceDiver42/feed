rule Sightlines_tlsh_b374f34b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b374f34b"
        date = "2026-10-30"
        campaign = "tlsh-b374f34b"
        family = ""
        hash = "14bb8f8c7d713da32f153a203931979f065f0ddbb5e0c07763aea6b14bae3ebf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b374f34b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    out = _run([\"nslookup\", \"-type=TXT\", \"o-o.myaddr.l.google.com\", \"ns1.google.com\"], timeout=10, e" ascii
        $s1 = "def _run(cmd: list[str], timeout: int = 5, encoding: str = \"cp866\") -> str:" ascii
        $s2 = "            creationflags=subprocess.CREATE_NO_WINDOW," ascii
        $s3 = "            zf.writestr(\"system_info.json\", json.dumps(data, indent=2, ensure_ascii=False))" ascii
        $s4 = "    with ThreadPoolExecutor(max_workers=5) as ex:" ascii
        $s5 = "        with zipfile.ZipFile(zip_path, \"w\", zipfile.ZIP_DEFLATED) as zf:" ascii
        $s6 = "    out: dict = {\"collected_at\": datetime.now().isoformat()}" ascii
        $s7 = "    phase0_results: Optional[dict] = None," ascii
        $s8 = "    phase1_results: Optional[dict] = None," ascii
        $s9 = "    phase2_results: Optional[dict] = None," ascii
        $s10 = "    if bat_path is None and zapret1_strategy and Path(zapret1_strategy).exists():" ascii
        $s11 = "    ipconfig_out = _run([\"ipconfig\"], timeout=10)" ascii
    condition:
        filesize < 1048576 and 12 of them
}
