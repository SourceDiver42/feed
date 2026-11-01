rule Sightlines_tlsh_7cbe3c81_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cbe3c81"
        date = "2026-10-30"
        campaign = "tlsh-7cbe3c81"
        family = ""
        hash = "c3dd782441f71c2e070fdc699a09d29ea0642a6b14378f68943003eeb82d5ea8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cbe3c81.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "from core.config import ConfigManager, DEFAULT_PROFILE, VERSION" ascii
        $s1 = "            self._send_json({\"status\": \"error\", \"message\": str(e)}, HTTPStatus.SERVICE_UNAVAILABLE)" ascii
        $s2 = "def _run_with_timeout(args: list[str], timeout: float = 8.0) -> subprocess.CompletedProcess:" ascii
        $s3 = "            self._send_json({\"error\": \"Forbidden\"}, HTTPStatus.FORBIDDEN)" ascii
        $s4 = "            self._send_json({\"status\": \"error\", \"message\": str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR" ascii
        $s5 = "def _run_with_timeout_quiet(args: list[str], timeout: float = 5.0) -> None:" ascii
        $s6 = "        winsound.PlaySound(\"SystemNotification\", winsound.SND_ALIAS | winsound.SND_ASYNC)" ascii
        $s7 = "            self._send_json({\"status\": \"error\", \"message\": busy}, HTTPStatus.CONFLICT)" ascii
        $s8 = "        ctype = CONTENT_TYPES.get(ext, \"application/octet-stream\")" ascii
        $s9 = "        self.send_header(\"Content-Type\", \"application/json; charset=utf-8\")" ascii
        $s10 = "def _make_result_cb(state: TesterState, profile: Optional[str] = None) -> Callable:" ascii
        $s11 = "_BLOB_STOPLIST = {\"example_com\", \"sni2gis\", \"snimail\"}" ascii
    condition:
        filesize < 1048576 and 12 of them
}
