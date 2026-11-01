rule Sightlines_tlsh_6aba93d9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6aba93d9"
        date = "2026-10-28"
        campaign = "tlsh-6aba93d9"
        family = ""
        hash = "33b2e61081bd095840ee6c90f902c06b748193fc201acd7b9ae4288acf509b3f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6aba93d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    all_screened.sort(key=lambda x: x.get(\"network_rate\", 0) or 0, reverse=True)" ascii
        $s1 = "from .tester import Zapret2Tester, CDN_PROVIDERS" ascii
        $s2 = "    payload: dict[str, Any] = field(default_factory=dict)" ascii
        $s3 = "    on_event: Optional[Callable[[AnalyzerEvent], None]] = None," ascii
        $s4 = "    def progress(percent: float, msg: str, current: int = 0, profile: str = \"\") -> None:" ascii
        $s5 = "        emit(AnalyzerEvent(\"intermediate\", {**entry, \"idx\": idx}))" ascii
        $s6 = "in (result.results[0].domain or \"\") else \"\"," ascii
        $s7 = "    def run_one(profile_name: str, idx: int, tier: str, send_intermediate: bool = True," ascii
        $s8 = "    def test_result_cb(profile_name: str):" ascii
        $s9 = "    def emit(ev: AnalyzerEvent) -> None:" ascii
        $s10 = "from typing import Any, Callable, Optional" ascii
        $s11 = "        emit(AnalyzerEvent(\"progress\", {" ascii
    condition:
        filesize < 1048576 and 12 of them
}
