rule Sightlines_tlsh_d1ed9b44_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d1ed9b44"
        date = "2026-10-30"
        campaign = "tlsh-d1ed9b44"
        family = ""
        hash = "78dfc6f96c6edb5c5c2aff3fb7dc04a70eba4dd4d2f794122f11ccc1012ac949"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d1ed9b44.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    def update_domains_list(self, domains_list: List[str]) -> None:" ascii
        $s1 = "    def get_domains_for_dc(self, dc_id: int) -> Iterator[str]:" ascii
        $s2 = "    def update_domain_for_dc(self, dc_id: int, domain: str) -> bool:" ascii
        $s3 = "        if Counter(self.domains) == Counter(domains_list):" ascii
        $s4 = "        current_domain = self._dc_to_domain.get(dc_id)" ascii
        $s5 = "        random.shuffle(shuffled_domains)" ascii
        $s6 = "from typing import Dict, List, Iterator " ascii
        $s7 = "        shuffled_domains = self.domains[:]" ascii
        $s8 = "        for domain in shuffled_domains:" ascii
        $s9 = "        if current_domain is not None:" ascii
        $s10 = "from collections import Counter" ascii
        $s11 = "balancer = _Balancer()" ascii
    condition:
        filesize < 1048576 and 12 of them
}
