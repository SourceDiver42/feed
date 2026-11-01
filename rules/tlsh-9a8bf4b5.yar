rule Sightlines_tlsh_9a8bf4b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9a8bf4b5"
        date = "2026-10-30"
        campaign = "tlsh-9a8bf4b5"
        family = ""
        hash = "341dc8a019d310ffd044d13703bcb8b2d2f19ee9c48560cff447cf23c9f01677"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9a8bf4b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QFleK/GdNye8ar8mgWXZFO5zWGu0LUhvR8Sp496MYRibJwBgDHgV+Gi9r6wj3kpf" ascii
        $s1 = "zWaHROTDwCeBUSDsrXEPd8AKcA74rKo+n0gkrm31G942Z+NcLtemqkdF5MeBjwID" ascii
        $s2 = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/" ascii
        $s3 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AYWJjZGVmZ2hpamtsbW5v" ascii
        $s4 = "eJWmmnxhuAS1+OvL9GERM/ZlJbcRQovYaW7H/5W0gUOpfq6/gtZNzBGjg3FqEF4Z" ascii
        $s5 = "f3hHAjAM42VVnQEy9b6q7vYwyUiI/GrxvuberxXLvHphmpOXZ11dIJWKzdLy+j0N" ascii
        $s6 = "woQdDUgPqgaU8YIH9JnM5VL3mRfiBeiFuPjScQW9v6VBX8n0qoNz0fhtw/oE0pAI" ascii
        $s7 = "GBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BhYmNkZWZn" ascii
        $s8 = "Sve4kZm1o7VAXSlF5/KzcBOcnj/v6WEjaEQ4V1eNfqahsIgqubIDJ0zrpDPhNn96" ascii
        $s9 = "0eQDPEfUBEv9hQ3Sa7UKpfqotTVsmLJC1sm720D5vKzjbNgydVzfRc8N1txZPdGr" ascii
        $s10 = "OW+VeASwLbCwsNBmGMaAiAxRzSQcEZGdVLUKOtk6HYplYBa4parXgdNUJ+hes237" ascii
        $s11 = "uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn" ascii
    condition:
        filesize < 4300102 and 12 of them
}
