rule Sightlines_imphash_7e34bbdb_vidar
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7e34bbdb"
        date = "2026-10-24"
        campaign = "imphash-7e34bbdb"
        family = "vidar"
        hash = "21eacb925392e39b86b7a04262cdc4f9f55a21e4ae308cebf7e4d7d95e44699a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7e34bbdb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = "SELECT 'CREATE TABLE vacuum_db.' || substr(sql,14)   FROM sqlite_master WHERE type='table' AND name!" ascii
        $s2 = "OH163IV7RP72254RVEFJG7NCM4RPV0Y83BMS2DVGFFPWKWA1NTG2Y3NR4YU81GL11890SMZST9EBR02Z4ZBBU6KAY5XDTXO83Y4L" ascii
        $s3 = "SELECT 'CREATE UNIQUE INDEX vacuum_db.' || substr(sql,21)   FROM sqlite_master WHERE sql LIKE 'CREAT" ascii
        $s4 = "CB530H1UO79CYM5THLYPSOVEWRUA3RITI4RNZFUKDEC5VDQQZBMX78AYQ0HJX017ZP" ascii
        $s5 = "SELECT 'DELETE FROM vacuum_db.' || quote(name) || ';' FROM vacuum_db.sqlite_master WHERE name='sqlit" ascii
        $s6 = "SELECT 'CREATE INDEX vacuum_db.' || substr(sql,14)  FROM sqlite_master WHERE sql LIKE 'CREATE INDEX " ascii
        $s7 = "MIH6SJCKVV71GJAGNEYM0R4UYHQ71XKTSN71443UZY859PZF3KQPW8R4O" ascii
        $s8 = "1EZNAJRI2KACTFKAEIDGCS26QKQ5VFBMW7YO2F8OO9749KJ08X0535ZJM27Z3WXWJXPWR5I9JY" ascii
        $s9 = "autoindex%%' AND type='index' THEN 'sqlite_autoindex_' || %Q || substr(name,%d+18) ELSE name END WHE" ascii
        $s10 = "5BWLFU17VE5ZVMMYT7T8ORK4NMAOVJ53JHMG6FAEGLRUMJKP7TBOTR7N1282UMLMJBPN9F1O7O1D9ZSEBUQCHQJ2K9PEHHU4AFLK" ascii
        $s11 = "UPDATE %Q.%s SET type='table', name=%Q, tbl_name=%Q, rootpage=0, sql=%Q WHERE rowid=#%d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2416640 and 12 of them
}
