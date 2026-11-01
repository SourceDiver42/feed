rule Sightlines_tlsh_ed08f2a1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ed08f2a1"
        date = "2026-10-30"
        campaign = "tlsh-ed08f2a1"
        family = ""
        hash = "21b7160d4a6da9590794fdb38718982060b5c92d56fb0e441fc8b62ee789be8d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ed08f2a1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FFI_TRAMPOLINE_SIZE too small in src/c/libffi_x86_x64\\ffi.c" ascii
        $s1 = "extern \"Python\": function %s() called, but %s.  Returning 0." ascii
        $s2 = "initializer for ctype 'char16_t' must be a unicode string of length 1, not %.200s" ascii
        $s3 = "initializer for ctype 'char32_t' must be a unicode string of length 1, not %.200s" ascii
        $s4 = "don't use ffi.include() but duplicate the declarations of everything using %s %.200s)" ascii
        $s5 = "'%s %.200s' is opaque in the ffi.include(), but no longer in the ffi doing the include (workaround: " ascii
        $s6 = "back to the original object, use from_handle().  You must keep alive" ascii
        $s7 = "Cannot allocate write+execute memory for ffi.callback(). You might be running on a system that preve" ascii
        $s8 = "from_buffer('%s', ..): the actual length of the array cannot be computed" ascii
        $s9 = "only 'cdata' object from ffi.new(), ffi.gc(), ffi.from_buffer() or ffi.new_allocator()() can be used" ascii
        $s10 = "nts this. For more information, see https://cffi.readthedocs.io/en/latest/using.html#callbacks" ascii
        $s11 = "This is an internal subtype of _CDataBase for performance only on CPython.  Check with isinstance(x," ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
