rule Sightlines_tlsh_f951c813_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f951c813"
        date = "2026-10-29"
        campaign = "tlsh-f951c813"
        family = ""
        hash = "16f109e8411bc08341497c87704b7cf0d22a2678f1e3a7dca416ea7bff995469"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f951c813.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "python313.PyMarshal_ReadObjectFromString" ascii
        $s1 = "python313.PyErr_SetExcFromWindowsErrWithFilenameObjects" ascii
        $s2 = "python313._PyArg_VaParseTupleAndKeywords_SizeT" ascii
        $s3 = "python313.Py_HasFileSystemDefaultEncoding" ascii
        $s4 = "python313.PyImport_ExecCodeModuleWithPathnames" ascii
        $s5 = "python313.PyEval_CallObjectWithKeywords" ascii
        $s6 = "python313._PyArg_ParseTupleAndKeywords_SizeT" ascii
        $s7 = "python313.PyUnicode_CompareWithASCIIString" ascii
        $s8 = "python313.Py_FileSystemDefaultEncodeErrors" ascii
        $s9 = "python313.PyArg_ValidateKeywordArguments" ascii
        $s10 = "python313.PyUnicode_AsRawUnicodeEscapeString" ascii
        $s11 = "python313.PyErr_SetFromErrnoWithFilenameObjects" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
