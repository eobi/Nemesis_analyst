rule nemesis_loader_packer_unpacked_bc0886d6
{
    meta:
        author = "Nemesis Labs"
        family = "loader/packer"
        sha256 = "bc0886d626ba6ca8c60ab997b578c66a92abae0a72fa1a17fbe4cd0570892289"
        stage = "unpacked"
        date = "2026-10-21"
        goodware_fp = "0/28 files"
    strings:
        $s0 = "89<9@9D9H9L9P9T9X9\\9`9" ascii wide
        $s1 = "AddVectoredExceptionHandler" ascii wide
        $s2 = "4\\4`4d4h4l4p4t4x4|4" ascii wide
        $s3 = "<9=C=I=2>B>K?X?g?" ascii wide
        $s4 = ";?<I<O<3=C=Y>f>u>" ascii wide
        $s5 = "5)63696 707I8V8i8" ascii wide
        $s6 = "4)53595 606I7V7e7" ascii wide
        $s7 = "8L%g<S:b" ascii wide
        $s8 = "6!6O7\\7o7" ascii wide
        $s9 = "OutputDebugStringW" ascii wide
        $s10 = "DllUnregisterServer" ascii wide
        $s11 = "9Y9c9i9P:`:e:" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 868352 and 6 of ($s*)
}
