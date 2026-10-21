rule nemesis_loader_packer_packed_178ba564
{
    meta:
        author = "Nemesis Labs"
        family = "loader/packer"
        sha256 = "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"
        stage = "packed"
        date = "2026-10-21"
        goodware_fp = "0/28 files"
    strings:
        $s0 = "Fnotumajor.minor.build.patch.195butterBrinB1234567Y" ascii wide
        $s1 = "Copyright (C) INCA Internet. 2000-2003" ascii wide
        $s2 = "I_RpcNsInterfaceExported" ascii wide
        $s3 = "INCA Internet Co., Ltd." ascii wide
        $s4 = "4]mD:UN+XS\"P.8=" ascii wide
        $s5 = "A?1xm{/|u" ascii wide
        $s6 = "$wvnM0&\\Z" ascii wide
        $s7 = "PdhExpandWildCardPathW" ascii wide
        $s8 = "2 2H2L2P2T2X2\\2" ascii wide
        $s9 = "P7o=mA%}" ascii wide
        $s10 = "M-R$s, 1|8e7" ascii wide
        $s11 = "OLEAUT32.dll" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 851968 and 6 of ($s*)
}
