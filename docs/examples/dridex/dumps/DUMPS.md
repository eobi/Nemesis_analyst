# Dumps — what each file is

Each memory region the sample allocated/protected/targeted is dumped so nothing is missed. **PE** = carries an MZ header (installable/mappable image).

| File | Size | PE? | MD5 | Role |
|---|---|---|---|---|
| `api_fullmodule_0x10000000_PE.bin` | 217,088 | **PE** | `8e83c0e987ab924696ecbf13b7d380fa` | full module at W->X flip (-> reconstruct) |
| `api_fullmodule_0x10000000_rebuilt.exe` | 217,088 | **PE** | `9fc8d8fc35a3e4eb385f169eb16d6d16` | full module at W->X flip (-> reconstruct) |
| `api_ntwx_0x10001000.bin` | 134,417 | - | `691ceb869f2c5120a139d766242ec0f4` | W->X region = DECRYPTED PAYLOAD (made executable) |
| `api_plan_7000.bin` | 179,563 | - | `0a2fdfae075f7b1f75c66c361b7b3a75` | memory dump |
| `api_region0_0x670000.bin` | 176,128 | - | `2740f5927c507bc0df49f3a70d387699` | memory region the malware ALLOCATED (work buffer / staged data) |
| `api_region1_0x1e0000_PE.bin` | 24,576 | **PE** | `b8dd20ffc4818f4d84926096b7fb5a0c` | memory region the malware ALLOCATED (work buffer / staged data) |
| `api_region1_0x1e0000_rebuilt.exe` | 24,576 | **PE** | `a82f9ad175ac3348c41732ab35a8ae37` | memory region the malware ALLOCATED (work buffer / staged data) |
| `api_region2_0x6f0000.bin` | 172,032 | - | `72389e9e2971cd7227dd5aa2543d6c73` | memory region the malware ALLOCATED (work buffer / staged data) |
| `api_wx_0x10001000.bin` | 134,417 | - | `691ceb869f2c5120a139d766242ec0f4` | W->X region = DECRYPTED PAYLOAD (made executable) |