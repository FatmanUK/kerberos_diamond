package pac

// The fixtures in this file are the PAC blobs and keys upstream's own
// lib/krb5/krb/t_pac.c carries, rendered as hex the way
// internal/wire's reference encodings are. They were extracted from
// the C arrays mechanically and cross-checked against the two copies
// that also sit on disk as tests/fuzzing/fuzz_pac_seed_corpus/*.bin,
// so nothing here was retyped.
//
// They matter more than a reference encoding does, because these are
// not output from the implementation being compared against: every
// one of them was produced by a *Windows* KDC. refSavedPAC came from
// Samba's regression suite by way of a Windows 2003 domain
// controller; the four S4U PACs were captured off the wire from a
// Windows 2008 KDC (t_pac.c:100-102); and refADTicket is a complete
// 1307-octet Ticket issued by Windows Server 2022.

// t_pac.c:44, and tests/fuzzing/.../saved_pac.bin.
const refSavedPAC = "" +
	" 04 00 00 00 00 00 00 00 01 00 00 00 D8 01 00" +
	" 00 48 00 00 00 00 00 00 00 0A 00 00 00 20 00" +
	" 00 00 20 02 00 00 00 00 00 00 06 00 00 00 14" +
	" 00 00 00 40 02 00 00 00 00 00 00 07 00 00 00" +
	" 14 00 00 00 58 02 00 00 00 00 00 00 01 10 08" +
	" 00 CC CC CC CC C8 01 00 00 00 00 00 00 00 00" +
	" 02 00 30 DF A6 CB 4F 7D C5 01 FF FF FF FF FF" +
	" FF FF 7F FF FF FF FF FF FF FF 7F C0 3C 4E 59" +
	" 62 73 C5 01 C0 3C 4E 59 62 73 C5 01 FF FF FF" +
	" FF FF FF FF 7F 16 00 16 00 04 00 02 00 00 00" +
	" 00 00 08 00 02 00 00 00 00 00 0C 00 02 00 00" +
	" 00 00 00 10 00 02 00 00 00 00 00 14 00 02 00" +
	" 00 00 00 00 18 00 02 00 65 00 00 00 ED 03 00" +
	" 00 04 02 00 00 01 00 00 00 1C 00 02 00 20 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 14 00 16 00 20 00 02 00 16 00 18 00" +
	" 24 00 02 00 28 00 02 00 00 00 00 00 00 00 00" +
	" 00 00 21 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 01 00 00 00 2C 00 02 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 0B 00 00 00 00 00 00" +
	" 00 0B 00 00 00 57 00 32 00 30 00 30 00 33 00" +
	" 46 00 49 00 4E 00 41 00 4C 00 24 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01" +
	" 00 00 00 04 02 00 00 07 00 00 00 0B 00 00 00" +
	" 00 00 00 00 0A 00 00 00 57 00 32 00 30 00 30" +
	" 00 33 00 46 00 49 00 4E 00 41 00 4C 00 0C 00" +
	" 00 00 00 00 00 00 0B 00 00 00 57 00 49 00 4E" +
	" 00 32 00 4B 00 33 00 54 00 48 00 49 00 4E 00" +
	" 4B 00 00 00 04 00 00 00 01 04 00 00 00 00 00" +
	" 05 15 00 00 00 11 2F AF B5 90 04 1B EC 50 3B" +
	" EC DC 01 00 00 00 30 00 02 00 07 00 00 00 01" +
	" 00 00 00 01 01 00 00 00 00 00 05 09 00 00 00" +
	" 00 00 00 00 80 66 28 EA 37 80 C5 01 16 00 77" +
	" 00 32 00 30 00 30 00 33 00 66 00 69 00 6E 00" +
	" 61 00 6C 00 24 00 76 FF FF FF 37 D5 B0 F7 24" +
	" F0 D6 D4 EC 09 86 5A A0 E8 C3 A9 00 00 00 00" +
	" 76 FF FF FF B4 D8 B8 FE 83 B3 13 3F FC 5C 41" +
	" AD E2 64 83 E0 00 00 00 00"

// The Windows 2003 PAC's keys, and the client and authtime its
// CLIENT_INFO buffer names (t_pac.c:88-101).
//
// Both keys are **arcfour-hmac**, which this project does not
// implement and never will -- it is ETYPE_DEPRECATED upstream and a
// declared non-goal. So this blob anchors the framing and the
// CLIENT_INFO buffer and nothing else; its checksums are unverifiable
// here, which is recorded rather than worked around.
//
// The principal is w2003final$@WIN2K3.THINKER.LOCAL and the buffer
// holds only `w2003final$'. That is the rule rather than this blob
// being unusual: CLIENT_INFO carries the principal unparsed **without
// its realm** (insert_client_info's `flags |= NO_REALM',
// pac_sign.c:52-54), and the realm appears only for a cross-realm S4U
// request, where with_realm is true.
const (
	refSavedPACClient   = "w2003final$"
	refSavedPACAuthTime = 1120440609
	refSavedPACType1Len = 472
)

// t_pac.c, the S4U2Self PAC captured as s4u_pac_regular.
const refS4UPAC = "" +
	" 05 00 00 00 00 00 00 00 01 00 00 00 A0 01 00" +
	" 00 58 00 00 00 00 00 00 00 0A 00 00 00 14 00" +
	" 00 00 F8 01 00 00 00 00 00 00 0C 00 00 00 38" +
	" 00 00 00 10 02 00 00 00 00 00 00 06 00 00 00" +
	" 10 00 00 00 48 02 00 00 00 00 00 00 07 00 00" +
	" 00 14 00 00 00 58 02 00 00 00 00 00 00 01 10" +
	" 08 00 CC CC CC CC 90 01 00 00 00 00 00 00 00" +
	" 00 02 00 00 00 00 00 00 00 00 00 FF FF FF FF" +
	" FF FF FF 7F FF FF FF FF FF FF FF 7F C9 36 FD" +
	" 57 5B 59 D4 01 C9 36 FD 57 5B 59 D4 01 FF FF" +
	" FF FF FF FF FF 7F 0A 00 0A 00 04 00 02 00 0A" +
	" 00 0A 00 08 00 02 00 00 00 00 00 0C 00 02 00" +
	" 00 00 00 00 10 00 02 00 00 00 00 00 14 00 02" +
	" 00 00 00 00 00 18 00 02 00 00 00 00 00 76 04" +
	" 00 00 01 02 00 00 01 00 00 00 1C 00 02 00 20" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 06 00 08 00 20 00 02 00 08 00 0A" +
	" 00 24 00 02 00 28 00 02 00 00 00 00 00 00 00" +
	" 00 00 10 02 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 05 00 00 00 00 00" +
	" 00 00 05 00 00 00 77 00 32 00 6B 00 38 00 75" +
	" 00 00 00 05 00 00 00 00 00 00 00 05 00 00 00" +
	" 77 00 32 00 6B 00 38 00 75 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 01 00 00 00 01 02 00 00 07 00 00 00 04 00 00" +
	" 00 00 00 00 00 03 00 00 00 57 00 44 00 43 00" +
	" 00 00 05 00 00 00 00 00 00 00 04 00 00 00 41" +
	" 00 43 00 4D 00 45 00 04 00 00 00 01 04 00 00" +
	" 00 00 00 05 15 00 00 00 74 A0 8D 00 3F A5 C2" +
	" E9 60 91 E1 22 00 00 00 00 00 89 A1 25 D0 59" +
	" D4 01 0A 00 77 00 32 00 6B 00 38 00 75 00 00" +
	" 00 00 00 12 00 10 00 10 00 28 00 00 00 00 00" +
	" 00 00 00 00 77 00 32 00 6B 00 38 00 75 00 40" +
	" 00 61 00 62 00 63 00 00 00 00 00 00 00 41 00" +
	" 43 00 4D 00 45 00 2E 00 43 00 4F 00 4D 00 10" +
	" 00 00 00 88 1D 40 84 7A 01 7C 80 74 E3 6A 6B" +
	" 76 FF FF FF 1A 1D 97 D2 39 F4 B8 B2 53 AE 77" +
	" DB 6C 02 D4 3D 00 00 00 00"

// t_pac.c, the S4U2Self PAC captured as s4u_pac_enterprise.
const refS4UPACEnterprise = "" +
	" 05 00 00 00 00 00 00 00 01 00 00 00 A0 01 00" +
	" 00 58 00 00 00 00 00 00 00 0A 00 00 00 1C 00" +
	" 00 00 F8 01 00 00 00 00 00 00 0C 00 00 00 38" +
	" 00 00 00 18 02 00 00 00 00 00 00 06 00 00 00" +
	" 10 00 00 00 50 02 00 00 00 00 00 00 07 00 00" +
	" 00 14 00 00 00 60 02 00 00 00 00 00 00 01 10" +
	" 08 00 CC CC CC CC 90 01 00 00 00 00 00 00 00" +
	" 00 02 00 00 00 00 00 00 00 00 00 FF FF FF FF" +
	" FF FF FF 7F FF FF FF FF FF FF FF 7F C9 36 FD" +
	" 57 5B 59 D4 01 C9 36 FD 57 5B 59 D4 01 FF FF" +
	" FF FF FF FF FF 7F 0A 00 0A 00 04 00 02 00 0A" +
	" 00 0A 00 08 00 02 00 00 00 00 00 0C 00 02 00" +
	" 00 00 00 00 10 00 02 00 00 00 00 00 14 00 02" +
	" 00 00 00 00 00 18 00 02 00 00 00 00 00 76 04" +
	" 00 00 01 02 00 00 01 00 00 00 1C 00 02 00 20" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 06 00 08 00 20 00 02 00 08 00 0A" +
	" 00 24 00 02 00 28 00 02 00 00 00 00 00 00 00" +
	" 00 00 10 02 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 05 00 00 00 00 00" +
	" 00 00 05 00 00 00 77 00 32 00 6B 00 38 00 75" +
	" 00 00 00 05 00 00 00 00 00 00 00 05 00 00 00" +
	" 77 00 32 00 6B 00 38 00 75 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 01 00 00 00 01 02 00 00 07 00 00 00 04 00 00" +
	" 00 00 00 00 00 03 00 00 00 57 00 44 00 43 00" +
	" 00 00 05 00 00 00 00 00 00 00 04 00 00 00 41" +
	" 00 43 00 4D 00 45 00 04 00 00 00 01 04 00 00" +
	" 00 00 00 05 15 00 00 00 74 A0 8D 00 3F A5 C2" +
	" E9 60 91 E1 22 00 00 00 00 80 E1 9B E2 E0 59" +
	" D4 01 12 00 77 00 32 00 6B 00 38 00 75 00 40" +
	" 00 61 00 62 00 63 00 00 00 00 00 12 00 10 00" +
	" 10 00 28 00 00 00 00 00 00 00 00 00 77 00 32" +
	" 00 6B 00 38 00 75 00 40 00 61 00 62 00 63 00" +
	" 00 00 00 00 00 00 41 00 43 00 4D 00 45 00 2E" +
	" 00 43 00 4F 00 4D 00 10 00 00 00 FB E5 03 12" +
	" 13 00 6C 8E 81 97 09 EA 76 FF FF FF BA CD 3A" +
	" BC 67 61 16 9F B8 96 BC E1 BE 34 E1 77 00 00" +
	" 00 00"

// t_pac.c, the S4U2Self PAC captured as s4u_pac_xrealm.
const refS4UPACXRealm = "" +
	" 05 00 00 00 00 00 00 00 01 00 00 00 A0 01 00" +
	" 00 58 00 00 00 00 00 00 00 0A 00 00 00 26 00" +
	" 00 00 F8 01 00 00 00 00 00 00 0C 00 00 00 38" +
	" 00 00 00 20 02 00 00 00 00 00 00 06 00 00 00" +
	" 10 00 00 00 58 02 00 00 00 00 00 00 07 00 00" +
	" 00 14 00 00 00 68 02 00 00 00 00 00 00 01 10" +
	" 08 00 CC CC CC CC 90 01 00 00 00 00 00 00 00" +
	" 00 02 00 00 00 00 00 00 00 00 00 FF FF FF FF" +
	" FF FF FF 7F FF FF FF FF FF FF FF 7F C9 36 FD" +
	" 57 5B 59 D4 01 C9 36 FD 57 5B 59 D4 01 FF FF" +
	" FF FF FF FF FF 7F 0A 00 0A 00 04 00 02 00 0A" +
	" 00 0A 00 08 00 02 00 00 00 00 00 0C 00 02 00" +
	" 00 00 00 00 10 00 02 00 00 00 00 00 14 00 02" +
	" 00 00 00 00 00 18 00 02 00 00 00 00 00 76 04" +
	" 00 00 01 02 00 00 01 00 00 00 1C 00 02 00 20" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 06 00 08 00 20 00 02 00 08 00 0A" +
	" 00 24 00 02 00 28 00 02 00 00 00 00 00 00 00" +
	" 00 00 10 02 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 05 00 00 00 00 00" +
	" 00 00 05 00 00 00 77 00 32 00 6B 00 38 00 75" +
	" 00 00 00 05 00 00 00 00 00 00 00 05 00 00 00" +
	" 77 00 32 00 6B 00 38 00 75 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 01 00 00 00 01 02 00 00 07 00 00 00 04 00 00" +
	" 00 00 00 00 00 03 00 00 00 57 00 44 00 43 00" +
	" 00 00 05 00 00 00 00 00 00 00 04 00 00 00 41" +
	" 00 43 00 4D 00 45 00 04 00 00 00 01 04 00 00" +
	" 00 00 00 05 15 00 00 00 74 A0 8D 00 3F A5 C2" +
	" E9 60 91 E1 22 00 00 00 00 80 A8 60 1B 2B 5A" +
	" D4 01 1C 00 77 00 32 00 6B 00 38 00 75 00 40" +
	" 00 41 00 43 00 4D 00 45 00 2E 00 43 00 4F 00" +
	" 4D 00 00 00 12 00 10 00 10 00 28 00 00 00 00" +
	" 00 00 00 00 00 77 00 32 00 6B 00 38 00 75 00" +
	" 40 00 61 00 62 00 63 00 00 00 00 00 00 00 41" +
	" 00 43 00 4D 00 45 00 2E 00 43 00 4F 00 4D 00" +
	" 10 00 00 00 11 27 3A A5 41 84 87 DF C6 D7 29" +
	" 26 76 FF FF FF BA 7C 7A 84 D2 2B 9C 58 ED 2F" +
	" DF 23 09 15 05 6B 00 00 00 00"

// t_pac.c, the S4U2Self PAC captured as s4u_pac_ent_xrealm.
const refS4UPACEntXRealm = "" +
	" 05 00 00 00 00 00 00 00 01 00 00 00 A0 01 00" +
	" 00 58 00 00 00 00 00 00 00 0A 00 00 00 2E 00" +
	" 00 00 F8 01 00 00 00 00 00 00 0C 00 00 00 38" +
	" 00 00 00 28 02 00 00 00 00 00 00 06 00 00 00" +
	" 10 00 00 00 60 02 00 00 00 00 00 00 07 00 00" +
	" 00 14 00 00 00 70 02 00 00 00 00 00 00 01 10" +
	" 08 00 CC CC CC CC 90 01 00 00 00 00 00 00 00" +
	" 00 02 00 00 00 00 00 00 00 00 00 FF FF FF FF" +
	" FF FF FF 7F FF FF FF FF FF FF FF 7F C9 36 FD" +
	" 57 5B 59 D4 01 C9 36 FD 57 5B 59 D4 01 FF FF" +
	" FF FF FF FF FF 7F 0A 00 0A 00 04 00 02 00 0A" +
	" 00 0A 00 08 00 02 00 00 00 00 00 0C 00 02 00" +
	" 00 00 00 00 10 00 02 00 00 00 00 00 14 00 02" +
	" 00 00 00 00 00 18 00 02 00 00 00 00 00 76 04" +
	" 00 00 01 02 00 00 01 00 00 00 1C 00 02 00 20" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 06 00 08 00 20 00 02 00 08 00 0A" +
	" 00 24 00 02 00 28 00 02 00 00 00 00 00 00 00" +
	" 00 00 10 02 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 05 00 00 00 00 00" +
	" 00 00 05 00 00 00 77 00 32 00 6B 00 38 00 75" +
	" 00 00 00 05 00 00 00 00 00 00 00 05 00 00 00" +
	" 77 00 32 00 6B 00 38 00 75 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
	" 01 00 00 00 01 02 00 00 07 00 00 00 04 00 00" +
	" 00 00 00 00 00 03 00 00 00 57 00 44 00 43 00" +
	" 00 00 05 00 00 00 00 00 00 00 04 00 00 00 41" +
	" 00 43 00 4D 00 45 00 04 00 00 00 01 04 00 00" +
	" 00 00 00 05 15 00 00 00 74 A0 8D 00 3F A5 C2" +
	" E9 60 91 E1 22 00 00 00 00 00 87 39 5B 4F 5A" +
	" D4 01 24 00 77 00 32 00 6B 00 38 00 75 00 40" +
	" 00 61 00 62 00 63 00 40 00 41 00 43 00 4D 00" +
	" 45 00 2E 00 43 00 4F 00 4D 00 00 00 12 00 10" +
	" 00 10 00 28 00 00 00 00 00 00 00 00 00 77 00" +
	" 32 00 6B 00 38 00 75 00 40 00 61 00 62 00 63" +
	" 00 00 00 00 00 00 00 41 00 43 00 4D 00 45 00" +
	" 2E 00 43 00 4F 00 4D 00 10 00 00 00 A3 5D C5" +
	" FE 80 6B 62 0C B1 2F 43 A2 76 FF FF FF 95 40" +
	" 76 E4 0A 0A B9 E7 93 0F 05 F8 8A 81 9C 9C 00" +
	" 00 00 00"

// The two keys the four S4U PACs verify under, both
// aes256-cts-hmac-sha1-96 (t_pac.c:447-458), and the names and times
// their CLIENT_INFO buffers carry (t_pac.c:444-473).
const (
	refS4UServerKey = "14DFB5B2CDB42C8894DA2FA882E9729F" +
		"4A4DC74BA02A242CC6A8D71079B9AD9A"
	refS4UPrivsvrKey = "420C39C51A175404451F956B8C58E0F4" +
		"1BCA669A644795CA6E3AD55A3B918C9F"
	refS4UPrincipal  = "w2k8u@ACME.COM"
	refS4UEnterprise = "w2k8u@abc@ACME.COM"
)

// Two blobs from upstream's fuzzing corpus that must be refused
// rather than parsed (t_pac.c:434-442). The first claims a buffer
// count of 0x10000000 and the second 0x20000000, in fifteen and ten
// octets respectively -- so each is refused for the count *and* for
// the length, and a parser that checked only one of those would still
// pass. They are here because a PAC arrives from the network.
const (
	refFuzz1 = "00 00 00 10 00 00 00 00 06 FF FF FF 00 00 F5"
	refFuzz2 = "00 00 00 20 00 00 00 00 20 20"
)

// A complete Ticket issued by a Windows Server 2022 KDC, with the
// server and krbtgt keys that open and verify it (t_pac.c:608-706),
// and the two principal names involved.
//
// This is the strongest anchor in the phase, and the reason is in
// what upstream does with it: it re-signs the PAC and asserts the
// resulting authorization-data element is **byte-for-byte** what the
// Windows KDC produced (t_pac.c:764-766). That pins the buffer order,
// the eight-octet padding, the in-place header encoding, the
// zero-fill-then-sign order and all four checksums at once -- and,
// because the ticket checksum covers a re-encoded EncTicketPart, it
// pins this project's DER encoder against a Windows one too.
const refADTicket = "" +
	" 61 82 05 17 30 82 05 13 A0 03 02 01 05 A1 0F" +
	" 1B 0D 57 32 30 32 32 2D 4C 37 2E 42 41 53 45" +
	" A2 2A 30 28 A0 03 02 01 01 A1 21 30 1F 1B 04" +
	" 63 69 66 73 1B 17 77 32 30 32 32 2D 31 31 38" +
	" 2E 77 32 30 32 32 2D 6C 37 2E 62 61 73 65 A3" +
	" 82 04 CD 30 82 04 C9 A0 03 02 01 12 A1 03 02" +
	" 01 05 A2 82 04 BB 04 82 04 B7 44 5C 7B 5A 3F" +
	" 2E A3 50 34 DE B0 69 23 2D 47 89 2C C0 A3 F9" +
	" DD 70 AA A5 1E FE 74 E5 19 A2 4F 65 6C 9E 00" +
	" B4 60 00 7C 0C 29 43 31 99 77 02 73 ED B9 40" +
	" F5 D2 D1 C9 20 0F E3 38 F9 CC 5E 2A BD 1F 91" +
	" 66 1A D8 2A 80 3C 2C 00 3C 1E C9 2A 29 19 19" +
	" 96 18 54 03 97 8F 1D 5F DB E9 66 68 CD B1 D5" +
	" 00 35 69 49 45 F1 6A 78 7B 37 71 87 14 1C 98" +
	" 4D 69 CB 1B D8 F5 A3 D8 53 4A 75 76 62 BA 6C" +
	" 3F EA 8B 97 21 CA 8A 46 4B 38 DA 09 9F 5A C8" +
	" 38 FF 34 97 5B A2 E5 BA C9 87 17 D8 08 05 7A" +
	" 83 04 D6 02 8E 9B 18 B6 40 1A F7 47 25 24 3E" +
	" 37 1E F6 C1 3A 1F CA B3 43 5A AE 94 83 31 AF" +
	" FB EE ED 46 71 EF E2 37 37 15 FE 1B 0B 9E F8" +
	" 3E 0C 43 96 B6 0A 04 78 F8 5E AA 33 1F E2 07" +
	" 5A 8D C4 4E 32 6D D6 A0 C5 EA 3D 12 59 D4 41" +
	" 40 4E A1 D8 BE ED 17 CB 68 CC 59 CB 53 B2 0E" +
	" 58 8A A9 33 7F 6F 2B 37 89 08 44 BA C7 67 17" +
	" BB 91 F7 C3 0F 00 F8 AA A1 33 A6 08 47 CA FA" +
	" E8 49 27 45 46 F1 C1 C3 5F E2 45 0A 7D 64 52" +
	" 8C 2E E1 DE FF B2 64 EC 69 98 15 DF 9E B1 EB" +
	" D6 9D 08 06 4E 73 C1 0B 71 21 05 9E BC A2 17" +
	" CF B3 70 F4 EF B8 69 A9 94 27 FD 5E 72 B1 2D" +
	" D2 20 1B 57 80 AB 38 97 CF 22 68 4F B8 B7 17" +
	" 53 25 67 0B ED D1 58 20 0D 45 F9 09 FA E7 61" +
	" 3E DB C2 59 7B 3A 3B 59 81 51 AA A4 81 F4 96" +
	" 3B E1 6F 6F F4 8E 68 9E BA 1E 0F F2 44 68 11" +
	" FC 2B 5F BE F2 EA 07 80 B9 CA 9E 41 BD 2F 81" +
	" F5 11 2A 12 F3 4F D6 12 16 0F 21 90 F1 D3 1E" +
	" F1 A4 94 46 EA 30 F3 84 06 C1 A4 51 FC 43 35" +
	" BD EF 4D 89 1D A5 44 B2 69 C4 0F BF 86 01 08" +
	" 44 77 D5 B4 B7 5C 3F A7 D4 2F 39 73 85 88 EE" +
	" B1 64 1D 80 6C EE 6E 31 90 92 0D A1 B7 C4 5C" +
	" CC EE 91 C8 CB 11 2D 4A 1A 7D 43 8F EB 60 09" +
	" ED 1B 07 58 BE BC BD 29 F3 B3 A3 4F C5 8A 30" +
	" 33 B9 A9 9F 43 08 27 15 C4 9C 5D 8E BD 5C 05" +
	" C6 05 9C 87 60 08 1E E2 52 B8 45 8D 28 B6 2C" +
	" 15 46 74 9F 0E AA 6B 70 3A 2A 55 45 26 B2 58" +
	" 4D 35 A6 F1 96 BE 60 B2 71 7B F8 54 B9 90 21" +
	" 8E B9 0F 35 98 5E 88 EB 1A 53 B4 59 7F AF 69" +
	" 1C 61 67 F4 F6 BD AC 24 CD B7 A9 67 E8 A1 83" +
	" 85 5F 11 74 1F F7 4C 78 36 EF 50 74 88 58 4B" +
	" 1A 9F 84 9A 9A 05 92 EC 1D D5 F3 C4 95 51 28" +
	" E2 3F 32 87 B2 FD 21 27 66 E4 6B 85 2F DC 7B" +
	" C0 22 EB 7A 94 20 5A 7B D3 7A B9 5B F8 1A 5A" +
	" 84 4E A1 73 41 53 D2 60 F7 7C EE 68 59 85 80" +
	" FC 3D 70 4B 04 32 E7 F2 FD BD B3 D9 21 E2 37" +
	" 56 A2 16 CC DE 8A D3 BC 71 EF 58 19 0E 45 8A" +
	" 5B 53 D6 77 30 6A A7 F8 68 06 4E 07 CA CE 30" +
	" D7 35 AB 1A C7 18 D4 C6 2F 1A FF E9 7A 94 0B" +
	" 76 5E 7E 29 0C E6 D3 3B 5B 44 96 A8 F1 29 23" +
	" 95 D9 79 B3 39 FC 76 ED E1 1E 67 4E F7 E8 7B" +
	" 7A 12 9E D8 4B 35 09 0A F2 C1 63 5B EE FD 2A" +
	" C2 A6 66 30 3C 1F 95 AF 65 22 95 14 1D F5 D5" +
	" DC 38 79 35 1C CD 24 47 E0 FD 08 C8 F4 15 55" +
	" 9F D9 C7 AC 3F 67 B3 4F EB 26 7C 8E D6 74 B3" +
	" 0A CD E7 FA BE 7E A3 3E EC 61 50 77 52 56 CF" +
	" 90 5D 48 FB D4 2C 6C 61 8B DD 2B F5 92 1F 30" +
	" BF 3F 80 0D 31 DB B2 0B 7D 84 E3 A6 42 7F 00" +
	" 38 44 02 C5 B8 D9 58 29 9D 68 5C 32 8B 76 AE" +
	" ED 15 F9 7C AE 7B B6 8E D6 54 24 FF FA 87 05" +
	" EF 15 08 5E 4B 21 A2 2F 49 E7 0F C3 D0 B9 49" +
	" 22 EF D5 CA B2 11 F2 17 B6 77 24 68 76 B2 07" +
	" F8 0A 73 DD 65 9C 75 64 F7 A1 C6 23 08 84 72" +
	" 3E 54 2E EB 9B 40 A6 83 87 EB B5 00 40 4F E1" +
	" 72 2A 59 3A 06 60 29 7E 25 2F D8 80 40 8C 59" +
	" CA CF 8E 44 E4 2D 84 7E CB FD 1E 3B D5 FF 9A" +
	" B9 66 93 6D 5E C8 B7 13 26 D6 38 1B 2B E1 87" +
	" 96 05 D5 F3 AB 68 F7 12 62 2C 58 C1 C9 85 3C" +
	" 72 F1 26 EE C0 09 5F 1D 4B AC 01 41 C8 12 F8" +
	" F3 93 43 41 FF EC 0B 80 E2 EE 20 85 25 CD 6C" +
	" 30 8C 0D 24 2E BA 19 EA 28 7F CF D5 10 5C E9" +
	" B2 9D 5F 16 E4 C0 F3 CC D9 68 4A 05 08 70 17" +
	" 26 C8 5C 4A BF 94 6A 0E D5 DA 67 47 4B AF 44" +
	" E3 94 AA 05 DB A2 49 74 FA 5C 69 AB 44 B7 F7" +
	" BA AE 7A 23 87 EB 54 7E 80 F1 5B 60 A5 93 E5" +
	" D4 24 84 F7 0A 16 10 BE E9 4D D8 6B 15 40 5D" +
	" 74 DA 1B FF 2E 4D 17 9D 35 F7 0D CF 66 38 0D" +
	" 8A E4 DD 6B E1 0F 1F BD FD 4F 30 37 3F 96 B4" +
	" 92 54 D3 9A 7A D1 5B 5B A9 54 16 E6 24 AB D4" +
	" 23 39 7D D2 C7 09 FA D4 86 55 4D 60 C2 87 67" +
	" 6B E6"

const (
	refADServerKey = "114A84E3148FAAB1FA7B5351B28AC2F1" +
		"FD196D61E0F3F23E1FDBD3C1797DC1EE"
	refADKrbtgtKey = "037381EC43967BC2AC3DF52AAE95A68E" +
		"BE2458DBCE522820AF5EB704A222714F"
	refADClient = "administrator@W2022-L7.BASE"
	refADServer = "cifs/w2022-118.w2022-l7.base@W2022-L7.BASE"
)
