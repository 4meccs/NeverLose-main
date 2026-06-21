#include "neverlose.h"
#include "nops.h"
#include "internal_fixes.h"
#include "token.h"
#include "nl_log.h"

constexpr auto g_stupid_ahh_shit_flow_fix = std::to_array<DWORD>
({
    0x412EADC5,
    0x413129D2,
    0x41312D00,
    0x4133485D,
    0x41335068,
    0x4133CE9D,
    0x41340AF7,
    0x4134149A,
    0x4134185A,
    0x413534AF,
    0x4135F2BA,
    0x41368434,
    0x4136F4AE,
    0x413C1EE7,
    0x413C43A8,
    0x413D3AEF,
    0x413D5392,
    0x413D6481,
    0x413DC360,
    0x413DCD84,
    0x413E1A6F,
    0x413E472F,
    0x413E82AD,
    0x413E9204,
    0x413EBC8C,
    0x413F3D2F,
    0x413F838F,
    0x414000DB,
    0x414084DE,
    0x41409AC1,
    0x4140FFF7,
    0x4141485B,
    0x41414BB6,
    0x41415283,
    0x41419241,
    0x414196C3,
    0x4141AB52,
    0x4141B183,
    0x4141B655,
    0x4141BAB3,
    0x4141C2E6,
    0x4141FDB5,
    0x41420111,
    0x41420484,
    0x41439012,
    0x4143DED0,
    0x4146B4E8,
    0x414703B2,
    0x4147BD0C,
    0x414802FD,
    0x4148CE6F,
    0x4148D18E,
    0x4148D4A7,
    0x41493FCF,
    0x41495B74,
    0x414AD482,
    0x414B2D58,
    0x414B5F87,
    0x414B9BFF,
    0x414BBBB7,
    0x414BCAF3,
    0x414BDB3A,
    0x414BEB2B,
    0x414BFB2F,
    0x414C0C6B,
    0x414C4F25,
    0x414CFAA6,
    0x414D18C9,
    0x414D4963,
    0x414D4DB0,
    0x414D51C1,
    0x414D6281,
    0x414E4372,
    0x414FAD34,
    0x41503C9B,
    0x415041AA,
    0x415045B7,
    0x41504942,
    0x4150816B,
    0x41508EA6,
    0x41509281,
    0x415097B2,
    0x4150E146,
    0x4150E532,
    0x415113B7,
    0x41511718,
    0x41511FCF,
    0x4151EED3,
    0x415714E1,
    0x4157183A,
    0x41571CEA,
    0x415965A2,
    0x415A71F6,
    0x415A7A11,
    0x415B25F8,
    0x415B4D0F,
    0x415B78F9,
    0x415B9A1D,
    0x415DFBB3,
    0x415E3ABA,
    0x4185A75B,
    0x41976247,
    0x419B0199,
    });

static void last_resort_fixes()
{
	*(PHANDLE)0x42518C44 = GetStdHandle(STD_OUTPUT_HANDLE);
	memset((PVOID)0x41C12B3E, 0x90, 6); // for websocketpp

	*(PPVOID)0x41BF8341 = (PVOID)&auth_token;

	*(PBYTE)0x414E31F0 = 0x85;
	*(PBYTE)0x41B63BB0 = 0xC3;
	*(PBYTE)0x41DA128F = 0xEB;
	*(PSHORT)0x41580769 = 0xE967;
	*(PSHORT)0x41B64154 = 0xE967;
	PVOID addr = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	*(PPVOID)0x424AFCC0 = addr;
	*(PDWORD)0x4479EE00 = (DWORD)addr + 0x1000;
};

void neverlose::fix_dump()
{
	NlLog("fix_dump: fix_imports");
	fix_imports();

	NlLog("fix_dump: spoof_peb");
	spoof_peb();

	NlLog("fix_dump: spoof_kusd");
	spoof_kusd();

	NlLog("fix_dump: spoof_cpuid");
	spoof_cpuid();

	NlLog("fix_dump: fix_interfaces");
	fix_interfaces();

	NlLog("fix_dump: fix_cvars");
	fix_cvars();

	NlLog("fix_dump: fix_signatures");
	fix_signatures();

	NlLog("fix_dump: nop patching (%zu addrs)", g_noped_addrs.size());
	for (auto& [address, count] : g_noped_addrs) memset((PVOID)address, 0x90, count);

	NlLog("fix_dump: fix_mem_dispatcher");
	fix_mem_dispatcher();

	NlLog("fix_dump: flow fix (%zu addrs)", g_stupid_ahh_shit_flow_fix.size());
	for (DWORD addr : g_stupid_ahh_shit_flow_fix) *(PBYTE)addr = 0xEB;

	NlLog("fix_dump: fix_sha256");
	fix_sha256();

	NlLog("fix_dump: hijack_requestor");
	hijack_requestor();

	NlLog("fix_dump: last_resort_fixes");
	last_resort_fixes();

	NlLog("fix_dump: install_crypto_capture");
	install_crypto_capture();
};