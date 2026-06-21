#include "neverlose.h"
#include "cpuid_emulator.h"
#include "ArenaAllocator.h"
#include "HookFn.h"

void neverlose::spoof_cpuid()
{
	PVOID cpuid_emu = load_res_to_mem(IDR_CPUID_EMU, "cpuid emulator");

	ArenaAllocator<cpuid_emu_emplacement> cpuid_emu_arena(g_cpuid_emus.size());

	for (auto& [address, nops] : g_cpuid_emus)
	{
		auto* pcpuid_tramp = cpuid_emu_arena.construct(cpuid_emu);
		HookFn((PVOID)address, pcpuid_tramp->data, nops, (PVOID*)&pcpuid_tramp->JumpBackAddr, 2);
	};

	for (DWORD bp_addr : g_veh_cpuid_emus)
	{
		*(PBYTE)bp_addr = 0xCC;
		*((PBYTE)bp_addr + 1) = 0x58;
	};
};