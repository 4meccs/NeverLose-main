#include "neverlose.h"
#include "nl_log.h"

NTSTATUS NTAPI MainThread(LPVOID lpThreadParameter)
{
	NlLog("MainThread started (hModule=0x%p)", lpThreadParameter);
	g_neverlose.map((HMODULE)lpThreadParameter);

	while (!GetModuleHandleW(L"serverbrowser.dll"))
		Sleep(100);

	g_neverlose.fix_dump();
	g_neverlose.set_veh();
	g_neverlose.setup_hooks();
	g_neverlose.spoof();

	g_neverlose.entry();

	return STATUS_SUCCESS;
};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		HANDLE hThread;
		NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), MainThread, hinstDLL, THREAD_CREATE_FLAGS_NONE, 0, 0, 0, NULL);
		if (!NT_SUCCESS(status))
			return FALSE;
		NtClose(hThread);
	};

	return TRUE;
};