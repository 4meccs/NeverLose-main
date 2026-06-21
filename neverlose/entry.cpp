#include "neverlose.h"

constexpr uintptr_t winver_entry_point = 0x412A0000;

NTSTATUS __declspec(naked) NTAPI _fictive_(LPVOID lpThreadParameter)
{
	__asm
	{
		push 0
		call RtlExitUserProcess
	};
};

void neverlose::entry()
{
	HANDLE hThread;

	if (!NT_SUCCESS(NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PUSER_THREAD_START_ROUTINE)winver_entry_point, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0x40000, 0x40000, NULL))) panic("Failed to create thread!\n");

	THREAD_BASIC_INFORMATION tbi{0};
	if (!NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL))) panic("Failed to get TIB!\n");

	NtResumeThread(hThread, NULL);

	tbi = { 0 };

	NtWaitForSingleObject(hThread, FALSE, NULL);
	NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);

	NtClose(hThread);
};
