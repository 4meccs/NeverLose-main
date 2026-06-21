#include "internal_fixes.h"
#include "HookFn.h"
#include "FindPattern.h"
#include <cstdio>
#include "detours.h"
#include <vector>

enum operation_t
{
    OPERATION_REGISTER_HOOK = 1,
    OPERATION_EMPLACE_HOOKS,
    OPERATION_ERASE_HOOKS,
    OPERATION_SIGSCAN = 6,
};

#pragma pack(push, 1)
struct sigscan_t
{
    PVOID64 Base;
    PVOID64 Signature;
    size_t Length;
    PVOID64 Result;
};

struct hook_t
{
    PVOID64 Address;
    PVOID64 Hook;
    PVOID64 pTrampoline;
};
#pragma pack(pop)

struct HookDesc
{
    bool IsActive;
    PVOID Address;
    PVOID Trampoline;
    PVOID Hook;
};

static auto& g_HkDesc = *reinterpret_cast<std::vector<HookDesc>*>(0x42500C44);
static bool TransactionAlive = false;

BOOL __cdecl hkMemDispatcher(operation_t type, void* ptr)
{
    BOOL result = FALSE;

    switch (type)
    {
    case OPERATION_SIGSCAN:
    {
        auto* data = (sigscan_t*)ptr;
        data->Result = FindPattern(data->Base, 0x7FFFFFFF, (PBYTE)data->Signature, data->Length, 0xCC, 0);
        result = TRUE;
    };
    break;
    case OPERATION_REGISTER_HOOK:
    {
        if (!TransactionAlive)
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            TransactionAlive = true;
        };

        auto* data = (hook_t*)ptr;
        PVOID pTramp = data->Address;

        // skip hooks targeting specific internal addresses
        if (data->Hook == (PVOID)0x415A9820 && !*((DWORD*)&data->Hook + 1))
            return TRUE;

        if (DetourAttachEx(&pTramp, data->Hook, (PDETOUR_TRAMPOLINE*)data->pTrampoline, NULL, NULL) == NO_ERROR)
        {
            result = TRUE;
        }
        else
            result = FALSE;
    };
    break;
    case OPERATION_EMPLACE_HOOKS:
        if (TransactionAlive)
        {
            DetourTransactionCommit();
            TransactionAlive = false;
            result = TRUE;
        }
        else
            result = FALSE;
        break;
    case OPERATION_ERASE_HOOKS:
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        for (auto& hook : g_HkDesc)
        {
            if (hook.IsActive && hook.Trampoline && hook.Hook != (PVOID)0x415DE500)
            {
                DetourDetach(&hook.Trampoline, hook.Hook);
                hook.IsActive = false;
            };
        };
        DetourTransactionCommit();
        result = TRUE;
    };
    break;
    default:
        break;
    };
    return result;
};


void fix_mem_dispatcher()
{
	HookFn((PVOID)0x41DA0BA0, hkMemDispatcher, 0);
};
