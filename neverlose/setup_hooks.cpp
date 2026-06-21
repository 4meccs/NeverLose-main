#define _WINSOCKAPI_

#include <intrin.h>
#include <Windows.h>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <vector>
#include <cstring>
#include <cstdarg>

#include "neverlose.h"
#include "HookFn.h"
#include "FindPattern.h"
#include "json.hpp"
#include "neverlosesdk.hpp"

struct vec2_t
{
    float x;
    float y;
};

static void set_nl_logo(const char* name)
{
    constexpr size_t MAXLEN = 16;

    char buffer[MAXLEN] = { 0 };

    size_t len = strlen(name);
    if (len > MAXLEN)
        len = MAXLEN;

    memcpy(buffer, name, len);

    uint32_t* buff = reinterpret_cast<uint32_t*>(buffer);

    *(uint32_t*)0x4160555E = buff[0] ^ 0xD7E76FF9;
    *(uint32_t*)0x41605558 = buff[1] ^ 0xBA5A7287;
    *(uint32_t*)0x41605576 = buff[2] ^ 0x2D725D76;
    *(uint32_t*)0x41605570 = buff[3] ^ 0x4066CCAE;
}

HMODULE WaitForSingleModule(const char* module_name)
{
    HMODULE mod = nullptr;

    while (!mod)
    {
        mod = GetModuleHandleA(module_name);
        Sleep(0);
    }

    return mod;
}

void WSAAPI ProceedGetAddrInfo(
    PVOID retaddr,
    PCSTR* ppNodeName,
    PCSTR* ppServiceName)
{
    PVOID pBase = NULL;

    if (RtlPcToFileHeader(retaddr, &pBase) == (PVOID)0x412A0000)
    {
        *ppNodeName = "127.0.0.1";
        *ppServiceName = "30030";
    }
}

void* getaddr_tram = nullptr;

INT __declspec(naked) WSAAPI hkgetaddrinfo(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult)
{
    __asm
    {
        push ebp
        mov ebp, esp
        lea eax, [ebp + 12]
        push eax
        lea eax, [ebp + 8]
        push eax
        push [ebp + 4]
        call ProceedGetAddrInfo
        mov esp, ebp
        pop ebp

        push ebp
        mov ebp, esp
        jmp getaddr_tram
    }
}

NTSTATUS hkterm(HANDLE, NTSTATUS)
{
    RtlExitUserThread(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

void hkexit(int)
{
    RtlExitUserThread(STATUS_SUCCESS);
}

void __stdcall errhandl(std::exception& ec, PVOID a2)
{
    NtSuspendProcess(NtCurrentProcess());
}

void __fastcall performmenu(neverlosesdk::gui::Menu& menu)
{
    menu.IsOpen = !menu.IsOpen;
}

void* sndtram = nullptr;

void __fastcall hksend(
    void* hdl,
    void* edx,
    void* a1,
    void* const payload,
    size_t size)
{
    reinterpret_cast<void(__thiscall*)(void*, void*, void* const, size_t)>(
        sndtram
    )(hdl, a1, payload, size);
}

using tClickableText = int(__cdecl*)(const char*, vec2_t*, bool);
void* clickable_text_tram = nullptr;

int __cdecl hkClickableText(
    const char* text,
    vec2_t* size,
    bool force_style)
{
    return reinterpret_cast<tClickableText>(
        clickable_text_tram
    )(text, size, force_style);
}

using tRenderAvatar = int(__cdecl*)(
    void***,
    vec2_t*,
    const void*,
    const void*,
    int,
    int,
    float,
    int
);

void* render_avatar_tram = nullptr;

int __cdecl hkRenderAvatar(
    void*** texture_ptr,
    vec2_t* size,
    const void* uv_min,
    const void* uv_max,
    int tint_color,
    int border_params,
    float rounding,
    int interactive)
{
    float new_rounding = size->x * 0.5f;

    return reinterpret_cast<tRenderAvatar>(
        render_avatar_tram
    )(
        texture_ptr,
        size,
        uv_min,
        uv_max,
        tint_color,
        border_params,
        new_rounding,
        interactive
    );
}

static void PatchCopyrightText()
{
    const char* default_copyright = "neverlose.cc \xC2\xA9 2020-2026";
    char copyright[32] = { 0 };

    char path[MAX_PATH] = { 0 };
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)&PatchCopyrightText, &mod) && mod)
    {
        GetModuleFileNameA(mod, path, sizeof(path));
        char* p = strrchr(path, '\\');
        if (p)
        {
            *(p + 1) = '\0';
            strcat_s(path, sizeof(path), "nl_cloud\\state.json");
        }
    }

    HANDLE hFile = CreateFileA(path[0] ? path : "nl_cloud\\state.json", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        char buf[65536] = { 0 };
        DWORD read = 0;
        if (ReadFile(hFile, buf, sizeof(buf) - 1, &read, nullptr))
        {
            buf[read] = '\0';
            const char* key = "\"copyright\": \"";
            const char* p = strstr(buf, key);
            if (p)
            {
                p += strlen(key);
                const char* end = strchr(p, '"');
                if (end)
                {
                    size_t len = end - p;
                    if (len > 31) len = 31;
                    memcpy(copyright, p, len);
                    copyright[len] = '\0';
                }
            }
        }
        CloseHandle(hFile);
    }

    if (copyright[0] == '\0')
        strcpy_s(copyright, sizeof(copyright), default_copyright);

    char plaintext[32] = { 0 };
    size_t len = strlen(copyright);
    if (len > 31) len = 31;
    memcpy(plaintext, copyright, len);

    static const DWORD xk39[4] = { 0x4EE22AB1, 0x2DB6684B, 0xF8009786, 0x3BFABFB6 };
    static const DWORD xk40[4] = { 0x9726CACB, 0x9BDF5145, 0x1742CC28, 0x13C66ED0 };

    static const DWORD old_v39[4] = { 0x2B944FDF, 0x5ED90439, 0x9B63B9E3, 0x1B537D96 };
    static const DWORD old_v40[4] = { 0xA714FAF9, 0xA9EF6368, 0x1742CC1B, 0x13C66ED0 };

    DWORD new_v39[4], new_v40[4];
    DWORD* p32 = (DWORD*)plaintext;
    for (int i = 0; i < 4; i++)
    {
        new_v39[i] = p32[i] ^ xk39[i];
        new_v40[i] = p32[4 + i] ^ xk40[i];
    }

    BYTE* base = (BYTE*)g_neverlose.base();
    SIZE_T size = g_neverlose.size();
    // v39[1] (39 04 D9 5E) ?? ?? ?? v39[0] (DF 4F 94 2B)
    BYTE pat_v39[] = { 0x39, 0x04, 0xD9, 0x5E, 0xCC, 0xCC, 0xCC, 0xDF, 0x4F, 0x94, 0x2B };
    BYTE* found_v39 = (BYTE*)FindPattern(base, size, pat_v39, sizeof(pat_v39), 0xCC, 0);
    if (!found_v39) return;

    static const int off_v39[4] = { 7, 0, 0x21, 0x1A };
    static const int idx_v39[4] = { 0, 1, 2, 3 };
    for (int i = 0; i < 4; i++)
    {
        DWORD* target = (DWORD*)(found_v39 + off_v39[i]);
        DWORD old;
        VirtualProtect(target, 4, PAGE_EXECUTE_READWRITE, &old);
        *target = new_v39[idx_v39[i]];
        VirtualProtect(target, 4, old, &old);
    }

    // v40[1] (68 63 EF A9) ?? ?? ?? v40[0] (F9 FA 14 A7)
    BYTE pat_v40[] = { 0x68, 0x63, 0xEF, 0xA9, 0xCC, 0xCC, 0xCC, 0xF9, 0xFA, 0x14, 0xA7 };
    BYTE* found_v40 = (BYTE*)FindPattern(base, size, pat_v40, sizeof(pat_v40), 0xCC, 0);
    if (!found_v40) return;

    static const int off_v40[4] = { 7, 0, 0x21, 0x1A };
    static const int idx_v40[4] = { 0, 1, 2, 3 };
    for (int i = 0; i < 4; i++)
    {
        DWORD* target = (DWORD*)(found_v40 + off_v40[i]);
        DWORD old;
        VirtualProtect(target, 4, PAGE_EXECUTE_READWRITE, &old);
        *target = new_v40[idx_v40[i]];
        VirtualProtect(target, 4, old, &old);
    }

    FlushInstructionCache(GetCurrentProcess(), found_v39, 0x60);
}

void neverlose::setup_hooks()
{
    set_nl_logo("NEVERLOSE");
    PatchCopyrightText();

    HMODULE WS2 = WaitForSingleModule("ws2_32.dll");
    FARPROC getaddrinfo = GetProcAddress(WS2, "getaddrinfo");

    getaddr_tram = (PBYTE)getaddrinfo + 5;
    HookFn(getaddrinfo, hkgetaddrinfo, 0);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    FARPROC ntterm = GetProcAddress(ntdll, "NtTerminateProcess");
    HookFn(ntterm, hkterm, 0);

    HookFn((PVOID)0x42026080, hkexit, 0);
    HookFn((PVOID)0x4200A118, errhandl, 0);
    HookFn((PVOID)0x415E9086, performmenu, 0);
    HookFn((PVOID)0x41609C80, performmenu, 0);

    HookFn((PVOID)0x41C16EA0, hksend, 0, &sndtram);
    HookFn((PVOID)0x41CA9440, hkClickableText, 0, &clickable_text_tram);
    HookFn((PVOID)0x41CAAAE0, hkRenderAvatar, 0, &render_avatar_tram);
}