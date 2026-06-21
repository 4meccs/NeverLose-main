#pragma once
#include <windows.h>

inline void __cdecl NlLog(const char* fmt, ...)
{
    char line[4096];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int prefix = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02u:%02u:%02u.%03u] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (prefix < 0) prefix = 0;
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(line + prefix, sizeof(line) - prefix, _TRUNCATE, fmt, args);
    va_end(args);

    OutputDebugStringA(line);

    char path[MAX_PATH];
    if (GetTempPathA(MAX_PATH, path))
    {
        strcat_s(path, "nl_embed.log");
        HANDLE file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            DWORD written;
            WriteFile(file, line, (DWORD)strlen(line), &written, nullptr);
            WriteFile(file, "\r\n", 2, &written, nullptr);
            CloseHandle(file);
        }
    }
}
