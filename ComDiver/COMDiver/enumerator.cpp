#include "enumerator.h"

std::vector<std::wstring> EnumerateCLSID()
{
    std::vector<std::wstring> clsidList;
    HKEY hKey;
    LONG nError;

    nError = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey);
    if (nError == ERROR_SUCCESS)
    {
        DWORD dwIndex = 0;
        WCHAR szName[MAX_PATH];
        DWORD dwNameSize = _countof(szName);
        FILETIME ftLastWriteTime;

        while (RegEnumKeyEx(hKey, dwIndex, szName, &dwNameSize, NULL, NULL, NULL, &ftLastWriteTime) == ERROR_SUCCESS)
        {
            clsidList.push_back(szName);
            dwNameSize = _countof(szName);
            dwIndex++;
        }

        RegCloseKey(hKey);
    }
    else
    {
        std::wcerr << L"Cant open HKEY_CLASSES_ROOT\\CLSID. Error: " << nError << std::endl;
    }

    return clsidList;
}

DWORD GetAppIdFromClsid(IN std::wstring clsid, OUT std::wstring& appId)
{
    HKEY hClsidKey;
    std::wstring clsidSubKey = L"CLSID\\" + clsid;
    if (RegOpenKeyEx(HKEY_CLASSES_ROOT, clsidSubKey.c_str(), 0, KEY_READ, &hClsidKey) != ERROR_SUCCESS)
    {
        return ERROR_OPEN_FAILED;
    }

    TCHAR valueBuffer[256];
    DWORD valueBufferSize = sizeof(valueBuffer);

    if (RegQueryValueEx(hClsidKey, L"AppID", NULL, NULL, (LPBYTE)valueBuffer, &valueBufferSize) == ERROR_SUCCESS)
    {
        appId = valueBuffer;
    }

    RegCloseKey(hClsidKey);

    return ERROR_SUCCESS;
}

DWORD GetProgIdFromClsid(IN std::wstring clsid, OUT std::wstring& progId)
{
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CLASSES_ROOT, NULL, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return ERROR_OPEN_FAILED;
    }

    DWORD index = 0;
    TCHAR subKeyName[256];
    DWORD subKeyNameSize = sizeof(subKeyName) / sizeof(subKeyName[0]);
    LONG ret = ERROR_SUCCESS;

    while ((ret = RegEnumKeyEx(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS)
    {
        HKEY hSubKey;

        if (RegOpenKeyEx(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
        {
            DWORD valueBufferSize = 0;
            if (RegQueryValueEx(hSubKey, L"CLSID", NULL, NULL, NULL, &valueBufferSize) == ERROR_SUCCESS)
            {
                TCHAR* valueBuffer = new TCHAR[valueBufferSize / sizeof(TCHAR)];
                if (RegQueryValueEx(hSubKey, L"CLSID", NULL, NULL, (LPBYTE)valueBuffer, &valueBufferSize) == ERROR_SUCCESS)
                {
                    if (clsid == valueBuffer)
                    {
                        progId = subKeyName;
                        delete[] valueBuffer;
                        RegCloseKey(hSubKey);
                        RegCloseKey(hKey);
                        return ERROR_SUCCESS;
                    }
                }
                delete[] valueBuffer;
            }
            RegCloseKey(hSubKey);
        }

        subKeyNameSize = sizeof(subKeyName) / sizeof(subKeyName[0]);
        index++;
    }

    RegCloseKey(hKey);
    return ERROR_NOT_FOUND;
}

DWORD GetRunAsKeyFromAppId(IN std::wstring appId, OUT std::wstring& runAs)
{
    std::wstring appIdSubKey = L"AppID\\" + appId;
    HKEY hAppIdKey;
    if (RegOpenKeyEx(HKEY_CLASSES_ROOT, appIdSubKey.c_str(), 0, KEY_READ, &hAppIdKey) == ERROR_SUCCESS)
    {
        DWORD valueBufferSize = 256;
        TCHAR* valueBuffer = new TCHAR[valueBufferSize / sizeof(TCHAR)];
        if (RegQueryValueEx(hAppIdKey, L"RunAs", NULL, NULL, (LPBYTE)valueBuffer, &valueBufferSize) == ERROR_SUCCESS)
        {
            runAs = valueBuffer;
            return ERROR_SUCCESS;
        }
        RegCloseKey(hAppIdKey);
    }
    return ERROR_OBJECT_NOT_FOUND;
}

std::wstring GetUserNameFromSID(PSID sid)
{
    WCHAR name[256];
    WCHAR domain[256];
    DWORD nameSize = sizeof(name) / sizeof(WCHAR);
    DWORD domainSize = sizeof(domain) / sizeof(WCHAR);
    SID_NAME_USE sidUse;

    if (!LookupAccountSid(NULL, sid, name, &nameSize, domain, &domainSize, &sidUse))
        return L"";

    std::wstring fullName(domain);
    fullName += L"\\\\";
    fullName += name;

    return fullName;
}

std::wstring GetProcessUserName(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
        return L"";

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return L"";
    }

    DWORD bufferSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &bufferSize);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return L"";
    }

    std::vector<BYTE> buffer(bufferSize);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), bufferSize, &bufferSize))
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return L"";
    }

    PSID sid = reinterpret_cast<PTOKEN_USER>(buffer.data())->User.Sid;
    std::wstring userName = GetUserNameFromSID(sid);

    CloseHandle(hToken);
    CloseHandle(hProcess);

    return userName;
}

BOOL GetPIDFromIUnknown(IN IUnknown* pUnknown, OUT DWORD* pid)
{
    CComPtr<IStream> marshalStream;
    CreateStreamOnHGlobal(NULL, TRUE, &marshalStream);

    CoMarshalInterface(
        marshalStream,
        IID_IUnknown,
        pUnknown,
        MSHCTX_INPROC,
        NULL,
        MSHLFLAGS_NORMAL
    );

    HGLOBAL memoryHandleFromStream = NULL;
    GetHGlobalFromStream(marshalStream, &memoryHandleFromStream);

    LPOBJREF objref = reinterpret_cast<LPOBJREF> (GlobalLock(memoryHandleFromStream));
    if (objref && objref->signature == OBJREF_SIGNATURE)
    {
        IPID ipid;

        if (objref->flags == OBJREF_STANDARD)
        {
            ipid = objref->u_objref.u_standard.std.ipid;
        }
        else if (objref->flags == OBJREF_HANDLER)
        {
            ipid = objref->u_objref.u_handler.std.ipid;
        }
        else if (objref->flags == OBJREF_EXTENDED)
        {
            ipid = objref->u_objref.u_extended.std.ipid;
        }
        else if (objref->flags == OBJREF_CUSTOM)
        {
            return FALSE;
        }

        static const int COM_SERVER_PID_OFFSET = 4;

        *pid = *reinterpret_cast<LPWORD>(
            (reinterpret_cast<LPBYTE>(&ipid) + COM_SERVER_PID_OFFSET)
            );
        return *pid != 0xffff;
    }
}

std::wstring GetProcessName(DWORD processID) {
    std::wstring processName = L"";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            wchar_t szProcessName[MAX_PATH];
            if (GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(wchar_t))) {
                processName = szProcessName;
            }
        }
        else
        {
            std::wcout << L"[-] EnumProcessModules() Failed: " << GetLastError() << std::endl;
        }

        CloseHandle(hProcess);
    }

    return processName;
}