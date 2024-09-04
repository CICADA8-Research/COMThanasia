#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <atlbase.h>
#include <Psapi.h>
#include <strsafe.h>

typedef struct tagDATAELEMENT
{
    GUID dataID;
    unsigned long cbSize;
    unsigned long cbRounded;
    /* [size_is] */ BYTE Data[1];
}   DATAELEMENT;

typedef struct tagDUALSTRINGARRAY
{
    unsigned short wNumEntries;
    unsigned short wSecurityOffset;
    /* [size_is] */ unsigned short aStringArray[1];
}   DUALSTRINGARRAY;

typedef unsigned __int64 OXID;
typedef unsigned __int64 OID;
typedef GUID           IPID;

typedef struct tagOBJREFDATA
{
    unsigned long nElms;
    /* [unique][size_is][size_is] */ DATAELEMENT** ppElmArray;
}   OBJREFDATA;

typedef struct tagSTDOBJREF {
    unsigned long flags;
    unsigned long cPublicRefs;
    OXID oxid;
    OID  oid;
    IPID ipid;
} STDOBJREF;

typedef struct tagOBJREF {
    unsigned long signature;
    unsigned long flags;
    GUID        iid;
    union {
        struct {
            STDOBJREF     std;
            DUALSTRINGARRAY saResAddr;
        } u_standard;
        struct {
            STDOBJREF     std;
            CLSID         clsid;
            DUALSTRINGARRAY saResAddr;
        } u_handler;
        struct {
            CLSID         clsid;
            unsigned long   cbExtension;
            unsigned long   size;
            byte* pData;
        } u_custom;
        struct {
            STDOBJREF     std;
            unsigned long   Signature1;
            DUALSTRINGARRAY saResAddr;
            unsigned long   nElms;
            unsigned long   Signature2;
            DATAELEMENT   ElmArray;
        } u_extended;
    } u_objref;
} OBJREF, * LPOBJREF;

typedef struct _IPID_ENTRY {
    IID   iid;
    IPID  ipid;                // IPID to bind to
    OXID  oxid;                // Object Exporter ID
    OID   oid;
} IPID_ENTRY, * PIPID_ENTRY;


#define OBJREF_SIGNATURE    ( 0x574f454d )

#define OBJREF_STANDARD ( 0x1 )
#define OBJREF_HANDLER  ( 0x2 )
#define OBJREF_CUSTOM   ( 0x4 )
#define OBJREF_EXTENDED ( 0x8 )

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

bool CheckRegistryValue(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName, std::wstring& outValue)
{
    HKEY hKey;
    if (RegOpenKeyEx(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD dwType = 0;
    DWORD dwSize = 0;
    if (RegQueryValueEx(hKey, valueName.c_str(), nullptr, &dwType, nullptr, &dwSize) != ERROR_SUCCESS || (dwType != REG_SZ && dwType != REG_EXPAND_SZ))
    {
        RegCloseKey(hKey);
        return false;
    }

    std::wstring value(dwSize / sizeof(wchar_t), L'\0');
    if (RegQueryValueEx(hKey, valueName.c_str(), nullptr, &dwType, reinterpret_cast<LPBYTE>(&value[0]), &dwSize) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    outValue.assign(value.c_str(), dwSize / sizeof(wchar_t) - 1);
    return true;
}

bool CheckRegistryDWORD(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName, DWORD& outValue)
{
    HKEY hKey;
    if (RegOpenKeyEx(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD dwType = 0;
    DWORD dwSize = sizeof(DWORD);
    if (RegQueryValueEx(hKey, valueName.c_str(), nullptr, &dwType, reinterpret_cast<LPBYTE>(&outValue), &dwSize) != ERROR_SUCCESS || dwType != REG_DWORD)
    {
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

bool DoesKeyExist(HKEY hKeyRoot, const std::wstring& subKey)
{
    HKEY hKey;
    if (RegOpenKeyEx(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool GetDefaultRegistryValue(HKEY hKeyRoot, const std::wstring& subKey, std::wstring& outValue)
{
    return CheckRegistryValue(hKeyRoot, subKey, L"", outValue);
}

HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, void** ppv)
{
    BIND_OPTS3 bo;
    WCHAR wszCLSID[50];
    WCHAR wszMon[300];

    StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID) / sizeof(wszCLSID[0]));
    HRESULT hr = StringCchPrintfW(wszMon, sizeof(wszMon) / sizeof(wszMon[0]), L"Elevation:Administrator!new:%s", wszCLSID);
    if (FAILED(hr))
        return hr;
    memset(&bo, 0, sizeof(bo));
    bo.cbStruct = sizeof(bo);
    bo.hwnd = hwnd;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;
    return CoGetObject(wszMon, &bo, riid, ppv);
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

void ShowBanner()
{
    std::cout << R"(
 
          ,_  _  _,
            \o-o/
           ,(.-.),
         _/ |) (| \_
           /\=-=/\
          ,| \=/ |,
        _/ \  |  / \_
            \_!_/
        
 MonikerHound - find your own UAC Bypass!
)" << std::endl;
   
    std::wcout << L"\t CICADA8 Research Team" << std::endl;
    std::wcout << L"\t From Michael Zhmaylo (MzHmO)\n" << std::endl;
}

int main()
{
    ShowBanner();
    std::vector<std::wstring> clsids = EnumerateCLSID();

    if (clsids.empty())
    {
        std::wcerr << L"Cant get CLSIDs" << std::endl;
        return -1;
    }

    CoInitialize(NULL);

    HRESULT hr;

    for (const auto& wsclsid : clsids)
    {
        std::wstring registryPath = L"SOFTWARE\\Classes\\CLSID\\" + wsclsid;

        std::wstring name;
        bool nameValueExists = GetDefaultRegistryValue(HKEY_LOCAL_MACHINE, registryPath, name);

        std::wstring localizedString;
        bool localizedStringExists = CheckRegistryValue(HKEY_LOCAL_MACHINE, registryPath, L"LocalizedString", localizedString);

        std::wstring elevationPath = registryPath + L"\\Elevation";
        bool elevationFolderExists = DoesKeyExist(HKEY_LOCAL_MACHINE, elevationPath);

        DWORD enabledValue;
        bool enabledExists = CheckRegistryDWORD(HKEY_LOCAL_MACHINE, elevationPath, L"Enabled", enabledValue);

        std::wstring iconReferenceValue;
        bool iconReferenceExists = CheckRegistryValue(HKEY_LOCAL_MACHINE, elevationPath, L"IconReference", iconReferenceValue);

        if (localizedStringExists && elevationFolderExists && enabledExists && iconReferenceExists)
        {
            std::wcout << L"[+] Potential COM server for elevation moniker found!" << std::endl;
            std::wcout << L"Name: " << name << std::endl;
            std::wcout << L"CLSID: " << wsclsid << std::endl;
            std::wcout << L"LocalizedString: " << localizedString << std::endl;
            std::wcout << L"Enabled: " << enabledValue << std::endl;
            std::wcout << L"IconReference: " << iconReferenceValue << std::endl;

            CComPtr<IUnknown> pUnknown;
            CLSID clsid;

            hr = CLSIDFromString(wsclsid.c_str(), &clsid);
            if (FAILED(hr))
            {
                std::wcout << L"Activate: Failed (CLSIDFromString Err:" << hr << L")" << std::endl;
                continue;
            }

            hr = CoCreateInstanceAsAdmin(NULL, clsid, IID_IUnknown, (void**)&pUnknown);

            if (FAILED(hr))
            {
                std::wcout << L"Activate: Failed (CoCreateInstanceAsAdmin Err:" << hr << L")" << std::endl;
                continue;
            }

            std::wcout << L"Activate: Success" << std::endl;

            DWORD pid;
            if (GetPIDFromIUnknown(pUnknown, &pid))
            {
                std::wcout << L"PID: " << pid << std::endl;
                std::wcout << GetProcessName(pid) << std::endl;
            }

            std::wcout << L"[+]........................[+]" << std::endl;
        }
    }



    return 0;
}