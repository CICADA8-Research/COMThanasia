#include "analyzer.h"
#include "enumerator.h"

void SetConsoleColor(WORD color)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

std::wstring toLowerCase(const std::wstring& input) {
	std::wstring result = input;
	std::transform(result.begin(), result.end(), result.begin(), ::tolower);
	return result;
}

void WriteRedText(const std::wstring& text)
{
	SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);

	std::wcout << text << std::endl;

	SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void WriteGreenText(const std::wstring& text)
{
	SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	std::wcout << text << std::endl;

	SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

bool CheckRegistryKeyExists(HKEY hive, const std::wstring& path) {
	HKEY hKey;
	DWORD res = RegOpenKeyEx(hive, path.c_str(), 0, KEY_READ, &hKey);
	if (res == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return true;
	}
	return false;
}


std::wstring GetFullPathFromPID(DWORD pid, const std::wstring& fileName) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess) {
		wchar_t processPath[MAX_PATH];
		if (GetModuleFileNameEx(hProcess, NULL, processPath, MAX_PATH)) {
			wchar_t* filePart;
			if (GetFullPathName(fileName.c_str(), MAX_PATH, processPath, &filePart)) {
				CloseHandle(hProcess);
				return std::wstring(processPath);
			}
		}
		CloseHandle(hProcess);
	}
	return fileName;
}

std::wstring GetCurrentUsername()
{
	wchar_t username[255 + 1];
	DWORD username_len = 255 + 1;
	if (GetUserNameW(username, &username_len)) {
		return std::wstring(username);
	}
	else {
		return L"";
	}
}

std::wstring ExpandEnvironmentStringsIfNeeded(const std::wstring& input) {
	if (input.empty()) {
		return input;
	}

	std::vector<wchar_t> expandedPath(MAX_PATH);
	DWORD result = ExpandEnvironmentStrings(input.c_str(), expandedPath.data(), MAX_PATH);
	if (result == 0 || result > MAX_PATH) {
		return input;
	}

	return std::wstring(expandedPath.data());
}

std::wstring GetRegistryStringValue(HKEY hKeyRoot, const std::wstring& subKey) {
	HKEY hKey;
	LONG lResult = RegOpenKeyEx(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS) {
		DWORD dw = GetLastError();
		return L"";
	}

	DWORD dwType = 0;
	DWORD dwSize = 0;
	lResult = RegQueryValueEx(hKey, nullptr, nullptr, &dwType, nullptr, &dwSize);

	if (lResult != ERROR_SUCCESS || (dwType != REG_SZ && dwType != REG_EXPAND_SZ)) {
		RegCloseKey(hKey);
		return L"";
	}

	std::wstring value(dwSize / sizeof(wchar_t), L'\0');
	lResult = RegQueryValueEx(hKey, nullptr, nullptr, nullptr, reinterpret_cast<LPBYTE>(&value[0]), &dwSize);

	RegCloseKey(hKey);

	if (lResult != ERROR_SUCCESS) {
		return L"";
	}

	if (!value.empty() && value.back() == L'\0') {
		value.pop_back();
	}

	if (dwType == REG_EXPAND_SZ) {
		value = ExpandEnvironmentStringsIfNeeded(value);
	}

	return value;
}

bool CheckFileWriteAccess(const std::wstring& filePath)
{
	DWORD filePermissions = GENERIC_WRITE;
	HANDLE hFile = CreateFile(filePath.c_str(), filePermissions, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD dw = GetLastError();
		return false;
	}
	else {
		CloseHandle(hFile);
		return true;
	}
}

std::wstring GetRootKeyName(HKEY hKey) {
	if (hKey == HKEY_CURRENT_USER) return L"HKCU";
	if (hKey == HKEY_LOCAL_MACHINE) return L"HKLM";
	if (hKey == HKEY_CLASSES_ROOT) return L"HKCR";
	return L"";
}

std::pair<std::wstring, std::wstring> FindPathFromRegistry(const std::wstring& clsid)
{
	const std::wstring paths[] = {
		L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\TreatAs",
		L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\InprocServer32",
		L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\LocalServer32"
	};

	for (const auto& hKey : { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE })
	{
		for (const auto& partialPath : paths)
		{
			std::wstring value = GetRegistryStringValue(hKey, partialPath);
			if (!value.empty())
			{
				std::wstring fullPath = GetRootKeyName(hKey) + L"\\" + partialPath;
				return { value, fullPath };
			}
		}
	}

	return { L"", L"" };
}

bool CheckRegistryWriteCreateAccess(HKEY hive, const std::wstring& path)
{
	HKEY hKey;
	REGSAM samDesired = KEY_WRITE | KEY_CREATE_SUB_KEY;

	DWORD res = RegOpenKeyEx(hive, path.c_str(), 0, samDesired, &hKey);
	if (res == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return true;
	}

	res = RegCreateKeyEx(hive, path.c_str(), 0, NULL,
		REG_OPTION_VOLATILE, // temporary key
		KEY_WRITE | KEY_CREATE_SUB_KEY,
		NULL, &hKey, NULL);

	if (res == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);

		RegDeleteKey(hive, path.c_str());

		return true;
	}
	return false;
}

std::wstring GetFileName(const std::wstring& path)
{
	if (path.empty()) {
		return L"";
	}

	size_t start = 0;
	size_t end = path.length();

	if (path[0] == L'"') {
		start = 1;
		for (size_t i = start; i < path.length(); ++i) {
			if (path[i] == L'"') {
				end = i;
				break;
			}
		}
	}
	else {
		for (size_t i = 0; i < path.length(); ++i) {
			if (path[i] == L' ') {
				end = i;
				break;
			}
		}
	}

	return path.substr(start, end - start);
}

VOID AnalyzeCLSID(std::wstring& wsclsid, BOOL checkCreate, BOOL checkAnotherContext)
{
	HRESULT hr;
	CComPtr<IUnknown> pUnknown = nullptr;

	CLSID clsid;


	hr = CLSIDFromString(wsclsid.c_str(), &clsid);
	if (!SUCCEEDED(hr))
	{
		//std::wcout << L"\t[-] Error in converting " << wsclsid << L" to CLSID" << std::endl;
		return;
	}

	std::wcout << L"----------------------------" << std::endl;
	std::wcout << L"----[" << wsclsid << L"]----" << std::endl;
	
	// Checking Create Rights
	if (checkCreate)
	{
		hr = CoCreateInstance(clsid,
			nullptr,
			CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
			IID_IUnknown,
			reinterpret_cast<void**>(&pUnknown));

		if (!SUCCEEDED(hr))
		{
			std::wcout << L"\t[-] Error in CoCreateInstance: " << hr << L" CLSID: " << wsclsid << std::endl;
			return;
		}
	}

	std::wstring username = L"";
	std::wstring processName = L"";
	std::wstring runAs = L"";
	DWORD pid = 0;


	// Checking another user context
	if (checkAnotherContext)
	{
		std::wstring appId = L"";

		if (GetAppIdFromClsid(wsclsid, appId) != ERROR_SUCCESS)
		{
			//std::wcout << L"\t[-] Can't find AppId. May be there is no another context" << std::endl;
			return;
		}

		if (GetRunAsKeyFromAppId(appId, runAs) != ERROR_SUCCESS)
		{
			//std::wcout << L"\t[-] Cant get PID and cant get RunAs key -> NO ANOTHER CONTEXT" << std::endl;
			return;
		}

		if (GetPIDFromIUnknown(pUnknown, &pid) == TRUE)
		{
			std::wstring currentUsername = GetCurrentUsername();
			username = GetProcessUserName(pid);

			if (username.find(currentUsername) != std::wstring::npos && runAs.empty())
			{
				//std::wcout << L"\t[+] Running from current user: " << username << std::endl;
				// runAs.empty() <- NO Option Interactive User
				return;
			}

			processName = GetProcessName(pid);

		}
	}

	std::wcout << L"\t[+] Username: " << username << std::endl;
	std::wcout << L"\t[+] RunAs Value: " << runAs << std::endl;
	std::wcout << L"\t[+] Process: " << processName << std::endl;
	std::wcout << L"\t[+] PID: " << pid << std::endl;

	// Analiyzing Insecure Registry Permissions
	std::pair<std::wstring, std::wstring> result = FindPathFromRegistry(wsclsid);

	if (result.first.empty())
	{
		//std::wcout << L"No associated file found for CLSID " << wsclsid << std::endl;
		return;
	}

	std::wcout << L"\t[+] Disk Path: " << result.first << std::endl;
	std::wcout << L"\t[+] Registry Path: " << result.second << std::endl;
	
	std::wcout << L"\t[?] Load priority hijacking: " << std::endl;
	const std::wstring priorities[] = {
		L"HKCU\\Software\\Classes\\CLSID\\" + wsclsid + L"\\TreatAs",
		L"HKLM\\Software\\Classes\\CLSID\\" + wsclsid + L"\\TreatAs",
		L"HKCU\\Software\\Classes\\CLSID\\" + wsclsid + L"\\InprocServer32",
		L"HKLM\\Software\\Classes\\CLSID\\" + wsclsid + L"\\InprocServer32",
		L"HKCU\\Software\\Classes\\CLSID\\" + wsclsid + L"\\LocalServer32",
		L"HKLM\\Software\\Classes\\CLSID\\" + wsclsid + L"\\LocalServer32"
	};

	for (size_t i = 0; i < std::size(priorities); ++i) {
		const auto& path = priorities[i];
		HKEY hKey;
		if (path.find(L"HKCU") == 0)
			hKey = HKEY_CURRENT_USER;
		else if (path.find(L"HKLM") == 0)
			hKey = HKEY_LOCAL_MACHINE;
		else
			continue;

		bool exists = CheckRegistryKeyExists(hKey, path.substr(path.find_first_of(L'\\') + 1));
		bool writable = CheckRegistryWriteCreateAccess(hKey, path.substr(path.find_first_of(L'\\') + 1));

		std::wstring output = L"\t\t[" + std::to_wstring(i + 1) + L"] " + (writable ? L"Writable" : L"Non Writable") + L": ";
		output += path + L" (" + (exists ? L"Exists" : L"Does not exists") + L")";

		if (writable) {
			WriteRedText(output);
		}
		else {
			std::wcout << output << std::endl;
		}

		if (toLowerCase(path) == toLowerCase(result.second))
		{
			WriteGreenText(L"\t\t[" + std::to_wstring(i + 1) + L"] Real Path: " + path);
			break;
		}
	}


	// Analyzing File Disk Permissions
	std::wstring strippedPath = GetFileName(result.first);
	if (PathIsRelative(strippedPath.c_str())) {
		strippedPath = GetFullPathFromPID(pid, strippedPath);
	}

	if (CheckFileWriteAccess(strippedPath))
	{
		WriteRedText(L"\t[+] Writable path on disk: " + strippedPath);
	}


	return;
}