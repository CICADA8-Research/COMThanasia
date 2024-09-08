#include "main.h"


LONG WINAPI MyVectoredExceptionHandler(PEXCEPTION_POINTERS exceptionInfo)
{
	std::wcout << L"\t[!] Exception occurred!" << std::endl;

	std::wcout << L"\t[!] Exception Code: " << exceptionInfo->ExceptionRecord->ExceptionCode << std::endl;
	std::wcout << L"\t[!] Exception Address: " << exceptionInfo->ExceptionRecord->ExceptionAddress << std::endl;

	std::wcout << L"\t[!!!] If program had crashed pls restart using .\\COMHunter.exe --from <last showed clsid>" << std::endl;

	return EXCEPTION_EXECUTE_HANDLER;
}

void WriteDataToCSV(HANDLE hFile, const std::vector<std::wstring>& row)
{
	SetFilePointer(hFile, 0, NULL, FILE_END);
	bool first = true;
	for (const auto& cell : row)
	{
		if (!first)
		{
			WCHAR comma = L',';
			DWORD bytesWritten;
			WriteFile(hFile, &comma, sizeof(comma), &bytesWritten, NULL);
		}
		else
		{
			first = false;
		}

		DWORD bytesWritten;
		WriteFile(hFile, cell.c_str(), cell.size() * sizeof(WCHAR), &bytesWritten, NULL);
	}

	WCHAR newline = L'\n';
	DWORD bytesWritten;
	WriteFile(hFile, &newline, sizeof(newline), &bytesWritten, NULL);
}

std::wstring FormatHResult(HRESULT hr) {
	std::wstringstream ss;
	ss << L"- Err: 0x" << std::hex << hr;

	if (HRESULT_FACILITY(hr) == FACILITY_WIN32) {
		hr = HRESULT_CODE(hr); 
	}

	LPWSTR errorMsg = nullptr;
	DWORD size = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&errorMsg, 0, nullptr);

	std::wstring errorDesc = (size != 0 && errorMsg != nullptr) ? errorMsg : L"Unknown Error";
	if (errorMsg) {
		LocalFree(errorMsg);
	}

	if (!errorDesc.empty() && errorDesc.back() == L'\n') {
		errorDesc.pop_back();
	}

	return ss.str() + L" " + errorDesc;
}

bool IsBlacklisted(const std::wstring& clsid, const std::vector<std::wstring>& blackList)
{
	std::wstring clsidLower = clsid;

	std::transform(clsidLower.begin(), clsidLower.end(), clsidLower.begin(), ::towlower);

	for (const auto& blacklistedClsid : blackList) {
		std::wstring blacklistedClsidLower = blacklistedClsid;
		std::transform(blacklistedClsidLower.begin(), blacklistedClsidLower.end(), blacklistedClsidLower.begin(), ::towlower);

		if (clsidLower == blacklistedClsidLower) {
			return true;
		}
	}

	return false;
}


void ShowHelp()
{
	std::cout << R"(
	,,_
       zd$$??=
     z$$P? F:`c,                _
    d$$, `c'cc$$i           ,cd$?R
   $$$$ cud$,?$$$i       ,=P"2?z "
    $" " ?$$$,?$$$.    ,-''`>, bzP
     'cLdb,?$$,?$$$   ,h' "I$'J$P
  ... `?$$$,"$$,`$$h  $$PxrF'd$"
d$PP""?-,"?$$,?$h`$$,,$$'$F44"
?,,_`=4c,?=,"?hu?$`?L4$'? '
   `""?==""=-"" `""-`'_,,,,
           .ccu?m?e?JC,-,"=?
		"""=='?"
	)" << std::endl;
	std::wcout << L"ComTraveller - small tool to parse and extract information about all registered CLSIDs on the system" << std::endl;
	std::wcout << L"Usage: " << std::endl;
	std::wcout << L"--file <output> - output filename. Default: output.csv" << std::endl;
	std::wcout << L"--from <clsid> - start exploring clsids from this clsid. (for ex. default enum from 1 to 9. with --from 4 will be from 4 to 9)" << std::endl;
	std::wcout << L"--session <session> - use if you want to check Cross-Session Activation in a specific session. Useful only with 'Run as interactive user COM objects'" << std::endl;
	std::wcout << L"--target <CLSID> - analyze this CLSID" << std::endl;
	std::wcout << L"-h/--help - shows this screen" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "");
	std::wstring startFromCLSID;
	std::wstring targetCLSID;
	std::wstring outputFilename = L"output.csv";
	DWORD session = 0;

	for (int i = 1; i < argc; i++) {
		if (std::wstring(argv[i]) == L"--from" && i + 1 < argc) {
			startFromCLSID = argv[i + 1];
		}
		else if (std::wstring(argv[i]) == L"--file" && i + 1 < argc) {
			outputFilename = argv[i + 1];
		}
		else if (std::wstring(argv[i]) == L"--session" && i + 1 < argc) {
			session = _wtoi(argv[i + 1]);
		}
		else if (std::wstring(argv[i]) == L"--target" && i + 1 < argc)
		{
			targetCLSID = argv[i + 1];
		}
		else if (((std::wstring(argv[i]) == L"-h") || (std::wstring(argv[i]) == L"--help")))
		{
			ShowHelp();
			return 0;
		}
	}

	std::wcout << L"[COM Traveller] Starting......." << std::endl;
	std::wcout << L"[COM Traveller] Params:" << std::endl;
	std::wcout << L"[Initial CLSID. Empty -> not specified] " << startFromCLSID << std::endl;
	std::wcout << L"[Target CLSID. Empty -> not specified] " << targetCLSID << std::endl;
	std::wcout << L"[Output FileName] " << outputFilename << std::endl;
	std::wcout << L"[Activate in session. 0 -> dont checking] " << session << std::endl;
	Sleep(1000);

	HANDLE hFile = CreateFileW(
		outputFilename.c_str(),
		FILE_APPEND_DATA | GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::wcerr << L"[-] Can't open file " << outputFilename << L" for writing" << std::endl;
		return 1;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE)
	{
		std::wcerr << L"[-] Can't get file size for " << outputFilename << std::endl;
		CloseHandle(hFile);
		return 1;
	}

	WCHAR bom = 0xFEFF; // UTF-16-LE BOM Header
	DWORD bytesWritten;
	WriteFile(hFile, &bom, sizeof(bom), &bytesWritten, NULL);

	if (AddVectoredExceptionHandler(1, MyVectoredExceptionHandler) == nullptr)
	{
		std::wcout << L"[-] Failed to add the exception handler!" << std::endl;
		return 1;
	}

	CoInitialize(NULL);
	
	std::vector<std::wstring> clsidList;
	if (targetCLSID.empty())
	{
		clsidList = EnumerateCLSID();
	}
	else
	{
		clsidList.push_back(targetCLSID);
	}

	std::vector<std::wstring> clsidBlackList;

	// WIN10 Optional
	/*
	std::vector<std::wstring> clsidBlackList =
	{
		L"CLSID",
		L"{00B01B2E-B1FE-33A6-AD40-57DE8358DC7D}",
		L"{0A14D3FF-EC53-450f-AA30-FFBC55BE26A2}",
		L"{010911E2-F61C-479B-B08C-43E6D1299EFE}",
		L"{1b7cd997-e5ff-4932-a7a6-2a9e636da385}",
		L"{0B30F034-02D5-4E2B-9BB7-A9F6538F4110}",
		L"{1123D0C1-886C-42C3-98E6-7109780E8BE2}",
		L"{1910E202-236A-43E6-9469-FE0B3149F3D9}",
		L"{1b283861-754f-4022-ad47-a5eaaa618894}",
		L"{1b7cd997-e5ff-4932-a7a6-2a9e636da385}",
		L"{1ee7337f-85ac-45e2-a23c-37c753209769}",
		L"{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}",
		L"{1FA9085F-25A2-489B-85D4-86326EEDCD87}",
		L"{23F6D342-08C4-4E48-89B3-0BC8BF990783}",
		L"{265b1075-d22b-41eb-bc97-87568f3e6dab}",
		L"{2DCD7FDB-8809-48E4-8E4F-3157C57CF987}",
		L"{2F21A1B8-750B-4AC7-A6E2-C70A3F2D21FB}",
		L"{31337EC7-5767-11CF-BEAB-00AA006C3606}",
		L"{34684F0B-6721-4DC5-AF04-A8C2C1C3609}",
		L"{34684F0B-6721-4DC5-AF04-A8C2C1C3609E}",
		L"{36BAA497-8C84-4700-96A1-88E1876EC5B9}",
		L"{337448ee-2a70-43f7-99f9-40f2857950b9}", // Crashes program
		L"{4032FE99-EA88-432C-B870-D975C9F1D5F9}",
		L"{41945702-8302-44A6-9445-AC98E8AFA086}",
		L"{454CBB06-6BDE-4F0D-8392-C4BCE2A0B71B}",
		L"{45BA127D-10A8-46EA-8AB7-56EA9078943C}",
		L"{4575438F-A6C8-4976-B0FE-2F26B80D959E}",
		L"{4729dc2b-36ff-405f-bd36-f45113adb052}", // Crashes program
		L"{49E6370B-AB71-40AB-92F4-B009593E4518}",
		L"{4A56AF32-C21F-11DB-96FA-005056C00008}", // Crashes program
		L"{4B601364-A04B-38BC-BD38-A18E981324CF}",
		L"{4C1D33D1-3161-4A76-9487-2677CD589C11}",
		L"{50FDBB99-5C92-495E-9E81-E2C2F48CDDAE}",
		L"{55200BC1-D537-44E2-BC6B-DD098A015FA1}",
		L"{63766597-1825-407D-8752-098F33846F46}", // Killing output
		L"{6850404F-D7FB-32BD-8328-C94F66E8C1C7}",
		L"{69F9CB25-25E2-4BE1-AB8F-07AA7CB535E8}",
		L"{6ACB028E-48C0-4A44-964C-E14567C578BA}",
		L"{6C3EE638-B588-4D7D-B30A-E7E36759305D}",
		L"{73AD6842-ACE0-45E8-A4DD-8795881A2C2A}",
		L"{749962AB-D849-46D5-A39C-75A8307C2C86}",
		L"{7724F5B4-9A4A-4a93-AD09-B06F7AB31035}",
		L"{78D22140-40CF-303E-BE96-B3AC0407A34D}",
		L"{8A99553A-7971-4445-93B5-AAA43D1433C5}",
		L"{95243A62-2F9B-4FDF-B437-40D965F6D17F}", // Crashes program
		L"{99B29D3B-368A-4BE6-B675-805A69114497}", // Crashes program
		L"{9A3A64F4-8BA5-3DCF-880C-8D3EE06C5538}",
		L"{9B78F0E6-3E05-4A5B-B2E8-E743A8956B65}",
		L"{9B97D384-048C-4e24-926D-DB6F0841C9E4}",
		L"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}",
		L"{9BF8D948-5C56-450e-BAF8-D6144C6E81CB}",
		L"{9c15e692-86da-4ab8-8b5e-6ac79deb6f20}",
		L"{9C24A977-0951-451A-8006-0E49BD28CD5F}",
		L"{9C49FB9B-4E8C-43AE-BACF-76404B422264}",
		L"{9C4D3346-650D-472d-A867-6F595B39D973}",
		L"{9C67F424-22DC-3D05-AB36-17EAF95881F2}",
		L"{9C695035-48D2-4229-8B73-4C70E756E519}",
		L"{9C73F5E5-7AE7-4E32-A8E8-8D23B85255BF}",
		L"{9C86F320-DEE3-4DD1-B972-A303F26B061E}",
		L"{9c8db22b-8ddc-471c-9628-48847514b424}",
		L"{9CAB4470-D6FA-4903-986C-7D5A755B2691}",
		L"{9caf4a2e-c957-48c7-b4d2-4d11188e0b94}",
		L"{9cb233a5-a4a5-46b9-ab13-db07ce949410}",
		L"{9CB5172B-D600-46BA-AB77-77BB7E3A00D9}",
		L"{9CB89EFF-B39E-4D5C-A493-F2171580CC21}",
		L"{9cca66bb-9c78-4e59-a76f-a5e9990b8aa0}",
		L"{9CD64701-BDF3-4D14-8E03-F12983D86664}",
		L"{9cfc2df3-6ba3-46ef-a836-e519e81f0ec4}",
		L"{9d06f027-cbfc-421a-97b3-f09a8a9359bc}",
		L"{9D148290-B9C8-11D0-A4CC-0000F80149F6}",
		L"{9DAC2C1E-7C5C-40eb-833B-323E85A1CE84}",
		L"{A0F8D82C-E4D8-4ED9-BD3A-867A830B12BA}",
		L"{AA75448A-2459-4C8C-A801-3C98D7CA3D45}",
		L"{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}",
		L"{A961F842-FC8E-4D53-8074-4AB67E8854B4}",
		L"{BA126ADF-2166-11D1-B1D0-00805FC1270E}",
		L"{c39b7f77-976c-4983-b888-dbdc948d5364}", // Crashes program
		L"{CC6D9715-F553-4299-B2CE-6C7851FAA03A}",
		L"{ecabafc0-7f19-11d2-978e-0000f8757e2a}",
		L"{e5b35059-a1be-4977-9bee-5c44226340f7}",
		L"{EDA59C23-FCB4-44AF-BFE0-3708C08A212D}",
		L"{E0BA3BF5-25EF-459F-9EE0-855FD3666692}",
		L"{FFE8C349-2BB1-411F-93CE-0364C5F9FD9F}"
	}; // WIN10 Enterprise
	*/
	std::wcout << "[+] Total CLSID: " << clsidList.size() << std::endl;

	std::vector<std::vector<std::wstring>> data;

	if (fileSize == 0) {
		data.push_back({ L"CLSID", L"AppID", L"ProgID", L"RunAs", L"Username", L"PID", L"ProcessName", L"HasTypeLib", L"canCrossSessionActivate"});

		WriteDataToCSV(hFile, data.back());
	}

	auto it = clsidList.begin();
	if (!startFromCLSID.empty()) {
		it = std::find(clsidList.begin(), clsidList.end(), startFromCLSID);
		if (it == clsidList.end()) {
			std::wcerr << L"[-] Specified CLSID not found in the list: " << startFromCLSID << std::endl;
			return 1;
		}
		else
		{
			++it; // --from + 1
		}
	}

	for (; it != clsidList.end(); ++it)
	{
		const auto& wsclsid = *it;

		std::wcout << L"----------------------------" << std::endl;
		std::wcout << L"----[" << wsclsid << L"]----" << std::endl;

		std::wstring appId = L"";
		std::wstring progId = L"";
		std::wstring runAs = L"";
		std::wstring username = L"";
		std::wstring processName = L"";
		std::wstring hasTypeLib = L"-";
		std::wstring canCrossSessionActivate = L"?";
		DWORD pid = 0;

		if (GetAppIdFromClsid(wsclsid, appId) != ERROR_SUCCESS)
		{
			std::wcout << L"\t[-] Error in getting AppId info about CLSID: " << wsclsid << std::endl;
		}

		if (GetProgIdFromClsid(wsclsid, progId) != ERROR_SUCCESS)
		{
			std::wcout << L"\t[-] Error in getting ProgId info about CLSID: " << wsclsid << std::endl;
		}

		if (!appId.empty())
		{
			if (GetRunAsKeyFromAppId(appId, runAs) != ERROR_SUCCESS)
			{
				std::wcout << L"\t[-] Error getting runas for AppId: " << appId << std::endl;
			}
		}

		HRESULT hr;
		CComPtr<IUnknown> pUnknown = nullptr;

		CLSID clsid;

		hr = CLSIDFromString(wsclsid.c_str(), &clsid);
		if (!SUCCEEDED(hr))
		{
			std::wcout << L"\t[-] Error in converting " << wsclsid << L" to CLSID" << std::endl;
			continue;
		}

		if (IsBlacklisted(wsclsid, clsidBlackList))
		{
			std::wcout << L"\t[!] Found blacklisted clsid. Skipping" << std::endl;
			continue;
		}

		std::wcout << L"\t[?] Trying to start CLSID: " << wsclsid << std::endl;

		hr = CoCreateInstance(clsid,
			nullptr,
			CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
			IID_IUnknown,
			reinterpret_cast<void**>(&pUnknown));

		if (!SUCCEEDED(hr))
		{
			std::wcout << L"\t[-] Error in CoCreateInstance: " << hr << L" CLSID: " << wsclsid << std::endl;
			continue;
		}

		std::wcout << L"\t[+] Creation success " << wsclsid << std::endl;

		CComPtr<IDispatch> pDispatch;
		hr = pUnknown->QueryInterface(IID_IDispatch, (void**)&pDispatch);
		if (SUCCEEDED(hr))
		{
			if (HasTypeLib(pDispatch))
			{
				hasTypeLib = L"+";
			}
		}

		if (GetPIDFromIUnknown(pUnknown, &pid) != TRUE)
		{
			std::wcout << L"\t[-] Can't get PID from clsid: " << wsclsid << std::endl;
		}

		if (pid != 0)
		{
			std::wcout << L"\t[+] PID: " << pid << std::endl;
			processName = GetProcessName(pid);
			std::wcout << L"\t[+] Process: " << processName << std::endl;
			username = GetProcessUserName(pid);
			std::wcout << L"\t[+] Username: " << username << std::endl;
		}

		if (session != 0)
		{
			canCrossSessionActivate = L"-";

			CComPtr<IUnknown> pUnkCross;
			HRESULT hr = CoCreateInstanceInSession(session, clsid, IID_IUnknown, (void**)&pUnkCross);
			switch (hr)
			{
			case S_OK:
				canCrossSessionActivate = L"+";
				break;
			default:
				canCrossSessionActivate = FormatHResult(hr);
			}
		}

		std::wcout << L"\t[+] AppID: " << appId << std::endl;
		std::wcout << L"\t[+] RunAs: " << runAs << std::endl;
		std::wcout << L"\t[+] HasTypeLib: " << hasTypeLib << std::endl;
		std::wcout << L"\t[+] Cross Session: " << canCrossSessionActivate << std::endl;

		data.push_back({ std::wstring(wsclsid.begin(), wsclsid.end()),
			std::wstring(appId.begin(), appId.end()),
			std::wstring(progId.begin(), progId.end()),
			std::wstring(runAs.begin(), runAs.end()),
			std::wstring(username.begin(), username.end()),
			std::to_wstring(pid),
			std::wstring(processName.begin(), processName.end()),
			std::wstring(hasTypeLib.begin(), hasTypeLib.end()),
			std::wstring(canCrossSessionActivate.begin(), canCrossSessionActivate.end())
		});

		WriteDataToCSV(hFile, data.back());
	}

	CloseHandle(hFile);

	std::wcout << L"[+] Success" << std::endl;
	CoUninitialize();

	return 0;
}
