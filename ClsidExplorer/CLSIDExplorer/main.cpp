#include "main.h"
#include "Parser.h"

void ShowHelp()
{
	std::wcout << L"CLSIDExplorer.exe - get all info about clsid" << std::endl;
	std::wcout << L"Usage:" << std::endl;
	std::wcout << L".\\CLSIDExplorer.exe --clsid \"{00000618-0000-0010-8000-00aa006d2ea4}\"" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "");

	std::wstring wsclsid;
	for (int i = 1; i < argc; ++i) {
		if (std::wstring(argv[i]) == L"--clsid" && i + 1 < argc) {
			wsclsid = argv[i + 1];
		}
	}

	if (argc != 3 || wsclsid.size() == 0)
	{
		ShowHelp();
		return -1;
	}

	std::wcout << L"[" << wsclsid << L"]" << std::endl;

	CoInitialize(NULL);
	
	HRESULT hr;

	CLSID clsid;
	hr = CLSIDFromString(wsclsid.c_str(), &clsid);
	if (FAILED(hr))
	{
		std::wcout << L"[-] Cannot convert to CLSID: " << wsclsid << std::endl;
		return hr;
	}

	std::wstring appId;
	if (Registry::GetAppIdFromClsid(wsclsid, appId) == ERROR_SUCCESS)
	{
		std::wcout << L"\tAppID: " << appId << std::endl;
	} 
	else {
		std::wcout << L"\tAppID: Unknown" << std::endl;
	}

	std::wstring progId;
	if (Registry::GetProgIdFromClsid(wsclsid, progId) == ERROR_SUCCESS)
	{
		std::wcout << L"\tProgID: " << progId << std::endl;
	}
	else {
		std::wcout << L"\tProgID: Unknown" << std::endl;
	}

	std::wstring runAs;
	if (!appId.empty())
	{
		if (Registry::GetRunAsKeyFromAppId(appId, runAs) == ERROR_SUCCESS)
		{
			std::wcout << L"\tRunAs: " << runAs << std::endl;
		}
		else {
			std::wcout << L"\tRunAs: The launching user" << std::endl;
		}
	}

	CComPtr<IUnknown> pUnknown = nullptr;

	hr = CoCreateInstance(clsid,
		nullptr,
		CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
		IID_IUnknown,
		reinterpret_cast<void**>(&pUnknown));

	DWORD pid;
	if (Process::GetPIDFromIUnknown(pUnknown, &pid))
	{
		std::wcout << L"\tPID: " << pid << std::endl;

		std::wcout << L"\tProcess Name: " << Process::GetProcessName(pid) << std::endl;
		
		std::wcout << L"\tUsername: " << Process::GetProcessUserName(pid) << std::endl;

	}
	else {
		std::wcout << L"\tPID: Unknown" << std::endl;
	}

	std::vector<std::wstring> methods;

	if (TypeLib::GetMethodsFromTypelib(pUnknown, methods) == ERROR_SUCCESS)
	{
		std::wcout << "\tMethods:" << std::endl;
		
		for (int i = 0; i < methods.size(); i++)
		{
			std::wcout << " \t[" << i << L"] " << methods[i] << std::endl;
		}
	}


	std::wcout << L"[END]" << std::endl;

	return 0;
}