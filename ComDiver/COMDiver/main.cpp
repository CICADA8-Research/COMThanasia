#include "main.h"
#include "argparse.h"
#include "enumerator.h"
#include "analyzer.h"


LONG WINAPI MyVectoredExceptionHandler(PEXCEPTION_POINTERS exceptionInfo)
{
	std::wcout << L"\t[!] Exception occurred!" << std::endl;

	std::wcout << L"\t[!] Exception Code: " << exceptionInfo->ExceptionRecord->ExceptionCode << std::endl;
	std::wcout << L"\t[!] Exception Address: " << exceptionInfo->ExceptionRecord->ExceptionAddress << std::endl;

	std::wcout << L"\t[!!!] If program had crashed pls restart using .\\COMDiver.exe --from <last showed clsid>" << std::endl;

	return EXCEPTION_EXECUTE_HANDLER;
}

void ShowHelp()
{
	std::cout << R"(
              \     /
          \    o ^ o    /
            \ (     ) /
 ____________(%%%%%%%)____________
(     /   /  )%%%%%%%(  \   \     )
(___/___/__/           \__\___\___)
   (     /  /(%%%%%%%)\  \     )
    (__/___/ (%%%%%%%) \___\__)
            /(       )\
          /   (%%%%%)   \
               (%%%)
                 !
	)" << std::endl;
	std::wcout << L"----------- COM DIVER --------------" << std::endl;
	std::wcout << L"[?] Small tool to check insecure registry and disk permissions on com objects" << std::endl;
	std::wcout << L"[?] ARGS" << std::endl;
	std::wcout << L"\t-h/--help <- show this message" << std::endl;
	std::wcout << L"\t--from <CLSID> <- analyze CLSIDs from this clsid" << std::endl;
	std::wcout << L"\t--target <CLSID> <- analyze one target clsid" << std::endl;
	std::wcout << L"\t--no-context <- dont check another COM-server context. Only registry analyzing." << std::endl;
	std::wcout << L"\t--no-create <- dont create target COM object. This is the fastest mode" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "");

	if (cmdOptionExists(argv, argv + argc, L"-h") || cmdOptionExists(argv, argv + argc, L"--help"))
	{
		ShowHelp();
		return 0;
	}

	std::wstring targetClsid;
	if (cmdOptionExists(argv, argv + argc, L"--target"))
	{
		targetClsid = getCmdOption(argv, argv + argc, L"--target");
	}

	std::wstring startFromClsid;
	if (cmdOptionExists(argv, argv + argc, L"--from"))
	{
		startFromClsid = getCmdOption(argv, argv + argc, L"--from");
	}

	BOOL checkAnotherContext = TRUE;
	if (cmdOptionExists(argv, argv + argc, L"--no-context"))
	{
		checkAnotherContext = FALSE;
	}

	BOOL checkCreate = TRUE;
	if (cmdOptionExists(argv, argv + argc, L"--no-create"))
	{
		checkCreate = FALSE;
	}

	if (AddVectoredExceptionHandler(1, MyVectoredExceptionHandler) == nullptr)
	{
		std::wcout << L"[-] Failed to add the exception handler!" << std::endl;
		return 1;
	}

	std::vector<std::wstring> clsidList;
	if (targetClsid.empty())
	{
		std::wcout << L"[+] Analyzing all CLSIDs" << std::endl;
		clsidList = EnumerateCLSID();
	}
	else
	{
		std::wcout << L"[+] Analyzing CLSID: " << targetClsid << std::endl;
		clsidList.push_back(targetClsid);
	}

	CoInitialize(NULL);
	std::wcout << "[+] Total CLSID: " << clsidList.size() << std::endl;

	auto it = clsidList.begin();
	if (!startFromClsid.empty()) {
		it = std::find(clsidList.begin(), clsidList.end(), startFromClsid);
		if (it == clsidList.end()) {
			std::wcerr << L"[-] Specified CLSID not found in the list: " << startFromClsid << std::endl;
			return 1;
		}
		else
		{
			++it; // --from + 1
		}
	}

	for (; it != clsidList.end(); it++)
	{
		AnalyzeCLSID(*it, checkCreate, checkAnotherContext);
	}

	CoUninitialize();

	return 0;
}