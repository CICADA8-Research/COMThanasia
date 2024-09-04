#include "Parser.h"


DWORD Registry::GetAppIdFromClsid(IN std::wstring clsid, OUT std::wstring& appId)
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
	else
	{
		return ERROR_NOT_FOUND;
	}

	RegCloseKey(hClsidKey);

	return ERROR_SUCCESS;
}

DWORD Registry::GetProgIdFromClsid(IN std::wstring clsid, OUT std::wstring& progId)
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

DWORD Registry::GetRunAsKeyFromAppId(IN std::wstring appId, OUT std::wstring& runAs)
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


std::wstring TypeLib::GetTypeName(ITypeInfo* pTypeInfo, TYPEDESC* pTypeDesc)
{
	CComBSTR bstrName;
	HRESULT hr = S_OK;

	switch (pTypeDesc->vt)
	{
	case VT_I2: return L"short";
	case VT_I4: return L"long";
	case VT_R4: return L"float";
	case VT_R8: return L"double";
	case VT_CY: return L"CURRENCY";
	case VT_DATE: return L"DATE";
	case VT_BSTR: return L"BSTR";
	case VT_DISPATCH: return L"IDispatch*";
	case VT_ERROR: return L"SCODE";
	case VT_BOOL: return L"VARIANT_BOOL";
	case VT_VARIANT: return L"VARIANT";
	case VT_UNKNOWN: return L"IUnknown*";
	case VT_DECIMAL: return L"DECIMAL";
	case VT_I1: return L"char";
	case VT_UI1: return L"unsigned char";
	case VT_UI2: return L"unsigned short";
	case VT_UI4: return L"unsigned long";
	case VT_INT: return L"int";
	case VT_UINT: return L"unsigned int";
	case VT_HRESULT: return L"HRESULT";
	case VT_VOID: return L"void";
	case VT_LPSTR: return L"LPSTR";
	case VT_LPWSTR: return L"LPWSTR";
	case VT_PTR:
		return GetTypeName(pTypeInfo, pTypeDesc->lptdesc) + L"*";
	case VT_USERDEFINED:
	{
		CComPtr<ITypeInfo> spRefTypeInfo;
		hr = pTypeInfo->GetRefTypeInfo(pTypeDesc->hreftype, &spRefTypeInfo);
		if (SUCCEEDED(hr))
		{
			TYPEATTR* pRefTypeAttr;
			hr = spRefTypeInfo->GetTypeAttr(&pRefTypeAttr);
			if (SUCCEEDED(hr))
			{
				spRefTypeInfo->GetDocumentation(MEMBERID_NIL, &bstrName, NULL, NULL, NULL);
				spRefTypeInfo->ReleaseTypeAttr(pRefTypeAttr);
				return std::wstring(bstrName);
			}
		}
	}
	break;
	default:
		break;
	}

	return L"unknown";
}

DWORD TypeLib::GetMethodsFromTypelib(IN IUnknown* pUnknown, OUT std::vector<std::wstring>& methods)
{
	CComPtr<IDispatch> pDispatch = nullptr;
	HRESULT hr;

	hr = pUnknown->QueryInterface(IID_IDispatch, (void**)&pDispatch);
	if (FAILED(hr))
		return hr;

	CComPtr<ITypeInfo> spTypeInfo;
	TYPEATTR* pTypeAttr = nullptr;

	hr = pDispatch->GetTypeInfo(0, LOCALE_USER_DEFAULT, &spTypeInfo);
	if (FAILED(hr))
	{
		std::wcout << L"Failed to get type info." << std::endl;
		return hr;
	}

	hr = spTypeInfo->GetTypeAttr(&pTypeAttr);
	if (FAILED(hr))
	{
		std::wcout << L"Failed to get type attributes." << std::endl;
		return hr;
	}

	for (UINT i = 0; i < pTypeAttr->cFuncs; ++i)
	{
		FUNCDESC* pFuncDesc = nullptr;
		hr = spTypeInfo->GetFuncDesc(i, &pFuncDesc);
		if (SUCCEEDED(hr))
		{
			BSTR bstrName;
			UINT cNames;
			hr = spTypeInfo->GetNames(pFuncDesc->memid, &bstrName, 1, &cNames);
			if (SUCCEEDED(hr))
			{
				std::wstring returnType = GetTypeName(spTypeInfo, &pFuncDesc->elemdescFunc.tdesc);

				std::wstring callConv;
				switch (pFuncDesc->callconv)
				{
				case CC_FASTCALL:
					callConv = L"__fastcall";
					break;
				case CC_CDECL:
					callConv = L"__cdecl";
					break;
				case CC_MPWPASCAL:
				case CC_PASCAL:
					callConv = L"__pascal";
					break;
				case CC_MACPASCAL:
					callConv = L"__macpascal";
					break;
				case CC_MPWCDECL:
				case CC_SYSCALL:
				case CC_STDCALL:
					callConv = L"__stdcall";
					break;
				case CC_FPFASTCALL:
					callConv = L"__fpfastcall";
					break;
				default:
					callConv = L"";
					break;
				}

				std::wstring params;
				for (UINT j = 0; j < pFuncDesc->cParams; ++j)
				{
					if (j > 0) params += L", ";

					std::wstring paramFlag;
					if (pFuncDesc->lprgelemdescParam[j].paramdesc.wParamFlags & PARAMFLAG_FIN)
						paramFlag += L"IN ";
					if (pFuncDesc->lprgelemdescParam[j].paramdesc.wParamFlags & PARAMFLAG_FOUT)
						paramFlag += L"OUT ";

					params += paramFlag + GetTypeName(spTypeInfo, &pFuncDesc->lprgelemdescParam[j].tdesc);
				}

				methods.push_back(callConv + L" " + returnType + L" " + bstrName + L"(" + params + L")");
			

				SysFreeString(bstrName);
			}
			spTypeInfo->ReleaseFuncDesc(pFuncDesc);
		}
	}

	spTypeInfo->ReleaseTypeAttr(pTypeAttr);

	return ERROR_SUCCESS;
}

std::wstring Process::GetUserNameFromSID(PSID sid)
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

std::wstring Process::GetProcessUserName(DWORD pid)
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
	std::wstring userName = Process::GetUserNameFromSID(sid);

	CloseHandle(hToken);
	CloseHandle(hProcess);

	return userName;
}

BOOL Process::GetPIDFromIUnknown(IN IUnknown* pUnknown, OUT DWORD* pid)
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

std::wstring Process::GetProcessName(DWORD processID) {
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