#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <comdef.h>
#include <atlbase.h>
#include <vector>
#include <psapi.h>

static class Registry
{
public:
	static DWORD GetAppIdFromClsid(IN std::wstring clsid, OUT std::wstring& appId);
	static DWORD GetProgIdFromClsid(IN std::wstring clsid, OUT std::wstring& progId);
	static DWORD GetRunAsKeyFromAppId(IN std::wstring appId, OUT std::wstring& runAs);

private:

};

static class TypeLib
{
public:
	static DWORD GetMethodsFromTypelib(IN IUnknown* pUnknown, OUT std::vector<std::wstring>& methods);
	static std::wstring GetTypeName(ITypeInfo* pTypeInfo, TYPEDESC* pTypeDesc);
};


static class Process
{
public:
	static std::wstring GetProcessUserName(DWORD pid);
	static std::wstring GetProcessName(DWORD processID);
	static std::wstring GetUserNameFromSID(PSID sid);
	static BOOL GetPIDFromIUnknown(IN IUnknown* pUnknown, OUT DWORD* pid);
};



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