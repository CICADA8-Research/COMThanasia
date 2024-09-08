# COMThanasia

## TL;DR
With this tool, you will be able to detect:
- Incorrect access control to a COM object (LaunchPermission , AccessPermission) - LPE through abusable COM methods, DCOM Authentication relaying. That's `PermissionHunter`.
- Incorrect registry rights to a COM object - LPE through COM Hijacking. That's `ComDiver`.
- Find new Elevation Moniker - UAC Bypass. That's `MonikerHound`.
- Get detailed information about a specific CLSID - Inspect COM object to find abusable COM Methods. That's `ClsidExplorer`.
- Check Cross-Session Activation on behalf of a low-privileged user - Attempting to instantiate an object in someone else's session for LPE. That's `ComTraveller`.

If we had published this tool a couple months ago (e.g. Spring 2024), you would have discovered CVE-2024-38100 (FakePotato) and CVE-2024-38061 (SilverPotato).

Start using this tool and you can find more ways to elevate privilege on Windows systems. It's like an automated OleViewDotnet :)

![изображение](https://github.com/user-attachments/assets/57dc0eaa-4fbf-47e7-a65a-e7d0ef5960d5)


## PermissionHunter
### What is this
PermissionHunter is a tool that allows you to examine LaunchPermission and ActivatePermission on all COM objects on the system.

```shell
PS A:\mzhmo> .\PermissionHunter.exe -h

                     ,
                `-.   \    .-'
        ,-"`````""-\__ |  /
         '-.._    _.-'` '-o,
             _>--:{{<   ) |)
         .-''      '-.__.-o`
        '-._____..-/`  |  \
                ,-'   /    `-.
                      `
  PermissionHunter - hunt for incorrect LaunchPermission and ActivatePermission

        CICADA8 Research Team
        From Michael Zhmaylo (MzHmO)

PermissionHunter.exe
Small tool that allows you to find vulnerable COM objects with incorrect LaunchPermission and ActivatePermission

[OPTIONS]
-outfile : output filename
-outformat : output format. Accepted 'csv' and 'xlsx'
-h/--help : shows this windows
```
There are only two arguments here:
- `-outfile` - name of the file with the rights report;
- `-outformat` - format of the file with the report, you can output both in csv and xlsx. It is better to output in csv, because if you do not have Excel, you will not be able to output in xlsx format.

### Usage
Example:
```shell
PS A:\mzhmo> .\PermissionHunter -outfile result -outformat xlsx

                     ,
                `-.   \    .-'
        ,-"`````""-\__ |  /
         '-.._    _.-'` '-o,
             _>--:{{<   ) |)
         .-''      '-.__.-o`
        '-._____..-/`  |  \
                ,-'   /    `-.
                      `
  PermissionHunter - hunt for incorrect LaunchPermission and ActivatePermission

        CICADA8 Research Team
        From Michael Zhmaylo (MzHmO)

[+] Result will be in result, format xlsx
[+] Success
```

After that you will get a file result.xlsx, which will list all rights to existing COM objects.
![изображение](https://github.com/user-attachments/assets/f72ec28c-02b5-40e0-a262-af842d58f94d)

I output the following columns:
- `ApplicationID` - ApplicationID of a specific COM object. Ex: `{69AD4AEE-51BE-439b-A92C-86AE490E8B30}`;
- `ApplicationName` - ApplicationName of a specific COM object. Ex: `Background Intelligent Transfer Service`;
- `RunAs` - RunAs registry key of a COM object. Ex: `Interactive User`;
- `LaunchAccess`, `LaunchType`, `LaunchPrincipal`, `LaunchSid` - LaunchPermission registry key. LaunchPrincipal specifies the user who has LaunchAccess rights to the COM object. LaunchType - type of ACE: enabling or disabling. LaunchSID - SID of LaunchPrincipal. Ex:
```shell
LocalLaunch. RemoteLaunch. LocalActivation. RemoteActivation	AccessAllowed	NT AUTHORITY\SYSTEM	S-1-5-18
```
This means that the system has LocalLaunch, RemoteLaunch, LocalActivation, RemoteActivation permissions on this COM object;
- `AccessAccess`, `AccessType`, `AccessPrincipal`, `AccessSID` - fields have the same meaning as LaunchPermissions, only in the context of AccessPermission;
- `AuthLevel`, `ImpLevel` - Authentication Level and Impersonation Level. By default they are set to `RPC_C_AUTHN_LEVEL_CONNECT` and `RPC_C_IMP_LEVEL_IDENTIFY`;
- `CLSIDs` - COM object CLSIDs.

### How to abuse
If you find a COM object that you can access on behalf of a low-privileged user, for example, you can abuse it as follows:
1. Create an instance and call the methods of that COM object to, for example, write an arbitrary file on behalf of the system.  For example, you have found a COM object with a `DeployCmdShell()` method that runs on behalf of the `NT AUTHORITY\SYSTEM` account and you have `LaunchPermissions` and `AccessPermissions`. You can start this COM object, call the `DeployCmdShell()` method, and get code execution on behalf of the system. You can view the available methods using `ClsidExplorer`.
2. Abuse DCOM authentication. For this, see [RemoteKrbRelay](https://github.com/CICADA8-Research/RemoteKrbRelay/tree/main)

## ComDiver
### What is this
All information about COM objects is in the registry. But what if the registration was incorrect? In such a case we have a possibility to override COM settings, for example, to hijack the executable file. 

This tool allows you to detect such vulnerabilities, and it scans the registry according to the priority of keys that are viewed when searching for COM objects. In this way, you can even find Shadow COM Hijacking. The priority is as follows:
```shell
1. HKCU\Software\Classes\(GUID)\TreatAs 

2. HKLM\Software\Classes\(GUID)\TreatAs

3. HKCU\Software\Classes\(GUID)\InprocServer32

4. HKLM\Software\Classes\(GUID)\InprocServer32 

5. HKCU\Software\Classes\(GUID)\LocalServer32

6. HKLM\Software\Classes\(GUID)\LocalServer32
```

Thus at least two vectors of privilege escalation emerge:
1. If we have write permissions to `HKCU...TreatAs`, and the original COM executable is in `HKCU...LocalServer32`, then we can do Shadow COM Hijacking by writing our executable to `HKCU..TreatAs`.
2. If the COM object lies in `HKCU..LocalServer32` and we can write to `HKCU..LocalServer32`, then we can do COM Hijacking

Let's take a closer look at the tool:
```shell
PS A:\ssd\gitrepo\COMThanasia\ComDiver\x64\Debug> .\ComDiver.exe -h

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

----------- COM DIVER --------------
[?] Small tool to check insecure registry and disk permissions on com objects
[?] ARGS
        -h/--help <- show this message
        --from <CLSID> <- analyze CLSIDs from this clsid
        --target <CLSID> <- analyze one target clsid
        --no-context <- dont check another COM-server context. Only registry analyzing.
        --no-create <- dont create target COM object. This is the fastest mode
```
It accepts the following arguments:
- `--from` - there are a lot of CLSIDs on a Windows system. If you do not want the tool to look at all CLSIDs starting from the first, you can specify the CLSID to start with, for example, `--from {50FDBB99-5C92-495E-9E81-E2C2F48CDDA}`
- `--target` - analyze specific clsid;
- `--no-context` - do not check the name of the user on whose behalf the COM object is launched;
- `--no-create` - not to create a COM object that has been detected. This limits the information you can get about it. However, this is the fastest way to examine only the registry rights.

### Usage
Example:
```shell
.\ComDiver.exe --no-create
```
![изображение](https://github.com/user-attachments/assets/737534c3-27b2-41cf-9987-a94019aadb2a)

In this case we can see that there are no keys inside HKCU and we have write permissions to those keys. Accordingly, if we write our own value to this path, we will do COM Hijacking.

### How to abuse
If you see red in lines in the tool output, this is a potential way to abuse a COM object! You can perform COM Hijacking (spoofing an existing executable), or Shadow COM Hijacking (spoofing a missing executable). Read more about COM Hijacking [here](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/com-hijacking)

## MonikerHound
### What is this
There is a built-in way to bypass UAC on a Windows system, this is done through Elevation Moniker. You can read more about it [here](https://learn.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker). This kind of UAC Bypass requires a non-standard way of registering the COM object in the registry, which is fairly easy to trace. So you can use my tool to find new ways of UAC Bypass.

There are some examples:
- https://github.com/0xlane/BypassUAC
- https://github.com/Wh04m1001/IDiagnosticProfileUAC

### Usage
Example:
```shell
PS A:\ssd\gitrepo\COMThanasia\MonikerHound\x64\Debug> .\MonikerHound.exe


          ,_  _  _,
            \o-o/
           ,(.-.),
         _/ |) (| \_
           /\=-=/\
          ,| \=/ |,
        _/ \  |  / \_
            \_!_/

 MonikerHound - find your own UAC Bypass!

         CICADA8 Research Team
         From Michael Zhmaylo (MzHmO)

[+] Potential COM server for elevation moniker found!
Name: CEIPLuaElevationHelper
CLSID: {01D0A625-782D-4777-8D4E-547E6457FAD5}
LocalizedString: @%systemroot%\system32\werconcpl.dll,-351
Enabled: 1
IconReference: @%systemroot%\system32\werconcpl.dll,-6
Activate: Success
PID: 15800
DllHost.exe
[+]........................[+]
[+] Potential COM server for elevation moniker found!
Name: CTapiLuaLib Class
CLSID: {03e15b2e-cca6-451c-8fb0-1e2ee37a27dd}
LocalizedString: @%systemroot%\system32\tapiui.dll,-1
Enabled: 1
IconReference: @%systemroot%\system32\tapiui.dll,-201
Activate: Success
PID: 440
DllHost.exe
[+]........................[+]
```

### How to abuse
Once you have discovered potential candidates for UAC Bypass, you can start checking them out. As a great template for running Elevation Moniker, you can take [this function](https://github.com/CICADA8-Research/COMThanasia/blob/main/MonikerHound/MonikerHound/Source.cpp#L183), or this [program](https://github.com/0xlane/BypassUAC).


## ClsidExplorer
### What is this
ClsidExplorer allows you to retrieve information about a specific CLSID. The program outputs the following data:
- `AppID` - ApplicationID of a specific COM Object;
- `ProgID` - ProgID of a specific COM Object;
- `PID` - PID in which this COM Object is running;
- `Process Name` - the name of the PID process;
- `Username` - name of the user on whose behalf the process is running;
- `Methods` - available methods of the COM Object. Made by parsing TypeLib.

```shell
PS A:\ssd\gitrepo\COMThanasia\ClsidExplorer\x64\Debug> .\CLSIDExplorer.exe -h
CLSIDExplorer.exe - identify all info by clsid
Usage:
.\CLSIDExplorer.exe --clsid "{00000618-0000-0010-8000-00aa006d2ea4}"
```
The program accepts only one argument:
- `--clsid` - target CLSID to analyze

### Example
```shell
PS A:\ssd\gitrepo\COMThanasia\ClsidExplorer\x64\Debug> .\CLSIDExplorer.exe --clsid "{00000618-0000-0010-8000-00aa006d2ea4}"
[{00000618-0000-0010-8000-00aa006d2ea4}]
        AppID: Unknown
        ProgID: Unknown
        PID: 1572
        Process Name: CLSIDExplorer.exe
        Username: WINPC\\Michael
        Methods:
        [0] __stdcall void QueryInterface(IN GUID*, OUT void**)
        [1] __stdcall unsigned long AddRef()
        [2] __stdcall unsigned long Release()
        [3] __stdcall void GetTypeInfoCount(OUT unsigned int*)
        [4] __stdcall void GetTypeInfo(IN unsigned int, IN unsigned long, OUT void**)
        [5] __stdcall void GetIDsOfNames(IN GUID*, IN char**, IN unsigned int, IN unsigned long, OUT long*)
        [6] __stdcall void Invoke(IN long, IN GUID*, IN unsigned long, IN unsigned short, IN DISPPARAMS*, OUT VARIANT*, OUT EXCEPINFO*, OUT unsigned int*)
        [7] __stdcall BSTR Name()
        [8] __stdcall void Name(IN BSTR)
        [9] __stdcall RightsEnum GetPermissions(IN VARIANT, IN ObjectTypeEnum, IN VARIANT)
        [10] __stdcall void SetPermissions(IN VARIANT, IN ObjectTypeEnum, IN ActionEnum, IN RightsEnum, IN InheritTypeEnum, IN VARIANT)
        [11] __stdcall void ChangePassword(IN BSTR, IN BSTR)
        [12] __stdcall Groups* Groups()
        [13] __stdcall Properties* Properties()
        [14] __stdcall _Catalog* ParentCatalog()
        [15] __stdcall void ParentCatalog(IN _Catalog*)
        [16] __stdcall void ParentCatalog(IN _Catalog*)
[END]
```

### How to abuse
This program is great for checking a COM class discovered with `ComTraveller` or `PermissionHunter` or `MonikerHound` for interesting methods that can be abused.

## ComTraveller
### What is this
ComTraveller - this tool allows you to explore all available COM objects. First, it allows you to quickly identify COM objects with interesting values (RunAs Interactive User), availability of TypeLib, and Cross-Session Activation capabilities. Thus, you can quickly detect objects that may be instantiated in another user session, leading to privilege escalation.

```shell
PS A:\SSD\gitrepo\COMThanasia\ComTraveller\x64\Debug> .\ComTraveller.exe -h

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

ComTraveller - small tool to parse and extract information about all registered CLSIDs on the system
Usage:
--file <output> - output filename. Default: output.csv
--from <clsid> - start exploring clsids from this clsid. (for ex. default enum from 1 to 9. with --from 4 will be from 4 to 9)
--session <session> - use if you want to check Cross-Session Activation in a specific session. Useful only with 'Run as interactive user COM objects'
--target <CLSID> - analyze this CLSID
-h/--help - shows this screen
```
- `--file` - name of the file to which information about COM objects will be output;
- `--from` - there are a lot of CLSIDs on a Windows system. If you do not want the tool to look at all CLSIDs starting from the first, you can specify the CLSID to start with, for example, `--from {50FDBB99-5C92-495E-9E81-E2C2F48CDDA}`
- `--session` - try to instantiate an object in someone else's session
- `--target` - analyze only one target clsid

### Usage
Example:
```shell
.\ComTraveller.exe --file rep.csv --session 1
```

![изображение](https://github.com/user-attachments/assets/1779405d-8314-44e4-bad6-abce7c421238)

After that you will find a rep.csv file with information about COM objects. 
![изображение](https://github.com/user-attachments/assets/e6753aff-3ea0-4e48-add0-6e88ed451fc3)
There are several columns here:
- `CLSID` - CLSID of the COM object;
- `AppId` - APPID of the COM object;
- `ProgId` - APPID of COM object;
- `RunAs` - value in the RunAs registry. If value is `The Interactive User` or `NT AUTHORITY\SYSTEM`, you can try to make LPE;
- `Username` - name of the user on whose behalf the COM object is run;
- `PID` - the PID in which the COM object is running;
- `ProcessName` - name of the process in which the COM-object is running;
- `HasTypeLib` - whether the COM-object has TypeLib. If it does, you can give this object to `ClsidExplorer` to see the available methods;
- `canCrossSessionActivate` - whether it is possible to abuse this COM class for LPE through activation in someone else's session. If value is `+` or the error is `ACCESS DENIED`, this could be a potential candidate for LPE.

For example, if you apply filters, you will immediately find interesting COM classes :) Wow, is this a COM class that can be activated cross-sessionally and it works on behalf of the system? 
![изображение](https://github.com/user-attachments/assets/820411a0-7bf9-4972-9a02-d30562329149)
![изображение](https://github.com/user-attachments/assets/517d3215-28b7-4e14-8010-9ff8e6253ec4)

It should be noted that the program may crash due to the abundance of COM objects. In this case, you can restart it like this:
```shell
.\ComTraveller.exe --file rep.csv --session 1 --from "{0006F071-0000-0000-C000-000000000046}"
```
![изображение](https://github.com/user-attachments/assets/0db19ec0-98d6-40fe-9403-0bf846c82993)


