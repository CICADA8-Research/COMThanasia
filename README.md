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
Small tool that allow you to find vulnerable COM objects with incorrect LaunchPermission and ActivatePermission

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
1. Create an instance and call the methods of that COM object to, for example, write an arbitrary file on behalf of the system.  For example, you have found a COM object with a `DeployCmdShell()` method that runs on behalf of the `NT AUTHORITY\SYSTEM` account and you have `LaunchPermissions` and `AccessPermissions`. You can start this COM object, call the `DeployCmdShell()` method, and get code execution on behalf of the system.
2. Abuse DCOM authentication. For this, see [RemoteKrbRelay](https://github.com/CICADA8-Research/RemoteKrbRelay/tree/main)
