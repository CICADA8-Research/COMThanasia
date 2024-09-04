# COMThanasia

## TL;DR
With this tool, you will be able to detect:
- Incorrect access control to a COM object (LaunchPermission , AccessPermission) - LPE through abusable COM methods, DCOM Authentication relaying. That's `PermissionHunter`.
- Incorrect registry rights to a COM object - LPE through COM Hijacking. That's `ComDiver`.
- Find new Elevation Moniker - UAC Bypass. That's `MonikerHound`.
- Get detailed information about a specific CLSID - Inspect COM object to find abusable COM Methods. That's `ClsidExplorer`.
- Check Cross-Session Activation on behalf of a low-privileged user - Attempting to instantiate an object in someone else's session for LPE. That's `ComTraveller`.

If we had published this tool a couple months ago (e.g. Spring 2024), you would have discovered CVE-2024-38100 (FakePotato) and CVE-2024-38061 (SilverPotato).

Start using this tool and you can find more ways to elevate privilege on Windows systems :)

![изображение](https://github.com/user-attachments/assets/57dc0eaa-4fbf-47e7-a65a-e7d0ef5960d5)
