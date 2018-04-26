using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DWS.lib
{
    public static class DWSFunctions
    {
        public static void DigTrackFullRemove()
        {
            ServiceSC.DisableService("DiagTrack");
            ServiceSC.DisableService("diagnosticshub.standardcollector.service");
            ServiceSC.DisableService("dmwappushservice");
            ServiceSC.DisableService("WMPNetworkSvc");
            WindowsUtil.RunCmd(
                "/c REG ADD HKLM\\SYSTEM\\ControlSet001\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener /v Start /t REG_DWORD /d 0 /f");
            ServiceSC.DeleteService("dmwappushsvc");
            ServiceSC.DeleteService("\"Diagnostics Tracking Service\"");
            ServiceSC.DeleteService("diagtrack");
            WindowsUtil.RunCmd("/c reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\"  /v \"{60E6D465-398E-4850-BE86-7EF7620A2377}\" /t REG_SZ /d  \"v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\\windows\\system32\\svchost.exe|Svc=DiagTrack|Name=Windows  Telemetry|\" /f");
            WindowsUtil.RunCmd("/c reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\"  /v \"{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}\" /t REG_SZ /d  \"v2.24|Action=Block|Active=TRUE|Dir=Out|App=C:\\windows\\systemapps\\microsoft.windows.cortana_cw5n1h2txyewy\\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|\"  /f");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Device Metadata\" /v \"PreventDeviceMetadataFromNetwork\" /t REG_DWORD /d 1 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d 0 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MRT\" /v \"DontOfferThroughWUAU\" /t REG_DWORD /d 1 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows\" /v \"CEIPEnable\" /t REG_DWORD /d 0 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v \"AITEnable\" /t REG_DWORD /d 0 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v \"DisableUAR\" /t REG_DWORD /d 1 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d 0 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener\" /v \"Start\" /t REG_DWORD /d 0 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\SQMLogger\" /v \"Start\" /t REG_DWORD /d 0 /f ");
            WindowsUtil.RunCmd(
                "/c reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Siuf\\Rules\" /v \"NumberOfSIUFInPeriod\" /t REG_DWORD /d 0 /f ");
            WindowsUtil.RunCmd(
                "/c reg delete \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Siuf\\Rules\" /v \"PeriodInNanoSeconds\" /f ");
        }
    }
}
