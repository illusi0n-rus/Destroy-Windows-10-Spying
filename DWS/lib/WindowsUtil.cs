using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;
using DWS.Properties;
using Microsoft.Win32;

namespace DWS.lib
{
    public static class WindowsUtil
    {
        public static void DeleteFile(string filepath)
        {
            RunCmd($"/c del /F /Q \"{filepath}\"");
        }

        public static object ReadSubKeyValue(string subKey, string keyName)
        {
            var rkSubKey = Registry.LocalMachine.OpenSubKey(subKey);
            if (rkSubKey == null)
            {
                Logger.Log($@"Error while reading registry key: {subKey}\{keyName} does not exist!", Logger.LogType.ERROR);
                return null;
            }
            try
            {
                var result = rkSubKey.GetValue(keyName);
                rkSubKey.Close();
                return result;

            }
            catch (Exception ex)   //This exception is thrown
            {
                Logger.Log(
                    $@"Error while reading registry key: {subKey} param: {keyName}. ErrorMessage: {ex.Message}", Logger.LogType.ERROR);
                rkSubKey.Close();
                return null;
            }
        }

        public static void SetRegValueHkcu(string regkeyfolder, string paramname, string paramvalue, RegistryValueKind keytype)
        {
            var registryKey = Registry.CurrentUser.CreateSubKey(regkeyfolder);
            registryKey?.Close();
            var myKey = Registry.CurrentUser.OpenSubKey(regkeyfolder, RegistryKeyPermissionCheck.ReadWriteSubTree,
                RegistryRights.FullControl);
            try
            {
                myKey?.SetValue(paramname, paramvalue, keytype);
            }
            catch (Exception ex)
            {
                Logger.Log($"Error set key value on HKCU. Exception message: {ex.Message}", Logger.LogType.ERROR);
            }

            myKey?.Close();
        }

        public static void SetRegValueHklm(string regkeyfolder, string paramname, string paramvalue, RegistryValueKind keytype)
        {
            var registryKey = Registry.LocalMachine.CreateSubKey(regkeyfolder);
            registryKey?.Close();
            var myKey = Registry.LocalMachine.OpenSubKey(regkeyfolder,
                RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.FullControl);
            try
            {
                myKey?.SetValue(paramname, paramvalue, keytype);
            }
            catch (Exception ex)
            {
                Logger.Log($"Error set key value on HKLM. Exception message: {ex.Message}", Logger.LogType.ERROR);
            }
            myKey?.Close();
        }

        public static int GetWindowsBuildNumber()
        {
            return Convert.ToInt32(ReadSubKeyValue(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber"));
        }
        public static bool UAC_Status()
        {
            return Convert.ToBoolean(ReadSubKeyValue(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"));
        }
        public static int SystemRestore_Status()
        {
            return Convert.ToInt32(ReadSubKeyValue(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore", "RPSessionInterval"));
        }
        public static string GetProductName()
        {
            return Convert.ToString(ReadSubKeyValue(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName"));
        }
        public static string GetSystemBuild()
        {
            return Convert.ToString(ReadSubKeyValue(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "BuildLabEx"));
        }

        public static string ExtractResourceToTemp(byte[] bytesFile, string filename)
        {
            var filePath = Path.Combine(Path.GetTempPath(), filename);
            File.Create(filePath).Close();
            File.WriteAllBytes(filePath, bytesFile);
            Logger.Log($"Created temp file complete. Path: {filePath}", Logger.LogType.DEBUG);
            return filePath;
        }

        public static void RunCmd(string args)
        {
            ProcStartargs(Paths.ShellCmdLocation, args);
        }

        public static void ProcStartargs(string name, string args)
        {
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = name,
                        Arguments = args,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = Encoding.GetEncoding(866)
                    }
                };
                proc.Start();
                string line = null;
                while (!proc.StandardOutput.EndOfStream)
                {
                    line += Environment.NewLine + proc.StandardOutput.ReadLine();
                }
                proc.WaitForExit();
                Logger.Log($"Start: {name} {args}{Environment.NewLine}Output: {line}", Logger.LogType.DEBUG);
            }
            catch (Exception ex)
            {
                Logger.Log($"Error start prog {name} {args}. Exception: {ex}", Logger.LogType.ERROR);
            }
        }
    }
}
