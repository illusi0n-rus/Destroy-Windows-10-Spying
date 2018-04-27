using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DWS.lib
{
    public static class HostsEditor
    {
        private static readonly string Hostslocation = Paths.System32Location + @"drivers\etc\hosts";
        public static void AddHostToHosts(string hostname)
        {
            try
            {
                if(!File.Exists(Hostslocation))
                    File.Create(Hostslocation).Close();
                if (!HostExitsInHostsFile(hostname))
                {
                    File.AppendAllText(Hostslocation, $"\r\n0.0.0.0 {hostname}");
                    Logger.Log($"Host {hostname} successfully added to hosts file.", Logger.LogType.SUCCESS);
                    WindowsUtil.RunCmd("/c ipconfig /flushdns");
                }
                else
                {
                    Logger.Log($"Hostname {hostname} exists in hosts", Logger.LogType.WARNING);
                }
            }
            catch (Exception e)
            {
                Logger.Log($"Error add host {hostname} to hosts file {Hostslocation}. Exception: {e}", Logger.LogType.ERROR);
            }
        }

        public static bool HostExitsInHostsFile(string hostname)
        {
            return File.ReadAllLines(Hostslocation).Any(line => line.EndsWith($" {hostname}"));
        }
    }
}
