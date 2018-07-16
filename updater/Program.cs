using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace updater
{
    class Program
    {
        static void Main(string[] args)
        {
            File.Delete("DWS.exe");
            new WebClient().DownloadFile($"http://download.renessans.bz/DWS.exe", "DWS.exe");
            Process.Start("DWS.exe");
            Process.GetCurrentProcess().Kill();
        }
    }
}
