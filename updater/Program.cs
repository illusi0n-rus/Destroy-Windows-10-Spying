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
            File.Delete(args[0]);
            new WebClient().DownloadFile($"http://download.renessans.bz/{args[1]}", args[0]);
            Process.Start(args[1]);
            Process.GetCurrentProcess().Kill();
        }
    }
}
