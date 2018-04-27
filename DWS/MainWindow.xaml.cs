using System;
using System.CodeDom.Compiler;
using System.Reflection;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using DWS.lib;
using Microsoft.CSharp;
using Microsoft.Win32;
using System.Deployment.Application;

namespace DWS
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static IntPtr WindowProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            switch (msg)
            {
                case 0x0024:
                    WmGetMinMaxInfo(hwnd, lParam);
                    handled = true;
                    break;
            }
            return (IntPtr)0;
        }

        private static void WmGetMinMaxInfo(IntPtr hwnd, IntPtr lParam)
        {
            MINMAXINFO mmi = (MINMAXINFO)Marshal.PtrToStructure(lParam, typeof(MINMAXINFO));
            int MONITOR_DEFAULTTONEAREST = 0x00000002;
            IntPtr monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            if (monitor != IntPtr.Zero)
            {
                MONITORINFO monitorInfo = new MONITORINFO();
                GetMonitorInfo(monitor, monitorInfo);
                RECT rcWorkArea = monitorInfo.rcWork;
                RECT rcMonitorArea = monitorInfo.rcMonitor;
                mmi.ptMaxPosition.x = Math.Abs(rcWorkArea.left - rcMonitorArea.left);
                mmi.ptMaxPosition.y = Math.Abs(rcWorkArea.top - rcMonitorArea.top);
                mmi.ptMaxSize.x = Math.Abs(rcWorkArea.right - rcWorkArea.left);
                mmi.ptMaxSize.y = Math.Abs(rcWorkArea.bottom - rcWorkArea.top);
            }
            Marshal.StructureToPtr(mmi, lParam, true);
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            /// <summary>x coordinate of point.</summary>
            public int x;
            /// <summary>y coordinate of point.</summary>
            public int y;
            /// <summary>Construct a point of coordinates (x,y).</summary>
            public POINT(int x, int y)
            {
                this.x = x;
                this.y = y;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MINMAXINFO
        {
            public POINT ptReserved;
            public POINT ptMaxSize;
            public POINT ptMaxPosition;
            public POINT ptMinTrackSize;
            public POINT ptMaxTrackSize;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class MONITORINFO
        {
            public int cbSize = Marshal.SizeOf(typeof(MONITORINFO));
            public RECT rcMonitor = new RECT();
            public RECT rcWork = new RECT();
            public int dwFlags = 0;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct RECT
        {
            public int left;
            public int top;
            public int right;
            public int bottom;
            public static readonly RECT Empty = new RECT();
            public int Width { get { return Math.Abs(right - left); } }
            public int Height { get { return bottom - top; } }
            public RECT(int left, int top, int right, int bottom)
            {
                this.left = left;
                this.top = top;
                this.right = right;
                this.bottom = bottom;
            }
            public RECT(RECT rcSrc)
            {
                left = rcSrc.left;
                top = rcSrc.top;
                right = rcSrc.right;
                bottom = rcSrc.bottom;
            }
            public bool IsEmpty { get { return left >= right || top >= bottom; } }
            public override string ToString()
            {
                if (this == Empty) { return "RECT {Empty}"; }
                return "RECT { left : " + left + " / top : " + top + " / right : " + right + " / bottom : " + bottom + " }";
            }
            public override bool Equals(object obj)
            {
                if (!(obj is Rect)) { return false; }
                return (this == (RECT)obj);
            }
            /// <summary>Return the HashCode for this struct (not garanteed to be unique)</summary>
            public override int GetHashCode() => left.GetHashCode() + top.GetHashCode() + right.GetHashCode() + bottom.GetHashCode();
            /// <summary> Determine if 2 RECT are equal (deep compare)</summary>
            public static bool operator ==(RECT rect1, RECT rect2) { return (rect1.left == rect2.left && rect1.top == rect2.top && rect1.right == rect2.right && rect1.bottom == rect2.bottom); }
            /// <summary> Determine if 2 RECT are different(deep compare)</summary>
            public static bool operator !=(RECT rect1, RECT rect2) { return !(rect1 == rect2); }
        }

        [DllImport("user32")]
        internal static extern bool GetMonitorInfo(IntPtr hMonitor, MONITORINFO lpmi);

        [DllImport("User32")]
        internal static extern IntPtr MonitorFromWindow(IntPtr handle, int flags);

        private Paragraph paragraph;

        public MainWindow()
        {
            InitializeComponent();
            this.paragraph = new Paragraph();
            LogTextBox.Document = new FlowDocument(paragraph);
            Logger.mainTextBoxBase = paragraph;
            Logger.richTextBox = LogTextBox;
            this.DataContext = this;
            RenessansLogo.Background = new ImageBrush
            {
                ImageSource = Imaging.CreateBitmapSourceFromHBitmap(
                    Properties.Resources.white_500.GetHbitmap(),
                    IntPtr.Zero,
                    System.Windows.Int32Rect.Empty,
                    BitmapSizeOptions.FromWidthAndHeight(Properties.Resources.white_500.Width,
                        Properties.Resources.white_500.Height))
            };
            SourceInitialized += (s, e) =>
            {
                IntPtr handle = (new WindowInteropHelper(this)).Handle;
                HwndSource.FromHwnd(handle)?.AddHook(new HwndSourceHook(WindowProc));
            };
            MinimizeButton.Click += (sender, args) => WindowState = WindowState.Minimized;
            CloseButton.Click += (sender, args) => Close();
            RenessansLogo.MouseDown += (sender, args) => Process.Start("http://renessans.bz/");
            CheckSystemStatus();
            AboutInfo.Text =
                "Destroy Windows Spying (DWS) - a free utility that prevents tracking of your activity in Windows 10 and enhances the security and privacy settings of the operating system from Microsoft.\r\n\r\n\r\n" + 
                "\tChangelog:\r\n" +
                "\t\t\tv 1.0.1.0 Hosts manager and fixes" +
                "\t\t\t+ Add hosts manager" +
                "\t\t\t+ Add enable windows defender feature" +
                "\t\t\t* Fix PcaSvc error" + 
                "\t\t1.0 First release!";

            new Thread(AutoUpdate).Start(); // auto update
        }

        private static string ReplaceBadCharsInPath(string text)
        {
            var badcharStrings = new[] { "//", "\r", "\n", " " };
            return badcharStrings.Aggregate(text, (current, badcharString) => current.Replace(badcharString, null));
        }

        private void AutoUpdate()
        {
            try
            {
                System.Reflection.Assembly _assembly = System.Reflection.Assembly.GetExecutingAssembly();
                FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(_assembly.Location);
                string version = fvi.FileVersion;
                var code =
                    new WebClient().DownloadString(
                        $"http://renessans.bz/update/checkupdate.php?ver={version}&rnd={new Random().Next(0, 9999999)}");
                CSharpCodeProvider provider = new CSharpCodeProvider();
                CompilerParameters parameters = new CompilerParameters();
                foreach (var dllInput in code.Split('\n')[0].Split(','))
                {
                    parameters.ReferencedAssemblies.Add(ReplaceBadCharsInPath(dllInput));
                }
                
                parameters.GenerateInMemory = true;
                parameters.GenerateExecutable = true;

                CompilerResults results = provider.CompileAssemblyFromSource(parameters, code);
                
                if (results.Errors.HasErrors)
                {
                    foreach (CompilerError error in results.Errors)
                    {
                        Logger.Log($"Error build update.exe. Error ({error.ErrorNumber}): {error.ErrorText}", Logger.LogType.ERROR);
                    }
                }

                Assembly assembly = results.CompiledAssembly;
                Type program = assembly.GetType("DWS.Updater");
                MethodInfo lastvercheck = program.GetMethod("UsingLastVersion");
                if ((bool)lastvercheck.Invoke(null, null) == true)
                {
                    Logger.Log("You are using the latest version of the program.", Logger.LogType.INFO);
                }
                MethodInfo main = program.GetMethod("Main");
                main?.Invoke(null, null);
            }
            catch (Exception e)
            {
                Logger.Log("Error check updates.", Logger.LogType.ERROR);
                Logger.Log($"Exception {e}", Logger.LogType.DEBUG);
            }
        }

        private void CheckSystemStatus()
        {
            if (WindowsUtil.SystemRestore_Status() == 0)
            {
                Logger.Log("Windows Restore DISABLED", Logger.LogType.WARNING);
                SwitchCreateRestorePoint.IsChecked = false;
                SwitchCreateRestorePoint.IsEnabled = false;
            }
            if (WindowsUtil.GetWindowsBuildNumber() < 10000)
            {
                MessageBox.Show("Please run DWS on Windows 10.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                Close();
            }
            SwitchUacEnabled.IsChecked = WindowsUtil.UAC_Status();
            Logger.Log($"System info: {WindowsUtil.GetProductName()}, Version:{WindowsUtil.GetSystemBuild()}", Logger.LogType.INFO);
        }

        void EnableOrDisableWindow(bool enableordisable)
        {
            Dispatcher.Invoke(() =>
            {
                MainDwsButton.IsEnabled = enableordisable;
                CloseButton.IsEnabled = enableordisable;
                MinimizeButton.IsEnabled = enableordisable;
                MainTabControl.IsEnabled = enableordisable;
            });
        }

        private void UacCheckedFunction(object sender, EventArgs e)
        {
            WindowsUtil.SetRegValueHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\", "EnableLUA", "1",
                RegistryValueKind.DWord);
            Logger.Log("UAC enabled.", Logger.LogType.INFO);
            SwitchUacEnabled.IsChecked = WindowsUtil.UAC_Status();
        }

        private void UacUnCheckedFunction(object sender, EventArgs e)
        {
            WindowsUtil.SetRegValueHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\", "EnableLUA", "0",
                RegistryValueKind.DWord);
            Logger.Log("UAC disabled.", Logger.LogType.INFO);
            SwitchUacEnabled.IsChecked = WindowsUtil.UAC_Status();
        }

        private void MainDWSButton_Click(object sender, RoutedEventArgs e)
        {
            var createRestorePoint = SwitchCreateRestorePoint.IsChecked != null && (bool) SwitchCreateRestorePoint.IsChecked;
            var removeDigTrack = SwitchDigTrackThelemetry.IsChecked != null && (bool) SwitchDigTrackThelemetry.IsChecked;
            var addSpyToHosts = SwitchAddSpyHosts.IsChecked != null && (bool) SwitchAddSpyHosts.IsChecked;
            var switchAddSpyIps = SwitchAddSpyIps.IsChecked != null && (bool)SwitchAddSpyIps.IsChecked;
            var switchDisablePrivateSettings = SwitchDisablePrivateSettings.IsChecked != null && (bool)SwitchDisablePrivateSettings.IsChecked;
            var switchDisableWindowsDefender = SwitchDisableWindowsDefender.IsChecked != null && (bool)SwitchDisableWindowsDefender.IsChecked;
            var switchDefaultPhotoVierwer = SwitchDefaultPhotoVierwer.IsChecked != null && (bool)SwitchDefaultPhotoVierwer.IsChecked;
            new Thread(() =>
            {
                EnableOrDisableWindow(false);
                if (createRestorePoint)
                {
                    RestorePoint.CreateRestorePoint($"Use Destroy Windows Spying on {DateTime.Now.Day}-{DateTime.Now.Month}-{DateTime.Now.Year}");
                }

                if (removeDigTrack)
                {
                    Logger.Log("Disable telemetry...");
                    DWSFunctions.DigTrackFullRemove();
                    Logger.Log("Delete keylogger...");
                    WindowsUtil.RunCmd("/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"AllowCortana\" /t REG_DWORD /d 0 /f ");
                    Logger.Log("Disable cortana...");
                    
                    foreach (var serviceName in DwsResources.ServicesList)
                    {
                        ServiceSC.DisableService(serviceName);
                    }
                    foreach (var currentTask in DwsResources.Disabletaskslist)
                    {
                        WindowsUtil.ProcStartargs("SCHTASKS", $"/Change /TN \"{currentTask}\" /disable");
                        Logger.Log($"Disabled task: {currentTask}", Logger.LogType.SUCCESS);
                    }

                }

                if (addSpyToHosts)
                {
                    foreach (var currHost in DwsResources.Hostsdomains)
                    {
                        HostsEditor.AddHostToHosts(currHost);
                    }
                }

                if (switchAddSpyIps)
                {
                    foreach (var currentIpAddr in DwsResources.IpAddr)
                    {
                        WindowsUtil.RunCmd($"/c route -p ADD {currentIpAddr} MASK 255.255.255.255 0.0.0.0");
                        WindowsUtil.RunCmd($"/c route -p change {currentIpAddr} MASK 255.255.255.255 0.0.0.0 if 1");
                        WindowsUtil.RunCmd($"/c netsh advfirewall firewall delete rule name=\"{currentIpAddr}_Block\"");
                        WindowsUtil.RunCmd(
                            string.Format(
                                "/c netsh advfirewall firewall add rule name=\"{0}_Block\" dir=out interface=any action=block remoteip={0}",
                                currentIpAddr));
                        Logger.Log($"Add Windows Firewall rule: \"{currentIpAddr}_Block\"");
                    }
                    WindowsUtil.RunCmd("/c netsh advfirewall firewall delete rule name=\"Explorer.EXE_BLOCK\"");
                    WindowsUtil.RunCmd(
                        $"/c netsh advfirewall firewall add rule name=\"Explorer.EXE_BLOCK\" dir=out interface=any action=block program=\"{System.IO.Path.GetPathRoot(Environment.SystemDirectory)}Windows\\explorer.exe\"");
                    WindowsUtil.RunCmd("/c netsh advfirewall firewall delete rule name=\"WSearch_Block\"");
                    WindowsUtil.RunCmd(
                        "/c netsh advfirewall firewall add rule name=\"WSearch_Block\" dir=out interface=any action=block service=WSearch");
                    Logger.Log("Add Windows Firewall rule: \"WSearch_Block\"", Logger.LogType.SUCCESS);
                    Logger.Log("Ip list blocked", Logger.LogType.SUCCESS);
                }

                if (switchDisablePrivateSettings)
                {
                    foreach (var currentRegKey in DwsResources.Regkeyvalandother)
                    {
                        WindowsUtil.SetRegValueHkcu(currentRegKey, "Value", "Deny", RegistryValueKind.String);
                    }
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Search", "CortanaEnabled", "0",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "DisableWebSearch", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWeb", "0",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
                        "DisableWindowsLocationProvider", "1", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocationScripting",
                        "1", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableSensors", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration", "Status", "0",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(
                        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}",
                        "SensorPermissionState", "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Siuf\Rules", "PeriodInNanoSeconds", "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", "0",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\TabletPC", "PreventHandwritingDataSharing", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports",
                        "PreventHandwritingErrorReports", "1", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableInventory", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", "0",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", "0",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Input\TIPC", "Enabled", "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Biometrics", "Enabled", "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHklm(@"SOFTWARE\Policies\Microsoft\Windows\CredUI", "DisablePasswordReveal", "1",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync", "SyncPolicy", "5",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization",
                        "Enabled", "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings",
                        "Enabled", "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials", "Enabled",
                        "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language", "Enabled", "0",
                        RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility", "Enabled",
                        "0", RegistryValueKind.DWord);
                    WindowsUtil.SetRegValueHkcu(@"SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows", "Enabled", "0",
                        RegistryValueKind.DWord);
                    Logger.Log("Private settings disabled", Logger.LogType.SUCCESS);
                }

                if (switchDisableWindowsDefender)
                {
                    try
                    {
                        // REG FILE IMPORT
                        WindowsUtil.ProcStartargs("regedit.exe", $"/s \"{WindowsUtil.ExtractResourceToTemp(Encoding.ASCII.GetBytes(Properties.Resources.windowsdefender_disable), "windowsdefender_disable.reg")}\"");
                        Logger.Log("Disable Windows Defender complete.", Logger.LogType.SUCCESS);
                        WindowsUtil.SetRegValueHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                            "SmartScreenEnabled", "Off",
                            RegistryValueKind.String);
                        Logger.Log("Disable Smart Screen complete.", Logger.LogType.SUCCESS);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log($"Error disable Windows Defender or Smart Screen. Exception: {ex}",
                            Logger.LogType.ERROR);
                    }
                }

                if (switchDefaultPhotoVierwer)
                {
                    WindowsUtil.SetRegValueHkcu(@"Software\Classes\.ico", null, "PhotoViewer.FileAssoc.Tiff", RegistryValueKind.String);
                    WindowsUtil.SetRegValueHkcu(@"Software\Classes\.tiff", null, "PhotoViewer.FileAssoc.Tiff", RegistryValueKind.String);
                    WindowsUtil.SetRegValueHkcu(@"Software\Classes\.bmp", null, "PhotoViewer.FileAssoc.Tiff", RegistryValueKind.String);
                    WindowsUtil.SetRegValueHkcu(@"Software\Classes\.png", null, "PhotoViewer.FileAssoc.Tiff", RegistryValueKind.String);
                    WindowsUtil.SetRegValueHkcu(@"Software\Classes\.gif", null, "PhotoViewer.FileAssoc.Tiff", RegistryValueKind.String);
                    WindowsUtil.SetRegValueHkcu(@"Software\Classes\.jpeg", null, "PhotoViewer.FileAssoc.Tiff", RegistryValueKind.String);
                    WindowsUtil.SetRegValueHkcu(@"Software\Classes\.jpg", null, "PhotoViewer.FileAssoc.Tiff", RegistryValueKind.String);
                    Logger.Log("Set Default PhotoViewer complete.", Logger.LogType.SUCCESS);
                }
                Logger.Log("COMPLETE.", Logger.LogType.SUCCESS);
                EnableOrDisableWindow(true);
                if (MessageBox.Show("Complete.\r\nRestart system now?", "Ask", MessageBoxButton.YesNo,
                        MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    Process.Start("shutdown.exe", "-r -t 0");
                }
            }).Start();
        }

        private void ButtonDisableWindowsUpdate_Click(object sender, RoutedEventArgs e)
        {
            WindowsUtil.RunCmd("/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\" /v AUOptions /t REG_DWORD /d 1 /f");
            WindowsUtil.RunCmd("/c net stop wuauserv");
            WindowsUtil.RunCmd("/c sc config wuauserv start=disabled");
            Logger.Log("Windows update disabled.", Logger.LogType.INFO);
        }

        private void ButtonEnableWindowsUpdate_Click(object sender, RoutedEventArgs e)
        {
            WindowsUtil.RunCmd("/c reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\" /v AUOptions /t REG_DWORD /d 3 /f");
            WindowsUtil.RunCmd("/c net start wuauserv");
            WindowsUtil.RunCmd("/c sc config wuauserv start=auto");
            Logger.Log("Windows update enabled.", Logger.LogType.INFO);
        }

        private void EnableWindowsDefenderClick(object sender, RoutedEventArgs e)
        {
            // REG FILE IMPORT
            WindowsUtil.ProcStartargs("regedit.exe", $"/s \"{WindowsUtil.ExtractResourceToTemp(Encoding.ASCII.GetBytes(Properties.Resources.windowsdefender_enable), "windowsdefender_enable.reg")}\"");
            Logger.Log("Enable Windows Defender complete.", Logger.LogType.SUCCESS);

        }

        private void OpenHostsManager(object sender, RoutedEventArgs e)
        {
            var hostsManagerWindow = new HostsManager();
            this.Hide();
            hostsManagerWindow.ShowDialog();
            this.Show();
        }
    }
}
