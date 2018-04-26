using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace DWS.lib
{
    public static class RestorePoint
    {
        public static bool CreateRestorePoint(string description)
        {
            try
            {
                Logger.Log($"Creating restore point {description}...", Logger.LogType.INFO);
                var mScope = new ManagementScope("\\\\localhost\\root\\default");
                var mPath = new ManagementPath("SystemRestore");
                var options = new ObjectGetOptions();
                using (var mClass = new ManagementClass(mScope, mPath, options))
                using (var parameters = mClass.GetMethodParameters("CreateRestorePoint"))
                {
                    parameters["Description"] = description;
                    parameters["EventType"] = 0x66;
                    parameters["RestorePointType"] = 0xc;
                    mClass.InvokeMethod("CreateRestorePoint", parameters, null);
                }
                Logger.Log($"Created restore point {description}...", Logger.LogType.SUCCESS);
                return true;
            }
            catch (Exception e)
            {
                Logger.Log($"Restore point create falied. Exception: {e.ToString()}", Logger.LogType.ERROR);
                return false;
            }
        }
    }
}
