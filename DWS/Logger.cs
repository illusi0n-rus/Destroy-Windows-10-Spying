using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

namespace DWS
{
    public sealed class Logger
    {
        private static volatile Logger instance;
        public static Paragraph mainTextBoxBase;
        public static RichTextBox richTextBox;
        private Logger() { }

        public static Logger Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (mainTextBoxBase)
                    {
                        if (instance == null)
                            instance = new Logger();
                    }
                }

                return instance;
            }
        }

        public enum LogType { INFO, SUCCESS, WARNING, ERROR, DEBUG };

        public static void Log(string Text, LogType type = LogType.INFO)
        {
            string logTypeText = null;
            SolidColorBrush logTextColor = null;
            switch (type)
            {
                case LogType.INFO:
                    logTypeText = "INFO";
                    logTextColor = Brushes.DeepSkyBlue;
                    break;
                case LogType.SUCCESS:
                    logTypeText = "SUCCESS";
                    logTextColor = Brushes.Green;
                    break;
                case LogType.WARNING:
                    logTypeText = "WARNING";
                    logTextColor = Brushes.Coral;
                    break;
                case LogType.ERROR:
                    logTypeText = "ERROR";
                    logTextColor = Brushes.Red;
                    break;
                case LogType.DEBUG:
#if !DEBUG
                    return;
#endif
                    logTypeText = "DEBUG";
                    logTextColor = Brushes.Gray;
                    break;
                default:
                    break;
            }
            mainTextBoxBase.Dispatcher.Invoke(() =>
            {
                mainTextBoxBase.Inlines.Add(new Run("[" + logTypeText + "] ")
                {
                    Foreground = logTextColor
                });
                mainTextBoxBase.Inlines.Add(Text);
                mainTextBoxBase.Inlines.Add(new LineBreak());
            });
            richTextBox.Dispatcher.Invoke(() => richTextBox.ScrollToEnd());
        }
    }
}
