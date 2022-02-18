using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Threading;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using LibraryForTOTP;
using Library;
using System.Diagnostics;

namespace WpfApp1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private List<TOTPs> ts = new();
        private DispatcherTimer timer = new DispatcherTimer();
        private long counter = 0;
        public MainWindow()
        {
            InitializeComponent();
            Reload();
            timer.Interval = new TimeSpan(0, 0, 0,0,100);
            timer.Tick += (e,s) => { TimedEvent(); };
            timer.Start();
        }
        private void TimedEvent()
        {
            long nowcounter = RFC6238andRFC4226.GenCounter();
            if (counter != nowcounter)
            {
                Reload();
                counter = nowcounter;
            }
            TimerText.Text = String.Format("TOTP(s) will be regenerated in {0:00}  seconds", 30 - DateTime.Now.Second % 30);
        }
        private List<string[]> ExportTOTPDatas()
        {
            List<string[]> vs = new();
            if (ts != null)
            {
                foreach (var t in ts)
                {
                    vs.Add(new string[]
                    {
                    t.Name+String.Empty,t.KeyValue+String.Empty,
                    });
                }
            }
            return vs;
        }
        public void AddList(string[] newkey)
        {
            try
            {
                ts.Add(new TOTPs()
                {
                    Name = newkey[0],
                    KeyValue = newkey[1],
                    TOTP = String.Format("{0:000000}", RFC6238andRFC4226.GenTOTP(RFC4648Base32.FromBase32String(newkey[1]))),
                    DeleteCheck = false,
                });
            }
            catch
            {
                ts.Add(new TOTPs()
                {
                    Name = newkey[0],
                    KeyValue = newkey[1],
                    TOTP = String.Format("error"),
                    DeleteCheck = false,
                });
            }
            totps.ItemsSource = ts;
            string savelog = SaveandImport.ExportKey(ExportTOTPDatas());
            if (savelog != "success")
            {
                MessageBox.Show("Failed to save your key. Try again manually.", "error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void Reload()
        {
            ts = new();
            var tmp = SaveandImport.ImportKey();
            foreach (string[] key in tmp)
            {
                try
                {
                    ts.Add(new TOTPs()
                    {
                        Name = key[0],
                        KeyValue = key[1],
                        TOTP = String.Format("{0:000000}", RFC6238andRFC4226.GenTOTP(RFC4648Base32.FromBase32String(key[1]))),
                        DeleteCheck = false,
                    });
                }
                catch
                {
                    ts.Add(new TOTPs()
                    {
                        Name = key[0],
                        KeyValue = key[1],
                        TOTP = String.Format("error"),
                        DeleteCheck = false,
                    });
                }
            }
            tmp.Clear();
            totps.ItemsSource = ts;
        }

        private void Button_Click_Save_manual(object sender, RoutedEventArgs e)
        {

            string savelog = SaveandImport.ExportKey(ExportTOTPDatas());
            if (savelog != "success")
            {
                MessageBox.Show("Failed to save your key. Try again later.", "error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Button_Click_DelChecked(object sender, RoutedEventArgs e)
        {
            ts = ts.Where(x => x.DeleteCheck==false).ToList();
            totps.ItemsSource = ts;

            string savelog = SaveandImport.ExportKey(ExportTOTPDatas());
            if (savelog != "success")
            {
                MessageBox.Show("Failed to save your key. Try again manually.", "error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        private void Button_Click_Addkey(object sender, RoutedEventArgs e)
        {
            if (newkeyvalue.Text!=""&Regex.IsMatch(newkeyvalue.Text, "^([A-Za-z2-7]{8})*(([A-Za-z2-7]{8})|([A-Za-z2-7]{7}={1})|([A-Za-z2-7]{6}={2})|([A-Za-z2-7]{5}={3})|([A-Za-z2-7]{4}={4})|([A-Za-z2-7]{3}={5})|([A-Za-z2-7]{2}={6})|([A-Za-z2-7]{1}={7})){1}(={8})*$")) {
                AddList(new string[] { newkeyname.Text + String.Empty, newkeyvalue.Text + String.Empty });
                Reload();
                newkeyname.Text = String.Empty;
                newkeyvalue.Text = String.Empty;
            }
            else
            {
                MessageBox.Show("You have to input valid key","Don't spam click",MessageBoxButton.OK,MessageBoxImage.Warning);
            }
        }
        private void Button_Click_GenNewKey(object sender, RoutedEventArgs e)
        {
            byte[] bytes = new byte[10];
            RandomNumberGenerator.Fill(bytes);
            newkeyvalue.Text = RFC4648Base32.ToBase32String(bytes);
        }
        private void Button_Click_delall(object sender, RoutedEventArgs e)
        {
            if(MessageBox.Show("Are you sure you want to delete all keys?", "delete all key", MessageBoxButton.YesNo, MessageBoxImage.Exclamation) == MessageBoxResult.Yes)
            {
                ts = new List<TOTPs>();
                totps.ItemsSource=ts;

            }

            string savelog = SaveandImport.ExportKey(ExportTOTPDatas());
            if (savelog != "success")
            {
                MessageBox.Show("Failed to save your key. Try again manually.", "error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void Open_License_Page(object sender,RoutedEventArgs e)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo() {
                FileName = "https://www.npca.jp/about/agreements",
                UseShellExecute = true
            };

            Process.Start(processStartInfo);
        }
    }
    public class TOTPs
    {
        public string? Name { get; set; }
        public string? KeyValue { get; set; }
        public string? TOTP { get; set; }
        public bool DeleteCheck { get; set; }
    }
}
