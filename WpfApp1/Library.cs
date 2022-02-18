using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.IO;
using Microsoft.VisualBasic.FileIO;

namespace Library
{
    public static class SaveandImport
    {
        public static List<string[]> ImportKey(string PathOfKey = "Keys.csv")
        {
            File.Open(PathOfKey, FileMode.OpenOrCreate).Dispose();
            List<string[]> keys = new List<string[]>();
            var parser = new TextFieldParser(Path.GetFullPath(PathOfKey));
            parser.TextFieldType = FieldType.Delimited;
            parser.Delimiters = new string[] { "," };
            parser.HasFieldsEnclosedInQuotes = true;
            while (!parser.EndOfData)
            {
                var fields = parser.ReadFields();
                keys.Add(new string[] { fields[0], fields[1] });
            }
            parser.Close();
            return keys;
        }

        public static string ExportKey(List<string[]>? Keys, string PathOfKey = "Keys.csv", string BackupName = "backup.csv")
        {
            try
            {
                string temp = string.Empty;
                if (Keys == null || Keys.Count == 0)
                {
                    //Console.WriteLine("No key in list. deleting the keyfile contents");
                }
                else
                {
                    foreach (string[] Key in Keys)
                    {
                        foreach (string key in Key)
                        {
                            var rgxquote = new Regex("\"");
                            rgxquote.Replace(key, "\"\"");
                            temp += "\"" + key  + "\"" + ',';
                        }
                        temp = temp.Substring(0, temp.Length - 1);
                        temp += '\n';
                    }
                }
                var keys = File.Open(PathOfKey, FileMode.OpenOrCreate);
                var bkup = File.Open(BackupName, FileMode.OpenOrCreate);
                keys.Dispose();
                bkup.Dispose();
                File.Copy(PathOfKey, BackupName, true);
                File.WriteAllText(PathOfKey, temp);
                return "success";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }
}