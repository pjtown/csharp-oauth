// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace OAuth.Core
{
    public static class RFC3986
    {
        public static readonly Regex EscapedSequence = new Regex("(%[0-9a-fA-F]{2})+", RegexOptions.Compiled);

        public static string Encode(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }

            var sb = new StringBuilder(input.Length * 2);

            foreach (var c in input)
            {
                if (IsValidChar(c))
                {
                    sb.Append(c);
                }
                else
                {
                    var utf8Data = Encoding.UTF8.GetBytes(new[] {c});

                    foreach (var b in utf8Data)
                    {
                        sb.AppendFormat("%{0:X}", b);
                    }
                }
            }

            return sb.ToString();
        }

        public static string Decode(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }

            var decodedValue = EscapedSequence.Replace(input, match =>
            {
                var hexByteString = match.Groups[0].Value;
                var hexByteValues = hexByteString.Split(new[] { '%' }, StringSplitOptions.RemoveEmptyEntries);

                var data = new byte[hexByteValues.Length];

                for (var i = 0; i < data.Length; i++)
                {
                    var hexByteValue = hexByteValues[i];
                    var byteValue = byte.Parse(hexByteValue, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
                    data[i] = byteValue;
                }

                var utf8String = Encoding.UTF8.GetString(data);

                return utf8String;
            });

            return decodedValue;
        }

        private static bool IsValidChar(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        }
    }
}