// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using System.Security.Cryptography;
using System.Text;

namespace OAuth
{
    public static class OAuthRandom
    {
        private const string Alphanumeric256CharString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh";

        private static readonly char[] AlphanumericChars = Alphanumeric256CharString.ToCharArray();

        public static string GenerateAlphanumericKey(int length)
        {
            var data = new byte[length];

            var random = new RNGCryptoServiceProvider();
            random.GetNonZeroBytes(data);

            var sb = new StringBuilder(length);

            foreach (var b in data)
            {
                sb.Append(AlphanumericChars[b]);
            }

            return sb.ToString();
        }
    }
}