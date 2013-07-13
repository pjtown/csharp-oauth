// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using System;
using System.Security.Cryptography;
using System.Text;

namespace OAuth.Core
{
    public static class OAuthUtil
    {
        private static readonly DateTime OAuthTimestampBase = new DateTime(1970, 1, 1, 0, 0, 0);

        public static string BuildSecretKey(string oauthConsumerSecret, string oauthTokenSecret)
        {
            var encodedConsumerSecret = RFC3986.Encode(oauthConsumerSecret);
            var encodedTokenSecret = RFC3986.Encode(oauthTokenSecret);

            if (string.IsNullOrEmpty(encodedConsumerSecret))
            {
                throw new ArgumentException("oauth_consumer_secret is empty after RFC3986 decoding");
            }

            var secretKey = string.Format("{0}&{1}", encodedConsumerSecret, encodedTokenSecret);

            return secretKey;
        }

        public static string CalculateHMACSHA1(string text, string key)
        {
            var keyData = Encoding.ASCII.GetBytes(key);
            var textData = Encoding.ASCII.GetBytes(text);

            var hashAlgorithm = new HMACSHA1(keyData);
            var hashData = hashAlgorithm.ComputeHash(textData);

            var hash = Convert.ToBase64String(hashData);

            return hash;
        }

        public static string CalculateSHA1Hash(string body)
        {
            var bodyData = Encoding.ASCII.GetBytes(body ?? string.Empty);
            var hashAlgorithm = new SHA1CryptoServiceProvider();

            var bodyHashData = hashAlgorithm.ComputeHash(bodyData);
            var bodyHash = Convert.ToBase64String(bodyHashData);

            return bodyHash;
        }

        public static DateTime ParseTimestamp(string oauthTimestamp)
        {
            var oauthTimestampSeconds = long.Parse(oauthTimestamp);
            var timestampDate = OAuthTimestampBase.AddSeconds(oauthTimestampSeconds);
            return timestampDate;
        }

        public static string CalculateTimestamp(DateTime timestamp)
        {
            return timestamp.Subtract(OAuthTimestampBase).TotalSeconds.ToString("0");
        }

        public static bool ValidMethod(string method)
        {
            var valid = method == "OPTIONS" || method == "GET" || method == "HEAD" || method == "POST" || method == "PUT" || method == "DELETE";
            return valid;
        }
    }
}