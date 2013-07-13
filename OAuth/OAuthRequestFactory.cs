// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using System;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using OAuth.Core;

namespace OAuth
{
    public static class OAuthRequestFactory
    {
        private const int DefaultNonceLength = 16;
        private const string AuthorizationHeaderName = "Authorization";
        private const string FormUrlEncodedContentType = "application/x-www-form-urlencoded";

        private static readonly Regex OAuthHeaderRegex = new Regex("\\s*[Oo][Aa][Uu][Tt][Hh]\\s+(.*)\\s*$", RegexOptions.Compiled);
        private static readonly Regex OAuthHeaderParameterRegex = new Regex("(\\w+)=\"([^\"]*)\"", RegexOptions.Compiled);

        public static OAuthRequest CreateRequest(string method, Uri url, string oauthConsumerKey, string oauthToken = null)
        {
            var request = new OAuthRequest { Method = method, Url = url };

            AddQueryStringParameters(request, url);

            request.OAuthConsumerKey = oauthConsumerKey;
            request.OAuthToken = oauthToken;
            request.OAuthNonce = OAuthRandom.GenerateAlphanumericKey(DefaultNonceLength);
            request.OAuthSignatureMethod = OAuthSignatureMethods.HMACSHA1;
            request.OAuthTimestamp = OAuthUtil.CalculateTimestamp(DateTime.UtcNow);

            return request;
        }

        public static OAuthRequest ParseRequest(string method, Uri url, string authorizationHeader)
        {
            var request = new OAuthRequest { Method = method, Url = url };

            AddQueryStringParameters(request, url);
            AddAuthorizationHeaderParameters(request, authorizationHeader);

            return request;
        }

        public static OAuthRequest ParseRequest(HttpRequest httpRequest)
        {
            var authorizationHeader = GetAuthorizationHeader(httpRequest.Headers);

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                throw new ArgumentException("HTTP authorization header is not available");
            }

            var request = ParseRequest(httpRequest.HttpMethod, httpRequest.Url, authorizationHeader);

            if (string.Compare(httpRequest.ContentType, FormUrlEncodedContentType, true, CultureInfo.InvariantCulture) == 0)
            {
                // TODO parse body text
            }

            return request;
        }

        private static void AddQueryStringParameters(OAuthRequest request, Uri uri)
        {
            var nameValueCollection = HttpUtility.ParseQueryString(uri.Query);

            for (var i = 0; i < nameValueCollection.Count; i++)
            {
                request.AddRequestParameter(nameValueCollection.GetKey(i), nameValueCollection.Get(i));
            }
        }

        private static void AddAuthorizationHeaderParameters(OAuthRequest request, string authorizationHeader)
        {
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                throw new ArgumentNullException("authorizationHeader");
            }

            var authorizationParametersMatch = OAuthHeaderRegex.Match(authorizationHeader);
            if (!authorizationParametersMatch.Success)
            {
                throw new ArgumentException("Invalid OAuth HTTP authorization header value. Must begin with \"OAuth\"");
            }

            var authorizationParametersValue = authorizationParametersMatch.Groups[1].Value;
            var authorizationParameterMatches = OAuthHeaderParameterRegex.Matches(authorizationParametersValue);

            foreach (var oauthParameterMatch in authorizationParameterMatches.Cast<Match>().Where(x => x.Success))
            {
                var key = oauthParameterMatch.Groups[1].Value;
                var value = oauthParameterMatch.Groups[2].Value;

                request.AddHeaderParameter(key, value);
            }
        }

        private static string GetAuthorizationHeader(NameValueCollection headers)
        {
            for (var i = 0; i < headers.Count; i++)
            {
                if (string.Compare(headers.GetKey(i), AuthorizationHeaderName, true, CultureInfo.InvariantCulture) == 0)
                {
                    return headers.Get(i);
                }
            }

            return null;
        }
    }
}