// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OAuth.Core;

namespace OAuth
{
    public class OAuthRequest
    {
        private const string DefaultOAuthVersion = "1.0";

        private readonly List<OAuthParameter> headerParameters = new List<OAuthParameter>();
        private readonly List<OAuthParameter> requestParameters = new List<OAuthParameter>();

        private string method;

        private readonly OAuthParameter realm = new OAuthParameter(OAuthParameterNames.Realm);
        private readonly OAuthParameter oauthBodyHash = new OAuthParameter(OAuthParameterNames.OAuthBodyHash);
        private readonly OAuthParameter oauthCallback = new OAuthParameter(OAuthParameterNames.OAuthCallback);
        private readonly OAuthParameter oauthConsumerKey = new OAuthParameter(OAuthParameterNames.OAuthConsumerKey);
        private readonly OAuthParameter oauthToken = new OAuthParameter(OAuthParameterNames.OAuthToken);
        private readonly OAuthParameter oauthTimestamp = new OAuthParameter(OAuthParameterNames.OAuthTimestamp);
        private readonly OAuthParameter oauthNonce = new OAuthParameter(OAuthParameterNames.OAuthNonce);
        private readonly OAuthParameter oauthSignatureMethod = new OAuthParameter(OAuthParameterNames.OAuthSignatureMethod);
        private readonly OAuthParameter oauthSignature = new OAuthParameter(OAuthParameterNames.OAuthSignature);
        private readonly OAuthParameter oauthVerifier = new OAuthParameter(OAuthParameterNames.OAuthVersion);
        private readonly OAuthParameter oauthVersion = new OAuthParameter(OAuthParameterNames.OAuthVersion);

        public OAuthRequest()
        {
            this.headerParameters.Add(this.oauthBodyHash);
            this.headerParameters.Add(this.oauthCallback);
            this.headerParameters.Add(this.oauthConsumerKey);
            this.headerParameters.Add(this.oauthNonce);
            this.headerParameters.Add(this.oauthSignature);
            this.headerParameters.Add(this.oauthSignatureMethod);
            this.headerParameters.Add(this.oauthTimestamp);
            this.headerParameters.Add(this.oauthToken);
            this.headerParameters.Add(this.oauthVerifier);
            this.headerParameters.Add(this.oauthVersion);
        }

        public string Method
        {
            get { return this.method; }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentException("Method must be a valid HTTP Method");
                }

                var normalisedMethod = value.ToUpperInvariant();

                var validMethod = normalisedMethod == "OPTIONS" || normalisedMethod == "GET" || normalisedMethod == "HEAD" || normalisedMethod == "POST" || normalisedMethod == "PUT" || normalisedMethod == "DELETE";

                if (!validMethod)
                {
                    throw new ArgumentException("Method must be a valid HTTP Method");
                }

                this.method = normalisedMethod;
            }
        }

        public Uri Url { get; set; }

        public string Realm
        {
            get { return this.realm.Value; }
            set { this.realm.Value = value; }
        }

        public string OAuthBodyHash
        {
            get { return this.oauthBodyHash.Value; }
            set { this.oauthBodyHash.Value = value; }
        }

        public string OAuthCallback
        {
            get { return this.oauthCallback.Value; }
            set { this.oauthCallback.Value = value; }
        }

        public string OAuthConsumerKey
        {
            get { return this.oauthConsumerKey.Value; }
            set { this.oauthConsumerKey.Value = value; }
        }

        public string OAuthToken
        {
            get { return this.oauthToken.Value; }
            set { this.oauthToken.Value = value; }
        }

        public string OAuthTimestamp
        {
            get { return this.oauthTimestamp.Value; }
            set { this.oauthTimestamp.Value = value; }
        }

        public string OAuthNonce
        {
            get { return this.oauthNonce.Value; }
            set { this.oauthNonce.Value = value; }
        }

        public string OAuthSignatureMethod
        {
            get { return this.oauthSignatureMethod.Value; }
            set { this.oauthSignatureMethod.Value = value; }
        }

        public string OAuthSignature
        {
            get { return this.oauthSignature.Value; }
            set { this.oauthSignature.Value = value; }
        }

        public string OAuthVerifier
        {
            get { return this.oauthVerifier.Value; }
            set { this.oauthVerifier.Value = value; }
        }
        
        public string OAuthVersion
        {
            get { return this.oauthVersion.Value; }
            set { this.oauthVersion.Value = value; }
        }

        public void SetBodyHash(string body)
        {
            this.OAuthBodyHash = OAuthUtil.CalculateSHA1Hash(body);
        }

        public void AddHeaderParameter(string name, string value)
        {
            this.AddParameter(name, value, true);
        }
        
        public void AddRequestParameter(string name, string value)
        {
            this.AddParameter(name, value, false);
        }

        public string CalculateSignature(string oauthConsumerSecret, string oauthTokenSecret = null)
        {
            if (string.IsNullOrEmpty(this.OAuthSignatureMethod))
            {
                throw new ArgumentException("The oauth_signature_method header must be defined. Only HMAC-SHA1 or PLAINTEXT are supported)");
            }

            var secretKey = OAuthUtil.BuildSecretKey(oauthConsumerSecret, oauthTokenSecret);

            if (string.CompareOrdinal(this.OAuthSignatureMethod, OAuthSignatureMethods.HMACSHA1) == 0)
            {
                var signatureBase = this.GetSignatureBase();
                var signature = OAuthUtil.CalculateHMACSHA1(secretKey, signatureBase);
                return signature;
            }

            if (string.CompareOrdinal(this.OAuthSignatureMethod, OAuthSignatureMethods.PLAINTEXT) == 0)
            {
                return secretKey;
            }

            var log = string.Format("The oauth_signature_method=\"{0}\" is not supported", this.OAuthSignatureMethod);
            throw new ArgumentException(log);
        }

        public string GetSignatureBase()
        {
            if (this.Method == null)
            {
                throw new Exception("Missing mandatory HTTP Method for building signature base string");
            }

            var encodedMethod = RFC3986.Encode(this.Method);

            var normalisedUrl = this.GetNormalizedUrl();
            var encodedNormalisedUrl = RFC3986.Encode(normalisedUrl);

            var parameterBase = GetSignatureParameterBase();
            var encodedParameterBase = RFC3986.Encode(parameterBase);

            var signatureBase = string.Format("{0}&{1}&{2}", encodedMethod, encodedNormalisedUrl, encodedParameterBase);

            return signatureBase;
        }

        public string GetSignatureParameterBase()
        {
            var signatureMethod = this.OAuthSignatureMethod;

            if (this.OAuthConsumerKey == null || this.OAuthNonce == null || signatureMethod == null || this.OAuthTimestamp == null)
            {
                throw new Exception("Missing mandatory parameter for building signature base string");
            }

            if (this.OAuthVersion != null && string.CompareOrdinal(this.OAuthVersion, DefaultOAuthVersion) != 0)
            {
                var log = string.Format("oauth_version parameter must be \"{0}\"", DefaultOAuthVersion);
                throw new Exception(log);
            }

            if (signatureMethod != OAuthSignatureMethods.HMACSHA1 && signatureMethod != OAuthSignatureMethods.PLAINTEXT && signatureMethod != OAuthSignatureMethods.RSASHA1)
            {
                var log = string.Format("Unsupported oauth_signature_method parameter \"{0}\"", signatureMethod);
                throw new Exception(log);
            }

            // Get all valid header parameters except oauth_signature
            var parameters = this.headerParameters.Where(x => x.Value != null && x != this.oauthSignature).ToList();

            // Add all request parameters
            parameters.AddRange(this.requestParameters);

            // Sort parameters alphabetically by encoded name and then by encoded value
            var orderedParameters = parameters.OrderBy(x => x.EncodedName).ThenBy(x => x.EncodedValue).ToList();

            var sb = new StringBuilder();

            for (var i = 0; i < orderedParameters.Count; i++)
            {
                var parameter = orderedParameters[i];

                if (i > 0)
                {
                    sb.Append("&");
                }

                sb.Append(parameter.EncodedName);
                sb.Append("=");
                sb.Append(parameter.EncodedValue ?? string.Empty);
            }

            return sb.ToString();
        }

        public string GetNormalizedUrl()
        {
            if (this.Url == null)
            {
                throw new Exception("Missing mandatory URL for building signature base string");
            }

            var normalisedUrl = string.Format("{0}://{1}{2}", this.Url.Scheme, this.Url.Authority, this.Url.AbsolutePath);

            return normalisedUrl;
        }

        public string GetAuthorizationHeader()
        {
            var parameters = new List<OAuthParameter>();
            
            if (this.realm.Value != null)
            {
                parameters.Add(this.realm);
            }

            parameters.AddRange(this.headerParameters.Where(x => x.Value != null));

            var sb = new StringBuilder("OAuth ");

            for (var i = 0; i < parameters.Count; i++)
            {
                var parameter = parameters[i];

                if (i > 0)
                {
                    sb.Append("&");
                }

                sb.Append(parameter.EncodedName);
                sb.Append("=\"");
                sb.Append(parameter.EncodedValue);
                sb.Append("\"");
            }

            return sb.ToString();
        }

        public bool ValidateSignature(string oauthConsumerSecret, string oauthTokenSecret)
        {
            if (this.OAuthSignature == null)
            {
                throw new Exception("OAuth request is missing the oauth_signature parameter value");
            }

            var signature = this.CalculateSignature(oauthConsumerSecret, oauthTokenSecret);

            var match = string.CompareOrdinal(this.OAuthSignature, signature) == 0;

            return match;
        }

        private void AddParameter(string name, string value, bool headerParameter)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentNullException("name");
            }

            var decodedName = RFC3986.Decode(name);
            var decodedValue = RFC3986.Decode(value);

            var parameter = this.headerParameters.FirstOrDefault(x => string.CompareOrdinal(x.Name, decodedName) == 0);

            if (parameter != null)
            {
                if (parameter.Value != null)
                {
                    var log = string.Format("Duplicate parameter ({0}={1})", name, value);
                    throw new ArgumentException(log);
                }

                parameter.Value = decodedValue;
            }
            else if (decodedName.StartsWith(OAuthParameterNames.OAuthPrefix))
            {
                parameter = new OAuthParameter(decodedName) { Value = decodedValue };
                this.headerParameters.Add(parameter);
            }
            else if (headerParameter)
            {
                if (decodedName == OAuthParameterNames.Realm)
                {
                    this.realm.Value = decodedValue;
                }
                else
                {
                    var log = string.Format("Invalid header parameter name ({0}={1})", name, value);
                    throw new ArgumentException(log);
                }
            }
            else
            {
                parameter = new OAuthParameter(decodedName) { Value = decodedValue };
                this.requestParameters.Add(parameter);
            }
        }

        public override string ToString()
        {
            return !string.IsNullOrEmpty(this.Method) ? string.Format("{0} {1}", this.Method, this.Url) : string.Empty;
        }
    }
}