// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

namespace OAuth.Core
{
    public static class OAuthParameterNames
    {
        public const string OAuthPrefix = "oauth_";

        public const string Realm = "realm";
        public const string OAuthBodyHash = "oauth_body_hash";
        public const string OAuthCallback = "oauth_callback";
        public const string OAuthConsumerKey = "oauth_consumer_key";
        public const string OAuthToken = "oauth_token";
        public const string OAuthTimestamp = "oauth_timestamp";
        public const string OAuthNonce = "oauth_nonce";
        public const string OAuthSignatureMethod = "oauth_signature_method";
        public const string OAuthSignature = "oauth_signature";
        public const string OAuthVerifier = "oauth_verifier";
        public const string OAuthVersion = "oauth_version";
    }
}