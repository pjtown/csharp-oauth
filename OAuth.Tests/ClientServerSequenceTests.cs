// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using System;
using NUnit.Framework;

namespace OAuth.Tests
{
    [TestFixture]
    public class ClientServerSequenceTests
    {
        public readonly Uri GetRequestTokenUrl = new Uri("https://api.eightbees.com:443/oauth/requesttoken");
        public readonly Uri RegisterUrl = new Uri("https://api.eightbees.com:443/users");

        public readonly string RegisterRequestBody = "{{\"email\":\"peter@example.com\",\"password\":\"123456\"}}";

        [Test]
        public void Registration()
        {
            var consumerKey = OAuthRandom.GenerateAlphanumericKey(16);
            var consumerSecret = OAuthRandom.GenerateAlphanumericKey(16);

            // client

            var request1 = OAuthRequestFactory.CreateRequest("GET", GetRequestTokenUrl, consumerKey, null);
            request1.OAuthSignature = request1.CalculateSignature(consumerSecret, null);
            var authorizationHeader = request1.GetAuthorizationHeader();

            // server

            var request2 = OAuthRequestFactory.ParseRequest("GET", GetRequestTokenUrl, authorizationHeader);
            Assert.True(request2.ValidateSignature(consumerSecret, null));

            var token = OAuthRandom.GenerateAlphanumericKey(16);
            var tokenSecret = OAuthRandom.GenerateAlphanumericKey(16);

            // client

            var request3 = OAuthRequestFactory.CreateRequest("POST", RegisterUrl, consumerKey, token);
            request3.SetBodyHash(RegisterRequestBody);
            request3.OAuthSignature = request3.CalculateSignature(consumerSecret, tokenSecret);
            authorizationHeader = request3.GetAuthorizationHeader();

            // server

            var request4 = OAuthRequestFactory.ParseRequest("POST", RegisterUrl, authorizationHeader);
            request4.SetBodyHash(RegisterRequestBody);
            Assert.True(request4.ValidateSignature(consumerSecret, tokenSecret));
        }
    }
}