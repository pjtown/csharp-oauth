// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using NUnit.Framework;

namespace OAuth.Tests
{
    [TestFixture]
    public class OAuthRequestTests
    {
        [Test]
        public void CreateRequest()
        {
            var request = new OAuthRequest { Method = "POST" };
            Assert.NotNull(request);
        }

        [Test]
        [ExpectedException]
        public void CreateRequest_EmptyMethod()
        {
            var request = new OAuthRequest {Method = string.Empty};
        }

        [Test]
        [ExpectedException]
        public void CreateRequest_InvalidMethod()
        {
            var request = new OAuthRequest { Method = "INVALID" };
        }

        [Test]
        public void CreateRequest_ValidKnownParameter()
        {
            var request = new OAuthRequest();
            request.AddHeaderParameter("oauth_callback", "value");
        }

        [Test]
        public void CreateRequest_ValidUnknownParameter()
        {
            var request = new OAuthRequest();
            request.AddHeaderParameter("oauth_undefined", "value");
        }

        [Test]
        [ExpectedException]
        public void CreateRequest_InvalidHeaderParameter()
        {
            var request = new OAuthRequest();
            request.AddHeaderParameter("is_not_valid", "value");
        }
    }
}
