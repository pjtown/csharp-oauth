// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using NUnit.Framework;
using OAuth.Core;

namespace OAuth.Tests
{
    [TestFixture]
    public class RFC3986Tests
    {
        [Test]
        public void EncodeSpecialCharacters()
        {
            var text = " ღabcdი ";
            var encoded = RFC3986.Encode(text);
            var decoded = RFC3986.Decode(encoded);
            Assert.That(text, Is.EqualTo(decoded));
        }
    }
}