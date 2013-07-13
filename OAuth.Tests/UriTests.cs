// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

using System;
using NUnit.Framework;

namespace OAuth.Tests
{
    [TestFixture]
    public class UriTests
    {
        [Test]
        public void CreateUri_ValidHttp_EmptyPath()
        {
            var url = new Uri("HTtp://Api.EIGHTbees.cOM?file=sample.jpg&cost=£300#frag");
            Assert.That(url.Scheme, Is.EqualTo("http"));
            Assert.That(url.Authority, Is.EqualTo("api.eightbees.com"));
            Assert.That(url.AbsolutePath, Is.EqualTo("/"));
        }

        [Test]
        public void CreateUri_ValidHttp_StandardPort()
        {
            var url = new Uri("HTtp://Api.EIGHTbees.cOM:80/requestTOKEN?file=sample.jpg&cost=£300#frag");
            Assert.That(url.Scheme, Is.EqualTo("http"));
            Assert.That(url.Authority, Is.EqualTo("api.eightbees.com"));
            Assert.That(url.AbsolutePath, Is.EqualTo("/requestTOKEN"));
        }

        [Test]
        public void CreateUri_ValidHttp_NonStandardPort()
        {
            var url = new Uri("HTtp://Api.EIGHTbees.cOM:81/requestTOKEN?file=sample.jpg&cost=£300#frag");
            Assert.That(url.Scheme, Is.EqualTo("http"));
            Assert.That(url.Authority, Is.EqualTo("api.eightbees.com:81"));
            Assert.That(url.AbsolutePath, Is.EqualTo("/requestTOKEN"));
        }

        [Test]
        public void CreateUri_ValidHttps_StandardPort()
        {
            var url = new Uri("HTtps://Api.EIGHTbees.cOM:443/requestTOKEN?file=sample.jpg&cost=£300#frag");
            Assert.That(url.Scheme, Is.EqualTo("https"));
            Assert.That(url.Authority, Is.EqualTo("api.eightbees.com"));
            Assert.That(url.AbsolutePath, Is.EqualTo("/requestTOKEN"));
        }

        [Test]
        public void CreateUri_ValidHttps_NonStandardPort()
        {
            var url = new Uri("HTtps://Api.EIGHTbees.cOM:444/requestTOKEN?file=sample.jpg&cost=£300#frag");
            Assert.That(url.Scheme, Is.EqualTo("https"));
            Assert.That(url.Authority, Is.EqualTo("api.eightbees.com:444"));
            Assert.That(url.AbsolutePath, Is.EqualTo("/requestTOKEN"));
        }

        [Test]
        [ExpectedException]
        public void CreateUri_EmptyString()
        {
            var url = new Uri(string.Empty);
        }

        [Test]
        [ExpectedException]
        public void CreateUri_InvalidString()
        {
            var url = new Uri("not a valid URI");
        }
    }
}