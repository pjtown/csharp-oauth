// Copyright 2013 Peter Townsend
// Licensed under the MIT License 

namespace OAuth.Core
{
    public class OAuthParameter
    {
        private string name;
        private string value;

        public OAuthParameter(string name)
        {
            this.Name = name;
        }

        public string Name
        {
            get { return this.name; }
            set
            {
                this.name = value;
                this.EncodedName = RFC3986.Encode(this.name);
            }
        }

        public string Value
        {
            get { return this.value; }
            set
            {
                this.value = value;
                this.EncodedValue = RFC3986.Encode(this.value);
            }
        }

        public string EncodedName { get; set; }
        public string EncodedValue { get; set; }

        public override string ToString()
        {
            return string.Format("{0}=\"{1}\"", this.EncodedName, this.EncodedValue);
        }
    }
}