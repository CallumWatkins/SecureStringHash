using System.Security;

namespace SecureStringHash.Tests
{
    internal static class SecureStringHelper
    {
        internal static SecureString NewEmpty()
        {
            var s = new SecureString();
            s.MakeReadOnly();
            return s;
        }

        internal static SecureString New(string str)
        {
            var s = new SecureString();
            foreach (char c in str) { s.AppendChar(c); }
            s.MakeReadOnly();
            return s;
        }
    }
}
