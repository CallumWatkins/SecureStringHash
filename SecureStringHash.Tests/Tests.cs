using System;
using NUnit.Framework;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace SecureStringHash.Tests
{
    [TestFixture]
    public class Tests
    {
        private const string TestString = "TEST_STRING_123_ɸɸɸ_ᛥᛥᛥ_🢫🢫🢫";
        private readonly SecureString _secureString = SecureStringHelper.New(TestString);

        [Test]
        public void EmptySecureString()
        {
            byte[] emptyStringUtf8Bytes = Encoding.UTF8.GetBytes(string.Empty);
            SecureString emptySecureString = SecureStringHelper.NewEmpty();
            using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
            {
                byte[] expectedHashedBytes = hashAlgorithm.ComputeHash(emptyStringUtf8Bytes);

                Assert.AreEqual(expectedHashedBytes, emptySecureString.Hash(hashAlgorithm, Encoding.UTF8));
            }
        }

        [Test]
        public void NullSecureString()
        {
            SecureString nullSecureString = null;
            using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
            {
                Assert.Throws<ArgumentNullException>(() => nullSecureString.Hash(hashAlgorithm, Encoding.UTF8));
            }
        }

        [Test]
        public void NullHashAlgorithm()
        {
            Assert.Throws<ArgumentNullException>(() => _secureString.Hash(null, Encoding.UTF8));
        }

        [Test]
        public void NullEncoding()
        {
            using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
            {
                Assert.Throws<ArgumentNullException>(() => _secureString.Hash(hashAlgorithm, null));
            }
        }

        [Test]
        public void Utf7Encoding()
        {
            byte[] testStringUtf7Bytes = Encoding.UTF7.GetBytes(TestString);
            using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
            {
                byte[] expectedHashedBytes = hashAlgorithm.ComputeHash(testStringUtf7Bytes);
                
                Assert.AreEqual(expectedHashedBytes, _secureString.Hash(hashAlgorithm, Encoding.UTF7));
            }
        }

        [Test]
        public void Utf8Encoding()
        {
            byte[] testStringUtf8Bytes = Encoding.UTF8.GetBytes(TestString);
            using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
            {
                byte[] expectedHashedBytes = hashAlgorithm.ComputeHash(testStringUtf8Bytes);

                Assert.AreEqual(expectedHashedBytes, _secureString.Hash(hashAlgorithm), "Default encoding should be UTF8.");
                Assert.AreEqual(expectedHashedBytes, _secureString.Hash(hashAlgorithm, Encoding.UTF8));
            }
        }

        [Test]
        public void Utf16Encoding()
        {
            byte[] testStringUtf16Bytes = Encoding.Unicode.GetBytes(TestString);
            using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
            {
                byte[] expectedHashedBytes = hashAlgorithm.ComputeHash(testStringUtf16Bytes);

                Assert.AreEqual(expectedHashedBytes, _secureString.Hash(hashAlgorithm, Encoding.Unicode));
            }
        }

        [Test]
        public void Utf32Encoding()
        {
            byte[] testStringUtf32Bytes = Encoding.UTF32.GetBytes(TestString);
            using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
            {
                byte[] expectedHashedBytes = hashAlgorithm.ComputeHash(testStringUtf32Bytes);

                Assert.AreEqual(expectedHashedBytes, _secureString.Hash(hashAlgorithm, Encoding.UTF32));
            }
        }
    }
}
