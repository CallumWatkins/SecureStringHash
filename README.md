# SecureStringHash

Hash any `SecureString` securely with any `HashAlgorithm` and any `Encoding`.

Prevents copies of the string from remaining in memory (unlike when converting to a managed `string`) and zeros out all memory used to store intermediate values.

## Usage

### Use the extension method...

```c#
// Use any HashAlgorithm
using (HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider())
{
    // Uses UTF-8 encoding by default
    byte[] hash = secureString.Hash(hashAlgorithm); // <-- The extension method being used
    
    // Alternatively you can specify the encoding
    byte[] hashUtf16 = secureString.Hash(hashAlgorithm, Encoding.Unicode);
}
```

The `SecureString` encoding is first converted from UTF-16 (the encoding .NET uses for all characters) to the encoding specified, or UTF-8 if no encoding is chosen, before being hashed.

### ... or just copy the short code
It's all in [SecureStringHashExtensions.cs](SecureStringHash/SecureStringHashExtensions.cs). Use it how you wish.
