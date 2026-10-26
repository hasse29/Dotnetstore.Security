using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Tests.Handlers;

public class EncryptionHandlerTests
{
    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static EncryptionOptions Options(string currentId, params (string Id, string Value)[] keys)
    {
        var options = new EncryptionOptions { CurrentKeyId = currentId };
        foreach (var (id, value) in keys)
        {
            options.Keys[id] = value;
        }

        return options;
    }

    private static EncryptionHandler CreateHandler() => new(Options("k1", ("k1", NewKey())));

    [Theory]
    [InlineData("hello")]
    [InlineData("")]
    [InlineData("pässwörd ✓ 日本語 😀")]
    public void EncryptDecrypt_RoundTrips(string text)
    {
        var handler = CreateHandler();

        Assert.Equal(text, handler.Decrypt(handler.Encrypt(text)));
    }

    [Fact]
    public void Encrypt_ProducesVersionedUrlSafeFormat()
    {
        var parts = CreateHandler().Encrypt("hello").Split('.');

        Assert.Equal(3, parts.Length);
        Assert.Equal("dse1", parts[0]);
        Assert.Equal("k1", parts[1]);
        Assert.DoesNotContain('+', parts[2]);
        Assert.DoesNotContain('/', parts[2]);
        Assert.DoesNotContain('=', parts[2]);
    }

    [Fact]
    public void Encrypt_SameTextTwice_ProducesDifferentPayloads()
    {
        var handler = CreateHandler();

        Assert.NotEqual(handler.Encrypt("hello"), handler.Encrypt("hello"));
    }

    [Fact]
    public void Encrypt_DoesNotExposePlaintext()
    {
        var payload = CreateHandler().Encrypt("super-secret-value");
        var raw = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(payload.Split('.')[2]));

        Assert.DoesNotContain("super-secret-value", payload);
        Assert.DoesNotContain("super-secret-value", raw);
    }

    [Fact]
    public void SpanOverload_InteroperatesWithStringOverload()
    {
        var handler = CreateHandler();
        var text = "pässwörd".ToCharArray();

        Assert.Equal("pässwörd", handler.Decrypt(handler.Encrypt(text.AsSpan())));
    }

    [Fact]
    public void Bytes_RoundTripIncludingAllByteValues()
    {
        var handler = CreateHandler();
        var data = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

        var payload = handler.Encrypt(data);

        Assert.Equal(data, handler.DecryptBytes(payload));
        Assert.True(handler.TryDecryptBytes(payload, out var result));
        Assert.Equal(data, result);
    }

    [Fact]
    public void Bytes_EmptyRoundTrips()
    {
        var handler = CreateHandler();

        Assert.Empty(handler.DecryptBytes(handler.Encrypt(Array.Empty<byte>())));
    }

    [Fact]
    public void Bytes_AndText_ShareFormat()
    {
        var handler = CreateHandler();

        Assert.Equal(Encoding.UTF8.GetBytes("pässwörd"), handler.DecryptBytes(handler.Encrypt("pässwörd")));
        Assert.Equal("pässwörd", handler.Decrypt(handler.Encrypt(Encoding.UTF8.GetBytes("pässwörd"))));
    }

    [Fact]
    public void Bytes_AssociatedDataTamperAndMalformed_Fail()
    {
        var handler = CreateHandler();
        var payload = handler.Encrypt(new byte[] { 1, 2, 3 }, "ctx");

        Assert.False(handler.TryDecryptBytes(payload, out var wrongContext, "other"));
        Assert.Null(wrongContext);
        Assert.False(handler.TryDecryptBytes("garbage", out _));
        Assert.Throws<CryptographicException>(() => handler.DecryptBytes(payload));
    }

    [Fact]
    public void AssociatedData_MustMatch()
    {
        var handler = CreateHandler();
        var payload = handler.Encrypt("hello", "user-1");

        Assert.Equal("hello", handler.Decrypt(payload, "user-1"));
        Assert.False(handler.TryDecrypt(payload, out _, "user-2"));
        Assert.False(handler.TryDecrypt(payload, out _));
        Assert.False(handler.TryDecrypt(handler.Encrypt("hello"), out _, "user-1"));
    }

    [Fact]
    public void TamperedPayload_FailsAuthentication()
    {
        var handler = CreateHandler();
        var parts = handler.Encrypt("hello").Split('.');
        var raw = Base64Url.DecodeFromChars(parts[2]);
        raw[^1] ^= 0x01;
        parts[2] = Base64Url.EncodeToString(raw);

        Assert.False(handler.TryDecrypt(string.Join('.', parts), out var plaintext));
        Assert.Null(plaintext);
    }

    [Fact]
    public void DifferentKeyWithSameId_FailsToDecrypt()
    {
        var payload = CreateHandler().Encrypt("hello");

        Assert.False(CreateHandler().TryDecrypt(payload, out _));
    }

    [Fact]
    public void Decrypt_Failure_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() => CreateHandler().Decrypt("garbage"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("dse1.k1")]
    [InlineData("dse1.k1.")]
    [InlineData("dse1.k1.AAAA")]
    [InlineData("dse2.k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("dse1.bad id.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("dse1.k1.!!!!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("dse1.unknown.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void MalformedOrUnknownPayload_ReturnsFalseWithoutThrowing(string payload)
    {
        Assert.False(CreateHandler().TryDecrypt(payload, out var plaintext));
        Assert.Null(plaintext);
    }

    [Fact]
    public void Rotation_OldPayloadsDecryptAndNeedReEncryption()
    {
        var oldKey = NewKey();
        var oldPayload = new EncryptionHandler(Options("k1", ("k1", oldKey))).Encrypt("hello");

        var rotated = new EncryptionHandler(Options("k2", ("k1", oldKey), ("k2", NewKey())));
        var newPayload = rotated.Encrypt("hello");

        Assert.Equal("hello", rotated.Decrypt(oldPayload));
        Assert.True(rotated.NeedsReEncryption(oldPayload));
        Assert.StartsWith("dse1.k2.", newPayload, StringComparison.Ordinal);
        Assert.False(rotated.NeedsReEncryption(newPayload));
    }

    [Fact]
    public void RetiredKeyRemoved_OldPayloadsNoLongerDecrypt()
    {
        var oldPayload = new EncryptionHandler(Options("k1", ("k1", NewKey()))).Encrypt("hello");
        var rotated = new EncryptionHandler(Options("k2", ("k2", NewKey())));

        Assert.False(rotated.TryDecrypt(oldPayload, out _));
        Assert.True(rotated.NeedsReEncryption(oldPayload));
    }

    [Fact]
    public void NeedsReEncryption_MalformedPayload_ReturnsTrue()
    {
        Assert.True(CreateHandler().NeedsReEncryption("garbage"));
    }

    [Fact]
    public void Encrypt_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CreateHandler().Encrypt((string)null!));
    }

    [Fact]
    public void InvalidConfiguration_Throws()
    {
        var good = NewKey();
        var shortKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

        Assert.Throws<ArgumentException>(() => new EncryptionHandler(Options("k1")));
        Assert.Throws<ArgumentException>(() => new EncryptionHandler(Options("k2", ("k1", good))));
        Assert.Throws<ArgumentException>(() => new EncryptionHandler(Options("k1", ("k1", "not base64!!"))));
        Assert.Throws<ArgumentException>(() => new EncryptionHandler(Options("k1", ("k1", shortKey))));
        Assert.Throws<ArgumentException>(() => new EncryptionHandler(Options("bad.id", ("bad.id", good))));
    }

    [Fact]
    public void AddEncryption_ResolvesConfiguredSingleton()
    {
        var key = NewKey();
        using var provider = new ServiceCollection()
            .AddEncryption(o =>
            {
                o.Keys["k1"] = key;
                o.CurrentKeyId = "k1";
            })
            .BuildServiceProvider();

        var handler = provider.GetRequiredService<IEncryptionHandler>();

        Assert.Same(handler, provider.GetRequiredService<IEncryptionHandler>());
        Assert.Equal("hello", handler.Decrypt(handler.Encrypt("hello")));
    }

    [Fact]
    public void AddEncryption_WithoutKeys_ThrowsOnResolve()
    {
        using var provider = new ServiceCollection().AddEncryption().BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IEncryptionHandler>());
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
    }
}
