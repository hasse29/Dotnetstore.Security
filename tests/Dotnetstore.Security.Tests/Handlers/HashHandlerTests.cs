using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Dotnetstore.Security.Tests.Handlers;

public class HashHandlerTests
{
    // Low cost keeps the suite fast; the algorithm path is identical.
    private static readonly Argon2Options FastOptions = new()
    {
        MemorySizeKiB = 64,
        Iterations = 1,
        DegreeOfParallelism = 2,
    };

    private static HashHandler CreateHandler(Argon2Options? options = null) =>
        new(options ?? FastOptions);

    [Fact]
    public void Hash_ProducesPhcFormattedArgon2idString()
    {
        var hash = CreateHandler().Hash("correct horse");

        Assert.StartsWith("$argon2id$v=19$m=64,t=1,p=2$", hash);
        Assert.Equal(6, hash.Split('$').Length);
        Assert.DoesNotContain('=', hash.Split('$')[4]);
    }

    [Fact]
    public void Hash_SamePasswordTwice_ProducesDifferentHashes()
    {
        var handler = CreateHandler();

        Assert.NotEqual(handler.Hash("secret"), handler.Hash("secret"));
    }

    [Fact]
    public void Verify_CorrectPassword_ReturnsTrue()
    {
        var handler = CreateHandler();
        var hash = handler.Hash("pässwörd ✓");

        Assert.True(handler.Verify("pässwörd ✓", hash));
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsFalse()
    {
        var handler = CreateHandler();
        var hash = handler.Hash("secret");

        Assert.False(handler.Verify("Secret", hash));
    }

    [Fact]
    public void Verify_UsesParametersFromStoredHash_NotCurrentOptions()
    {
        var hash = CreateHandler().Hash("secret");
        var stronger = CreateHandler(new Argon2Options { MemorySizeKiB = 128, Iterations = 2, DegreeOfParallelism = 2 });

        Assert.True(stronger.Verify("secret", hash));
    }

    [Fact]
    public void Verify_KnownVector_MatchesReferenceImplementation()
    {
        // Argon2id test vector from the reference implementation (password, salt "somesalt", m=65536, t=2, p=1).
        const string hash = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

        Assert.True(CreateHandler().Verify("password", hash));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a hash")]
    [InlineData("$argon2id$v=19$m=64,t=1,p=2$c29tZXNhbHQ")]
    [InlineData("$argon2i$v=19$m=64,t=1,p=2$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=16$m=64,t=1,p=2$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=abc,t=1,p=2$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=64,t=1,p=2$!!!!$AAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=2147483647,t=1,p=2$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=64,t=999999,p=2$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")]
    public void Verify_MalformedOrUnsafeHash_ReturnsFalseWithoutThrowing(string hash)
    {
        var handler = CreateHandler();

        Assert.False(handler.Verify("secret", hash));
        Assert.True(handler.NeedsRehash(hash));
    }

    [Fact]
    public void Verify_EmptyPassword_ReturnsFalse()
    {
        var handler = CreateHandler();

        Assert.False(handler.Verify("", handler.Hash("secret")));
    }

    [Fact]
    public void Verify_TamperedHash_ReturnsFalse()
    {
        var handler = CreateHandler();
        var parts = handler.Hash("secret").Split('$');
        parts[5] = (parts[5][0] == 'A' ? 'B' : 'A') + parts[5][1..];

        Assert.False(handler.Verify("secret", string.Join('$', parts)));
    }

    [Fact]
    public void NeedsRehash_CurrentParameters_ReturnsFalse()
    {
        var handler = CreateHandler();

        Assert.False(handler.NeedsRehash(handler.Hash("secret")));
    }

    [Fact]
    public void NeedsRehash_HashCreatedWithWeakerParameters_ReturnsTrue()
    {
        var hash = CreateHandler().Hash("secret");
        var stronger = CreateHandler(new Argon2Options { MemorySizeKiB = 128, Iterations = 1, DegreeOfParallelism = 2 });

        Assert.True(stronger.NeedsRehash(hash));
    }

    [Fact]
    public void Hash_NullOrEmpty_Throws()
    {
        var handler = CreateHandler();

        Assert.Throws<ArgumentNullException>(() => handler.Hash(null!));
        Assert.Throws<ArgumentException>(() => handler.Hash(""));
    }

    [Theory]
    [InlineData(0, 1, 1, 16)]
    [InlineData(64, 0, 1, 16)]
    [InlineData(64, 1, 0, 16)]
    [InlineData(64, 1, 16, 16)]
    [InlineData(64, 1, 1, 4)]
    public void Constructor_InvalidOptions_Throws(int memory, int iterations, int parallelism, int saltSize)
    {
        var options = new Argon2Options
        {
            MemorySizeKiB = memory,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
            SaltSize = saltSize,
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => new HashHandler(options));
    }

    [Fact]
    public void Constructor_SnapshotsOptions_LaterMutationHasNoEffect()
    {
        var options = new Argon2Options { MemorySizeKiB = 64, Iterations = 1, DegreeOfParallelism = 2 };
        var handler = new HashHandler(options);
        options.MemorySizeKiB = 0;

        Assert.StartsWith("$argon2id$v=19$m=64,", handler.Hash("secret"));
    }

    [Fact]
    public void AddSecurity_ResolvesConfiguredSingleton()
    {
        var provider = new ServiceCollection()
            .AddSecurity(o =>
            {
                o.MemorySizeKiB = 64;
                o.Iterations = 1;
                o.DegreeOfParallelism = 2;
            })
            .BuildServiceProvider();

        var handler = provider.GetRequiredService<IHashHandler>();

        Assert.Same(handler, provider.GetRequiredService<IHashHandler>());
        Assert.StartsWith("$argon2id$v=19$m=64,t=1,p=2$", handler.Hash("secret"));
    }

    [Fact]
    public void SpanOverloads_InteroperateWithStringOverloads()
    {
        var handler = CreateHandler();
        char[] password = "pässwörd ✓".ToCharArray();

        var spanHash = handler.Hash(password.AsSpan());
        var stringHash = handler.Hash("pässwörd ✓");

        Assert.True(handler.Verify("pässwörd ✓", spanHash));
        Assert.True(handler.Verify(password.AsSpan(), stringHash));
        Assert.False(handler.Verify("wrong".AsSpan(), stringHash));
    }

    [Fact]
    public void SpanOverloads_EmptyInput()
    {
        var handler = CreateHandler();

        Assert.Throws<ArgumentException>(() => handler.Hash(ReadOnlySpan<char>.Empty));
        Assert.False(handler.Verify(ReadOnlySpan<char>.Empty, handler.Hash("secret")));
    }

    private static string NewPepper() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    private static Argon2Options WithPeppers(string? currentId, params (string Id, string Value)[] peppers)
    {
        var options = new Argon2Options
        {
            MemorySizeKiB = 64,
            Iterations = 1,
            DegreeOfParallelism = 2,
            CurrentPepperId = currentId,
        };
        foreach (var (id, value) in peppers)
        {
            options.Peppers[id] = value;
        }

        return options;
    }

    [Fact]
    public void Pepper_HashStoresPepperId()
    {
        var hash = CreateHandler(WithPeppers("v1", ("v1", NewPepper()))).Hash("secret");

        Assert.Contains(",p=2,keyid=v1$", hash);
    }

    [Fact]
    public void Pepper_NoPepper_HashHasNoKeyId()
    {
        Assert.DoesNotContain("keyid", CreateHandler().Hash("secret"));
    }

    [Fact]
    public void Pepper_SamePepper_Verifies()
    {
        var pepper = NewPepper();
        var hash = CreateHandler(WithPeppers("v1", ("v1", pepper))).Hash("secret");

        Assert.True(CreateHandler(WithPeppers("v1", ("v1", pepper))).Verify("secret", hash));
    }

    [Fact]
    public void Pepper_DifferentValueForSameId_DoesNotVerify()
    {
        var hash = CreateHandler(WithPeppers("v1", ("v1", NewPepper()))).Hash("secret");

        Assert.False(CreateHandler(WithPeppers("v1", ("v1", NewPepper()))).Verify("secret", hash));
    }

    [Fact]
    public void Pepper_UnknownId_DoesNotVerifyAndNeedsRehash()
    {
        var hash = CreateHandler(WithPeppers("v1", ("v1", NewPepper()))).Hash("secret");
        var other = CreateHandler(WithPeppers("v2", ("v2", NewPepper())));

        Assert.False(other.Verify("secret", hash));
        Assert.True(other.NeedsRehash(hash));
    }

    [Fact]
    public void Pepper_Rotation_OldHashesVerifyAndNeedRehash()
    {
        var oldPepper = NewPepper();
        var oldHash = CreateHandler(WithPeppers("v1", ("v1", oldPepper))).Hash("secret");

        var rotated = CreateHandler(WithPeppers("v2", ("v1", oldPepper), ("v2", NewPepper())));
        var newHash = rotated.Hash("secret");

        Assert.True(rotated.Verify("secret", oldHash));
        Assert.True(rotated.NeedsRehash(oldHash));
        Assert.Contains("keyid=v2", newHash);
        Assert.True(rotated.Verify("secret", newHash));
        Assert.False(rotated.NeedsRehash(newHash));
    }

    [Fact]
    public void Pepper_AddedLater_UnpepperedHashesStillVerifyAndNeedRehash()
    {
        var legacyHash = CreateHandler().Hash("secret");
        var peppered = CreateHandler(WithPeppers("v1", ("v1", NewPepper())));

        Assert.True(peppered.Verify("secret", legacyHash));
        Assert.True(peppered.NeedsRehash(legacyHash));
    }

    [Fact]
    public void Pepper_TamperedKeyId_DoesNotVerify()
    {
        var pepper = NewPepper();
        var handler = CreateHandler(WithPeppers("v1", ("v1", pepper), ("v2", NewPepper())));
        var hash = handler.Hash("secret").Replace("keyid=v1", "keyid=v2", StringComparison.Ordinal);

        Assert.False(handler.Verify("secret", hash));
    }

    [Fact]
    public void Pepper_InvalidKeyIdInHash_IsMalformed()
    {
        var handler = CreateHandler(WithPeppers("v1", ("v1", NewPepper())));
        var hash = handler.Hash("secret").Replace("keyid=v1", "keyid=v 1", StringComparison.Ordinal);

        Assert.False(handler.Verify("secret", hash));
        Assert.True(handler.NeedsRehash(hash));
    }

    [Fact]
    public void Pepper_InvalidConfiguration_Throws()
    {
        var good = NewPepper();

        Assert.Throws<ArgumentException>(() => new HashHandler(WithPeppers("v1", ("v1", "not base64!!"))));
        Assert.Throws<ArgumentException>(() => new HashHandler(WithPeppers("v1", ("v1", "AAAA"))));
        Assert.Throws<ArgumentException>(() => new HashHandler(WithPeppers(null, ("v1", good))));
        Assert.Throws<ArgumentException>(() => new HashHandler(WithPeppers("v2", ("v1", good))));
        Assert.Throws<ArgumentException>(() => new HashHandler(WithPeppers("bad id", ("bad id", good))));
        Assert.Throws<ArgumentException>(() => new HashHandler(WithPeppers("v1")));
    }

    [Fact]
    public void AddSecurity_ConfiguresPeppers()
    {
        var pepper = NewPepper();
        var provider = new ServiceCollection()
            .AddSecurity(o =>
            {
                o.MemorySizeKiB = 64;
                o.Iterations = 1;
                o.DegreeOfParallelism = 2;
                o.Peppers["v1"] = pepper;
                o.CurrentPepperId = "v1";
            })
            .BuildServiceProvider();

        var hash = provider.GetRequiredService<IHashHandler>().Hash("secret");

        Assert.True(CreateHandler(WithPeppers("v1", ("v1", pepper))).Verify("secret", hash));
    }
}
