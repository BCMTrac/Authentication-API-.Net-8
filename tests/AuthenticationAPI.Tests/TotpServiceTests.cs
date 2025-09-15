using AuthenticationAPI.Services;
using FluentAssertions;
using Xunit;

namespace AuthenticationAPI.Tests;

public class TotpServiceTests
{
    [Fact]
    public void GenerateSecret_Produces_Base32_String()
    {
        var svc = new TotpService();
        var s = svc.GenerateSecret();
        s.Should().NotBeNullOrWhiteSpace();
        s.Should().MatchRegex("^[A-Z2-7]+$");
    }

    [Fact]
    public void ValidateCode_Invalid_Code_Fails()
    {
        var svc = new TotpService();
        var secret = svc.GenerateSecret();
        svc.ValidateCode(secret, "000000", out var _).Should().BeFalse();
    }
}

