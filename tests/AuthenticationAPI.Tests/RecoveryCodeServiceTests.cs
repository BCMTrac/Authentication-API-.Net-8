using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace AuthenticationAPI.Tests;

public class RecoveryCodeServiceTests
{
    private ApplicationDbContext NewDb()
    {
        var opts = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new ApplicationDbContext(opts);
    }

    [Fact]
    public async Task Generate_And_Redeem_Codes()
    {
        await using var db = NewDb();
        var svc = new RecoveryCodeService(db);
        var user = new ApplicationUser { Id = Guid.NewGuid().ToString(), UserName = "test" };
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var codes = await svc.GenerateAsync(user, 5);
        codes.Should().HaveCount(5);

        var ok = await svc.RedeemAsync(user, codes[0], "127.0.0.1");
        ok.Should().BeTrue();
        var again = await svc.RedeemAsync(user, codes[0], "127.0.0.1");
        again.Should().BeFalse();
    }
}

