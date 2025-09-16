using System;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using Microsoft.Extensions.DependencyInjection;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthenticationAPI.IntegrationTests;

public class MfaFlowTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public MfaFlowTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    [Fact]
    public async Task Enable_MFA_Login_With_Totp_Then_Disable()
    {
        var client = _factory.CreateClient();
        var email = NewEmail();
        var username = NewUser();
        var password = "Sup3r$tr0ngP@ss!";

        // Register + confirm
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new RegisterModel { Email = email, Username = username, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userMgr.FindByEmailAsync(email);
            var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
            (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
        }

        // Seed MFA secret directly for the user (simulating pre-enrolled secret prior to confirm)
        string secret;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var protector = scope.ServiceProvider.GetRequiredService<IMfaSecretProtector>();
            var user = await userMgr.FindByEmailAsync(email);
            var totp = scope.ServiceProvider.GetRequiredService<ITotpService>();
            secret = totp.GenerateSecret();
            user!.MfaSecret = protector.Protect(secret);
            await userMgr.UpdateAsync(user);
        }

        // Confirm enrollment with valid TOTP -> enables MFA and returns recovery codes
        // Need auth to call enroll confirm
        var login1 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login1.StatusCode.Should().Be(HttpStatusCode.OK);
        var login1Json = await login1.Content.ReadAsStringAsync();
        using var login1Doc = JsonDocument.Parse(login1Json);
        var access = login1Doc.RootElement.GetProperty("token").GetString()!;
        var mfaCode = TotpTestHelper.GenerateCode(secret);

        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        var enableResp = await authed.PostAsJsonAsync("/api/v1/authenticate/mfa/enroll/confirm", new { code = mfaCode });
        enableResp.StatusCode.Should().Be(HttpStatusCode.OK);

        // Now login without MFA code should respond mfaRequired
        var login2 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password });
        login2.StatusCode.Should().Be(HttpStatusCode.OK);
        var login2Json = await login2.Content.ReadAsStringAsync();
        using var login2Doc = JsonDocument.Parse(login2Json);
        login2Doc.RootElement.TryGetProperty("mfaRequired", out var mfaRequired).Should().BeTrue();
        mfaRequired.GetBoolean().Should().BeTrue();

        // Login providing TOTP should succeed and include amr=mfa in token
    var code = TotpTestHelper.GenerateCode(secret, DateTimeOffset.UtcNow.AddSeconds(31));
        var login3 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = username, Password = password, MfaCode = code });
        login3.StatusCode.Should().Be(HttpStatusCode.OK);
        var login3Json = await login3.Content.ReadAsStringAsync();
        using var login3Doc = JsonDocument.Parse(login3Json);
        var token3 = login3Doc.RootElement.GetProperty("token").GetString()!;
    var payload = JwtTestHelper.ReadPayload(token3);
    payload.GetProperty("amr").GetString().Should().Be("mfa");

        // Disable MFA (requires amr=mfa policy)
        var authedMfa = _factory.CreateClient();
        authedMfa.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token3);
        var disableResp = await authedMfa.PostAsync("/api/v1/authenticate/mfa/disable", content: null);
        disableResp.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
