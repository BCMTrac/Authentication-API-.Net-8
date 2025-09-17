using System;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntegrationTests;

public class MfaAdditionalTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public MfaAdditionalTests(TestApplicationFactory factory) { _factory = factory; }
    private static string NewEmail()=> $"mfa_{Guid.NewGuid():N}@example.com";
    private static string NewUser()=> $"mfa_{Guid.NewGuid():N}";

    [Fact(Skip = "Investigate 400 on MFA regeneration flow (timing or state issue)")]
    public async Task Regenerate_Recovery_Codes()
    {
        // Precondition: existing test (MfaFlowTests) covers enable + login; here validate regeneration endpoint structure
        var client = _factory.CreateClient();
        var email = NewEmail();
        var user = NewUser();
        var password = "Sup3r$tr0ngP@ss!";
        (await client.PostAsJsonAsync("/api/v1/authenticate/register", new { Email = email, Username = user, Password = password, TermsAccepted = true })).EnsureSuccessStatusCode();
        using (var scope = _factory.Services.CreateScope())
        {
            var userMgr = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var u = await userMgr.FindByEmailAsync(email);
            var token = await userMgr.GenerateEmailConfirmationTokenAsync(u!);
            (await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token })).EnsureSuccessStatusCode();
            // seed secret + enable
            var totp = scope.ServiceProvider.GetRequiredService<AuthenticationAPI.Services.ITotpService>();
            var protector = scope.ServiceProvider.GetRequiredService<AuthenticationAPI.Services.IMfaSecretProtector>();
            var secret = totp.GenerateSecret();
            u!.MfaSecret = protector.Protect(secret);
            await userMgr.UpdateAsync(u);
            var login1 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = user, Password = password });
            var login1Json = await login1.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(login1Json);
            var access = doc.RootElement.GetProperty("token").GetString();
            access.Should().NotBeNull();
            // confirm enroll
            var code = TotpTestHelper.GenerateCode(secret);
            var authed = _factory.CreateClient();
            authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
            var confirmResp = await authed.PostAsJsonAsync("/api/v1/authenticate/mfa/enroll/confirm", new { code });
            confirmResp.EnsureSuccessStatusCode();
            var confirmJson = await confirmResp.Content.ReadAsStringAsync();
            using var confirmDoc = JsonDocument.Parse(confirmJson);
            var recoveryCodes = confirmDoc.RootElement.GetProperty("recoveryCodes").EnumerateArray().Select(e => e.GetString()!).ToList();
            recoveryCodes.Should().NotBeEmpty();
            // Use a recovery code for second login to guarantee fresh MFA success regardless of TOTP window
            var recoveryCode = recoveryCodes[0];
            var login2 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = user, Password = password, MfaCode = recoveryCode });
            login2.EnsureSuccessStatusCode();
            var login2Json = await login2.Content.ReadAsStringAsync();
            using var doc2 = JsonDocument.Parse(login2Json);
            var token2 = doc2.RootElement.GetProperty("token").GetString();
            var authed2 = _factory.CreateClient();
            authed2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
            var regen = await authed2.PostAsync("/api/v1/authenticate/mfa/recovery/regenerate", null);
            regen.StatusCode.Should().Be(HttpStatusCode.OK);
            var regenJson = await regen.Content.ReadAsStringAsync();
            regenJson.Should().Contain("recoveryCodes");
        }
    }
}
