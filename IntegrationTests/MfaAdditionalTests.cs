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

    [Fact]
    public async Task Regenerate_Recovery_Codes()
    {
        // Create user through invitation
        var client = _factory.CreateClient();
        var email = NewEmail();
        var password = "Sup3r$tr0ngP@ss!";
        await TestHelpers.InviteActivateAndLoginAsync(_factory, client, email, password);

        string secret;
        using (var scope = _factory.Services.CreateScope())
        {
            // seed secret + enable in a fresh scope to avoid concurrency issues
            var userMgr = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthenticationAPI.Models.ApplicationUser>>();
            var totp = scope.ServiceProvider.GetRequiredService<AuthenticationAPI.Services.ITotpService>();
            var protector = scope.ServiceProvider.GetRequiredService<AuthenticationAPI.Services.IMfaSecretProtector>();
            secret = totp.GenerateSecret();
            var u = await userMgr.FindByEmailAsync(email);
            u!.MfaSecret = protector.Protect(secret);
            var updateRes = await userMgr.UpdateAsync(u);
            if (!updateRes.Succeeded)
            {
                var errs = string.Join("; ", updateRes.Errors.Select(e => $"{e.Code}:{e.Description}"));
                throw new Exception($"Failed to update user with MFA secret: {errs}");
            }
            var login1 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = email, Password = password });
            var login1Json = await login1.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(login1Json);
            var access = doc.RootElement.GetProperty("token").GetString();
            access.Should().NotBeNull();
            // confirm enroll
            var code = TotpTestHelper.GenerateCode(secret);
            var authed = _factory.CreateClient();
            authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
            var confirmResp = await authed.PostAsJsonAsync("/api/v1/authenticate/mfa/enroll/confirm", new { code });
            if (!confirmResp.IsSuccessStatusCode)
            {
                var body = await confirmResp.Content.ReadAsStringAsync();
                throw new Exception($"Enroll confirm failed: {(int)confirmResp.StatusCode} {confirmResp.ReasonPhrase} => {body}");
            }
            var confirmJson = await confirmResp.Content.ReadAsStringAsync();
            using var confirmDoc = JsonDocument.Parse(confirmJson);
            var recoveryCodes = confirmDoc.RootElement.GetProperty("recoveryCodes").EnumerateArray().Select(e => e.GetString()!).ToList();
            recoveryCodes.Should().NotBeEmpty();
            // Use a recovery code for second login to guarantee fresh MFA success regardless of TOTP window
            var recoveryCode = recoveryCodes[0];
            // Do a TOTP-based login to ensure amr=mfa for policy-guarded endpoints
            var totpCode = TotpTestHelper.GenerateCode(secret, DateTimeOffset.UtcNow.AddSeconds(31));
            var login2 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = email, Password = password, MfaCode = totpCode });
            login2.EnsureSuccessStatusCode();
            var login2Json = await login2.Content.ReadAsStringAsync();
            using var doc2 = JsonDocument.Parse(login2Json);
            var token2 = doc2.RootElement.GetProperty("token").GetString();
            var authed2 = _factory.CreateClient();
            authed2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
            var regen = await authed2.PostAsync("/api/v1/authenticate/mfa/recovery/regenerate", null);
            if (regen.StatusCode != HttpStatusCode.OK)
            {
                var body = await regen.Content.ReadAsStringAsync();
                var ct = regen.Content.Headers.ContentType?.ToString();
                throw new Exception($"Regenerate returned {(int)regen.StatusCode}: {regen.ReasonPhrase}; CT={ct}; Body={body}");
            }
            var regenJson = await regen.Content.ReadAsStringAsync();
            regenJson.Should().Contain("recoveryCodes");
        }
    }
}
