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
using Xunit;

namespace IntegrationTests;

public class MfaFlowTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public MfaFlowTests(TestApplicationFactory factory) { _factory = factory; }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    // [Fact]
    // public async Task Enable_MFA_Login_With_Totp_Then_Disable()
    // {
    //     var client = _factory.CreateClient();
    //     var email = NewEmail();
    //     var password = "Sup3r$tr0ngP@ss!";

    //     // Create user through invitation
    //     var (access, _) = await TestHelpers.InviteActivateAndLoginAsync(_factory, client, email, password);

    //     // Seed MFA secret directly for the user (simulating pre-enrolled secret prior to confirm)
    //     string secret;
    //     using (var scope = _factory.Services.CreateScope())
    //     {
    //         var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    //         var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    //         var protector = scope.ServiceProvider.GetRequiredService<IMfaSecretProtector>();
    //         var user = await userMgr.FindByEmailAsync(email);
    //         var totp = scope.ServiceProvider.GetRequiredService<ITotpService>();
    //         secret = totp.GenerateSecret();
    //         user!.MfaSecret = protector.Protect(secret);
    //         user!.TwoFactorEnabled = true;  // Enable 2FA
    //         await userMgr.UpdateAsync(user);
    //     }

    //     // Confirm enrollment with valid TOTP -> enables MFA and returns recovery codes
    //     // Need auth to call enroll confirm
    //     var mfaCode = TotpTestHelper.GenerateCode(secret);

    //     var authed = _factory.CreateClient();
    //     authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
    //     var enableResp = await authed.PostAsJsonAsync("/api/v1/authenticate/mfa/enroll/confirm", new { code = mfaCode });
    //     if (enableResp.StatusCode != HttpStatusCode.OK)
    //     {
    //         var errorContent = await enableResp.Content.ReadAsStringAsync();
    //         System.Console.WriteLine($"Enrollment failed: {enableResp.StatusCode} - {errorContent}");
    //     }
    //     enableResp.StatusCode.Should().Be(HttpStatusCode.OK);

    //     // Login again after enrollment to get a fresh token
    //     var freshLogin = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = email, Password = password });
    //     freshLogin.StatusCode.Should().Be(HttpStatusCode.OK);
    //     var freshJson = await freshLogin.Content.ReadAsStringAsync();
    //     using var freshDoc = JsonDocument.Parse(freshJson);
    //     var freshToken = freshDoc.RootElement.GetProperty("token").GetString()!;

    //     // Login providing TOTP should succeed and include amr=mfa in token
    //     var code = TotpTestHelper.GenerateCode(secret);
    //     var login3 = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = email, Password = password, MfaCode = code });
    //     if (login3.StatusCode != HttpStatusCode.OK)
    //     {
    //         var errorContent = await login3.Content.ReadAsStringAsync();
    //         System.Console.WriteLine($"Login failed: {login3.StatusCode} - {errorContent}");
    //     }
    //     login3.StatusCode.Should().Be(HttpStatusCode.OK);
    //     var login3Json = await login3.Content.ReadAsStringAsync();
    //     using var login3Doc = JsonDocument.Parse(login3Json);
    //     var token3 = login3Doc.RootElement.GetProperty("token").GetString()!;
    //     var payload = JwtTestHelper.ReadPayload(token3);
    //     payload.GetProperty("amr").GetString().Should().Be("mfa");

    //     // Disable MFA (requires amr=mfa policy)
    //     var authedMfa = _factory.CreateClient();
    //     authedMfa.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token3);
    //     var disableResp = await authedMfa.PostAsync("/api/v1/authenticate/mfa/disable", content: null);
    //     disableResp.StatusCode.Should().Be(HttpStatusCode.OK);
    // }
}
