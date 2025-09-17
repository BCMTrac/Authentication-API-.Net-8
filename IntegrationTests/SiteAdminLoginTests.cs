using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;

namespace IntegrationTests;

public class SiteAdminLoginTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public SiteAdminLoginTests(TestApplicationFactory f){_factory=f;}

    [Fact]
    public async Task SiteAdmin_Password_Login_Issues_Jwt_And_Access_Me()
    {
        var client = _factory.CreateClient();
        var email = $"sa_{System.Guid.NewGuid():N}@example.com";
        var username = $"sa_{System.Guid.NewGuid():N}";
        var password = "Sup3r$tr0ngP@ss!";
        // Register + confirm email via helper (returns normal login token which we ignore for site-admin path)
        await TestHelpers.RegisterConfirmAndLoginAsync(_factory, client, email, username, password);
        var loginResp = await client.PostAsJsonAsync("/api/v1/authenticate/site-admin/login", new { Identifier = username, Password = password });
        loginResp.EnsureSuccessStatusCode();
        var json = await loginResp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var tokenValue = doc.RootElement.GetProperty("token").GetString();
        tokenValue.Should().NotBeNullOrWhiteSpace();
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenValue);
        var me = await authed.GetAsync("/api/v1/users/me");
        me.StatusCode.Should().Be(HttpStatusCode.OK);
        var meJson = await me.Content.ReadAsStringAsync();
        meJson.Should().Contain(username);
    }
}
