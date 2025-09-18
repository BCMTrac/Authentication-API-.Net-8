using System;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntegrationTests;

public class TokenLifecycleTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public TokenLifecycleTests(TestApplicationFactory factory) { _factory = factory; }
    private static string NewEmail()=> $"tok_{Guid.NewGuid():N}@example.com";
    private static string NewUser()=> $"tok_{Guid.NewGuid():N}";

    [Fact]
    public async Task Refresh_Rotation_Reuse_Detected()
    {
        var client = _factory.CreateClient();
        var email = NewEmail(); var password = "Sup3r$tr0ngP@ss!";
        await TestHelpers.InviteActivateAndLoginAsync(_factory, client, email, password);
        var login = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { Identifier = email, Password = password });
        var text = await login.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(text);
        var refresh = doc.RootElement.GetProperty("refreshToken").GetString();
        // first refresh
        var r1 = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh });
        r1.StatusCode.Should().Be(HttpStatusCode.OK);
        var r1Json = await r1.Content.ReadAsStringAsync();
        using var doc2 = JsonDocument.Parse(r1Json);
        var newRefresh = doc2.RootElement.GetProperty("refreshToken").GetString();
        // reuse old refresh again -> should produce 400/401
        var reuse = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = refresh });
        reuse.StatusCode.Should().NotBe(HttpStatusCode.OK);
    }
}
