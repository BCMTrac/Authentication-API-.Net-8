using System;
using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace IntegrationTests;

public class NegativeAuthTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public NegativeAuthTests(TestApplicationFactory f){_factory=f;}
    private static string NewEmail()=> $"neg_{Guid.NewGuid():N}@example.com";
    private static string NewUser()=> $"neg_{Guid.NewGuid():N}";

    [Fact]
    public async Task Refresh_With_Invalid_Token_Returns_Error()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/authenticate/refresh", new { refreshToken = "not-a-token" });
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK);
    }
}
