using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

public class LoginTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    public LoginTests(CustomWebApplicationFactory factory) => _factory = factory;

    [Fact]
    public async Task Login_returns_token_for_valid_credentials()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/v1/authenticate/login", new { identifier = "testAdmin", password = "SuperSecretPassword123!" });
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await resp.Content.ReadFromJsonAsync<dynamic>();
        ((string)json.token).Should().NotBeNullOrEmpty();
    }
}
