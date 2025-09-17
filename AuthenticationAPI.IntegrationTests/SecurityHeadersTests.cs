using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace AuthenticationAPI.IntegrationTests;

public class SecurityHeadersTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public SecurityHeadersTests(TestApplicationFactory f){_factory=f;}

    [Fact]
    public async Task Root_Razor_Page_Has_Security_Headers()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        resp.Headers.Should().ContainKey("Content-Security-Policy");
        resp.Headers.Should().ContainKey("X-Content-Type-Options");
    }
}
