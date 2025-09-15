using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

public class PingTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    public PingTests(CustomWebApplicationFactory factory) => _factory = factory;

    [Fact]
    public async Task Ping_returns_200()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/ping");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
