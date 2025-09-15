using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AuthenticationAPI.Tests;

public class PingTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public PingTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory; // default hosting; no DB touch for /api/ping
    }

    [Fact]
    public async Task Ping_Returns_Ok()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/ping");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}

