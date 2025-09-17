using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IntegrationTests;

public class RateLimitEnabledFactory : TestApplicationFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((ctx,cfg)=>
        {
            cfg.AddInMemoryCollection(new Dictionary<string,string?>
            {
                ["Features:RateLimit"] = "true"
            });
        });
    }
}

public class RateLimitTests : IClassFixture<RateLimitEnabledFactory>
{
    private readonly RateLimitEnabledFactory _factory;
    public RateLimitTests(RateLimitEnabledFactory f){_factory=f;}

    [Fact]
    public async Task Register_Rate_Limit_Triggers_429()
    {
        var client = _factory.CreateClient();
        for (int i=0;i<5;i++)
        {
            await client.PostAsJsonAsync("/api/v1/authenticate/register", new { Email=$"rl_{i}@example.com", Username=$"rl_{i}", Password="Sup3r$tr0ngP@ss!", TermsAccepted=true});
        }
        var last = await client.PostAsJsonAsync("/api/v1/authenticate/register", new { Email=$"rl_last@example.com", Username=$"rl_last", Password="Sup3r$tr0ngP@ss!", TermsAccepted=true});
    last.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }
}
