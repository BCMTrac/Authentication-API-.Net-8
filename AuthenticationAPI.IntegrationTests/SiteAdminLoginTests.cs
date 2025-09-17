using System.Net;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;

namespace AuthenticationAPI.IntegrationTests;

public class SiteAdminLoginTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public SiteAdminLoginTests(TestApplicationFactory f){_factory=f;}

    [Fact(Skip="Site admin specific endpoint not yet implemented")] // Placeholder
    public async Task SiteAdmin_Login_Page_Loads()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/site-admin");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
