using System.Threading.Tasks;
using Xunit;

namespace AuthenticationAPI.IntegrationTests;

public class WizardStepTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public WizardStepTests(TestApplicationFactory f){_factory=f;}

    [Fact(Skip="Wizard state enforcement not yet exposed via API")] // Placeholder
    public async Task Roles_Select_Before_Schemes()
    {
        await Task.CompletedTask;
    }
}
