using System;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthenticationAPI.IntegrationTests;

public class TenantAndPermissionsTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;
    public TenantAndPermissionsTests(TestApplicationFactory f) { _factory = f; }
    private static string NewEmail()=>$"tenant_{Guid.NewGuid():N}@example.com";
    private static string NewUser()=> $"tenant_{Guid.NewGuid():N}";

    [Fact(Skip="Pending tenant creation endpoint implementation")] // Placeholder
    public async Task Admin_Creates_Tenant_Assigns_User()
    {
        await Task.CompletedTask;
    }
}
