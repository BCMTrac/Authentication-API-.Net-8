using System;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntegrationTests;

public class AuthFlowTests : IClassFixture<TestApplicationFactory>
{
    private readonly TestApplicationFactory _factory;

    public AuthFlowTests(TestApplicationFactory factory)
    {
        _factory = factory;
    }

    private static string NewEmail() => $"user_{Guid.NewGuid():N}@example.com";
    private static string NewUser() => $"user_{Guid.NewGuid():N}";

    // Tests for registration, email confirmation, and password reset have been removed
    // as these features have been removed from the AuthenticationAPI.
    // Users are now created exclusively through admin invitation.
}
