using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/token")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly IKeyRingService _keyRing;
    private readonly IConfiguration _config;
    public TokenController(IKeyRingService keyRing, IConfiguration config)
    {
        _keyRing = keyRing; _config = config;
    }

    // Client credentials removed for MVP
}
