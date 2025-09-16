using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/admin/keys")]
[ApiController]
[Authorize(Roles = "Admin")]
public class KeyManagementController : ControllerBase
{
    private readonly IKeyRingService _keyRingService;
    private readonly IKeyRingCache _cache;
    public KeyManagementController(IKeyRingService keyRingService, IKeyRingCache cache)
    {
        _keyRingService = keyRingService;
        _cache = cache;
    }

    [HttpPost("rotate")]
    public async Task<IActionResult> Rotate()
    {
        var key = await _keyRingService.RotateAsync();
        
        var activeKeys = await _keyRingService.GetAllActiveKeysAsync();
        _cache.Set(activeKeys);
        return Ok(new { key.Kid, key.CreatedUtc });
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        var active = await _keyRingService.GetAllActiveKeysAsync();
        return Ok(active.Select(k => new { k.Kid, k.CreatedUtc, k.Active, k.RetiredUtc }));
    }
}
