using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/admin/client-apps")]
[ApiController]
[Authorize(Roles = "Admin")]
public class ClientAppsController : ControllerBase
{
    private readonly IClientAppService _service;
    public ClientAppsController(IClientAppService service) => _service = service;

    public record CreateClientAppDto(string Name, string[] Scopes);

    [HttpPost]
    public async Task<IActionResult> Create(CreateClientAppDto dto)
    {
        var (app, secret) = await _service.CreateAsync(dto.Name, dto.Scopes);
        return Ok(new { app.Id, app.Name, secret, app.AllowedScopes });
    }
}
