using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers;

[Route("api/mfa")]
[Route("api/v1/mfa")]
[ApiController]
[Authorize]
public class MfaController : ControllerBase
{
    private readonly ITotpService _totp;
    public MfaController(ITotpService totp) { _totp = totp; }

    [HttpGet("qr")]
    public IActionResult GetQr([FromQuery] string otpauthUrl)
    {
        if (string.IsNullOrWhiteSpace(otpauthUrl)) return BadRequest(new { error = "Missing otpauthUrl" });
        return StatusCode(501, new { message = "QR PNG/SVG generation not installed on server. Use the otpauthUrl client-side or install QRCoder.", otpauthUrl });
    }
}
