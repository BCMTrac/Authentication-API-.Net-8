using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using QRCoder;

namespace AuthenticationAPI.Controllers;

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
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(otpauthUrl, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var bytes = qrCode.GetGraphic(20);
        return File(bytes, "image/png");
    }
}
