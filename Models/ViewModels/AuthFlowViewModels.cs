using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models.ViewModels;

public class LoginViewModel
{
    [Required, StringLength(100)]
    public string Username { get; set; } = string.Empty;

    [Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}

public class SiteAdminLoginViewModel
{
    [Required, StringLength(100)]
    public string Username { get; set; } = string.Empty;

    [Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}

public class RoleSelectionViewModel
{
    public IReadOnlyCollection<string> AvailableRoles { get; set; } = Array.Empty<string>();

    [Required]
    public string? SelectedRole { get; set; }
}

public class SchemeSelectionViewModel
{
    public IReadOnlyCollection<SchemeItem> AvailableSchemes { get; set; } = Array.Empty<SchemeItem>();

    [Required]
    public string? SelectedSchemeId { get; set; }
}

public record SchemeItem(string Id, string Name, string Type);
