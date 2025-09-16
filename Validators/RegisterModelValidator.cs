using AuthenticationAPI.Models;
using FluentValidation;
using Microsoft.Extensions.Configuration;
using System.Linq;

namespace AuthenticationAPI.Validators;

public class RegisterModelValidator : AbstractValidator<RegisterModel>
{
    public RegisterModelValidator(IConfiguration configuration)
    {
        var reservedUsernames = configuration.GetSection("Validation:ReservedUsernames").Get<string[]>() ?? System.Array.Empty<string>();
        var badPasswordFragments = configuration.GetSection("Validation:PasswordBadFragments").Get<string[]>() ?? System.Array.Empty<string>();
        var disposableDomains = configuration.GetSection("Validation:DisposableEmailDomains").Get<string[]>() ?? System.Array.Empty<string>();

        RuleFor(x => x.Username)
            .NotEmpty().Length(3, 50)
            .Matches("^[\\p{L}0-9._-]{3,50}$")
            .Must(x => !reservedUsernames.Contains(x, System.StringComparer.OrdinalIgnoreCase))
            .WithMessage("Username is reserved. Choose another.");

        RuleFor(x => x.Email)
            .NotEmpty().EmailAddress().MaximumLength(254)
            .Must(email =>
            {
                if (string.IsNullOrWhiteSpace(email)) return true;
                var domain = email.Split('@').LastOrDefault();
                return domain != null && !disposableDomains.Contains(domain, System.StringComparer.OrdinalIgnoreCase);
            })
            .WithMessage("Disposable email domains are not allowed.");

        RuleFor(x => x.Password)
            .NotEmpty().MinimumLength(12).MaximumLength(256)
            .Must((model, password) =>
            {
                if (string.IsNullOrEmpty(password)) return true;
                var pwLower = password.ToLowerInvariant();
                var emailLocal = (model.Email?.Split('@').FirstOrDefault() ?? string.Empty).ToLowerInvariant();
                var userLower = (model.Username ?? string.Empty).ToLowerInvariant();

                if (!string.IsNullOrWhiteSpace(emailLocal) && pwLower.Contains(emailLocal)) return false;
                if (!string.IsNullOrWhiteSpace(userLower) && pwLower.Contains(userLower)) return false;

                return true;
            })
            .WithMessage("Password is too similar to account identifiers.")
            .Must(password =>
            {
                if (string.IsNullOrEmpty(password)) return true;
                var pwLower = password.ToLowerInvariant();
                return !badPasswordFragments.Any(frag => pwLower.Contains(frag));
            })
            .WithMessage("Password contains common patterns; choose a stronger one.");

        RuleFor(x => x.FullName)
            .MaximumLength(100);

        RuleFor(x => x.TermsAccepted).Equal(true)
            .WithMessage("You must accept the terms and conditions.");

        When(x => !string.IsNullOrWhiteSpace(x.Phone), () =>
        {
            RuleFor(x => x.Phone!).Matches("^\\+[1-9][0-9]{7,14}$");
        });
    }
}