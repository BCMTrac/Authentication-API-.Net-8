using AuthenticationAPI.Models;
using FluentValidation;

namespace AuthenticationAPI.Validators;

public class LoginModelValidator : AbstractValidator<LoginModel>
{
    public LoginModelValidator()
    {
        RuleFor(x => x.Identifier).NotEmpty().MaximumLength(254);
        RuleFor(x => x.Password).NotEmpty().MaximumLength(256);
        When(x => !string.IsNullOrWhiteSpace(x.MfaCode), () =>
        {
            RuleFor(x => x.MfaCode!).Matches("^[0-9]{6}$");
        });
    }
}

