using AuthenticationAPI.Models;
using FluentValidation;

namespace AuthenticationAPI.Validators;

public class RegisterModelValidator : AbstractValidator<RegisterModel>
{
    public RegisterModelValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().Length(3, 50)
            .Matches("^[\\p{L}0-9._-]{3,50}$");
        RuleFor(x => x.Email)
            .NotEmpty().EmailAddress().MaximumLength(254);
        RuleFor(x => x.Password)
            .NotEmpty().MinimumLength(12).MaximumLength(256);
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

