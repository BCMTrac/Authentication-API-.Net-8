using AuthenticationAPI.Models;
using FluentValidation;

namespace AuthenticationAPI.Validators;

public class ChangePasswordValidator : AbstractValidator<ChangePasswordDto>
{
    public ChangePasswordValidator()
    {
        RuleFor(x => x.CurrentPassword).NotEmpty();
        RuleFor(x => x.NewPassword).NotEmpty().MinimumLength(12).MaximumLength(256);
    }
}

public class EmailRequestValidator : AbstractValidator<EmailRequestDto>
{
    public EmailRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress().MaximumLength(254);
    }
}

public class ChangeEmailStartValidator : AbstractValidator<ChangeEmailStartDto>
{
    public ChangeEmailStartValidator()
    {
        RuleFor(x => x.NewEmail).NotEmpty().EmailAddress().MaximumLength(254);
    }
}

public class ChangeEmailConfirmValidator : AbstractValidator<ChangeEmailConfirmDto>
{
    public ChangeEmailConfirmValidator()
    {
        RuleFor(x => x.NewEmail).NotEmpty().EmailAddress().MaximumLength(254);
        RuleFor(x => x.Token).NotEmpty().MaximumLength(2048);
    }
}

public class MfaCodeValidator : AbstractValidator<MfaCodeDto>
{
    public MfaCodeValidator()
    {
        RuleFor(x => x.Code).NotEmpty().Matches("^[0-9]{6}$");
    }
}

