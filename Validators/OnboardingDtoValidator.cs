using AuthenticationAPI.Models;
using FluentValidation;

namespace AuthenticationAPI.Validators
{
    public class TenantOnboardingDtoValidator : AbstractValidator<TenantOnboardingDto>
    {
        public TenantOnboardingDtoValidator()
        {
            RuleFor(x => x.CompanyName).NotEmpty().MaximumLength(100);
            RuleFor(x => x.Subdomain).NotEmpty().Length(3, 50).Matches("^[a-z0-9-]+$").WithMessage("Subdomain can only contain lowercase letters, numbers, and hyphens.");
            RuleFor(x => x.Plan).NotEmpty();
            RuleFor(x => x.PopiaDpaAgreed).Equal(true).WithMessage("The POPIA & DPA agreement must be accepted.");
        }
    }

    public class AdminOnboardingDtoValidator : AbstractValidator<AdminOnboardingDto>
    {
        public AdminOnboardingDtoValidator()
        {
            RuleFor(x => x.TenantId).NotEmpty();
            RuleFor(x => x.FirstName).NotEmpty().MaximumLength(50);
            RuleFor(x => x.LastName).NotEmpty().MaximumLength(50);
            RuleFor(x => x.Email).NotEmpty().EmailAddress().MaximumLength(254);
            When(x => !string.IsNullOrWhiteSpace(x.Phone), () =>
            {
                RuleFor(x => x.Phone!).Matches("^\\+[1-9][0-9]{7,14}$").WithMessage("Phone must be in E.164 format, e.g., +15551234567");
            });
        }
    }
}