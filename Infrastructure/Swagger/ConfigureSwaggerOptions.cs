using System;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace AuthenticationAPI.Infrastructure.Swagger
{
    /// <summary>
    /// Generates a Swagger document for each discovered API version.
    /// </summary>
    public sealed class ConfigureSwaggerOptions : IConfigureOptions<SwaggerGenOptions>
    {
        private readonly IApiVersionDescriptionProvider _provider;

        public ConfigureSwaggerOptions(IApiVersionDescriptionProvider provider)
        {
            _provider = provider;
        }

        public void Configure(SwaggerGenOptions options)
        {
            foreach (var description in _provider.ApiVersionDescriptions)
            {
                var info = new OpenApiInfo
                {
                    Title = "Authentication API",
                    Version = description.ApiVersion.ToString(),
                    Description = "Authentication and Authorization endpoints"
                };
                options.SwaggerDoc(description.GroupName, info);
            }
        }
    }
}
