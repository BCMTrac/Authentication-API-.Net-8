using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthenticationAPI.Models;

/// <summary>
/// Base type for DTOs that should reject unknown JSON properties. Any extra JSON members
/// will be captured here and validated by the InputNormalizationFilter.
/// </summary>
public abstract class StrictDtoBase
{
    [JsonExtensionData]
    public Dictionary<string, JsonElement> ExtensionData { get; set; } = new();
}

