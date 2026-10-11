using System.Text.Json.Serialization;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

[JsonSourceGenerationOptions(System.Text.Json.JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(List<StoredFile>))]
[JsonSerializable(typeof(IReadOnlyList<StoredFile>))]
internal partial class InfrastructureJsonContext : JsonSerializerContext;
