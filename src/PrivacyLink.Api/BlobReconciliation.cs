namespace PrivacyLink.Api;

internal sealed record BlobReference(string SecretId, string BlobId);

internal static class BlobReconciliation
{
    public static IReadOnlyList<string> FindOrphans(IEnumerable<string> relativeBlobPaths, IEnumerable<BlobReference> references)
    {
        var referenced = references
            .Select(reference => $"{reference.SecretId}/{reference.BlobId}")
            .ToHashSet(StringComparer.Ordinal);
        return relativeBlobPaths
            .Where(path => !string.IsNullOrWhiteSpace(path) && !referenced.Contains(path.Replace('\\', '/')))
            .Order(StringComparer.Ordinal)
            .ToArray();
    }
}
