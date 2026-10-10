namespace PrivacyLink.Contracts;

public sealed record HealthResponse(string Status);
public sealed record FileUploadPolicyResponse(int MaxFiles, long MaxTotalFileBytes, string[] AllowedFileExtensions);
public sealed record MessageCiphertext(string Nonce, string Ciphertext);
public sealed record FileMetadataResponse(string Id, string Extension, string NameNonce, string NameCiphertext, string MimeType, long Size);
public sealed record OpenedFileResponse(string Id, string Extension, string NameNonce, string NameCiphertext, string MimeType, long Size, string Nonce, string Ciphertext);
public sealed record CreateSecretResponse(string Id, DateTimeOffset ExpiresAt, bool PasswordProtected, string RevokeToken);
public sealed record SecretMetadataResponse(bool Exists, int ProtocolVersion, DateTimeOffset ExpiresAt, bool PasswordProtected, bool HasMessage, int FileCount, FileMetadataResponse[] Files);
public sealed record OpenSecretResponse(int ProtocolVersion, MessageCiphertext? Message, OpenedFileResponse[] Files);
public sealed record OpenFileResponse(int ProtocolVersion, OpenedFileResponse File);
public sealed record ErrorResponse(string Code);
public sealed record EncryptedMessageRequest(string Nonce, string Ciphertext);
public sealed record EncryptedFileRequest(string Id, string Extension, string NameNonce, string NameCiphertext, string MimeType, long Size, string Nonce, string Ciphertext);
public sealed record CreateSecretRequest(int ProtocolVersion, string Expiry, EncryptedMessageRequest? Message, EncryptedFileRequest[] Files, string? Password);
public sealed record UnlockSecretRequest(string Password);
