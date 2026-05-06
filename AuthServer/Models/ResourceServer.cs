namespace AuthServer.Models;

/// <summary>Resource server (API) registration record.</summary>
public sealed class ResourceServer
{
    public string ResourceServerId { get; set; } = default!;
    public string Name { get; set; } = default!;
    public string Audience { get; set; } = default!;
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
