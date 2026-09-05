namespace AuthServer.Models;

// Resource server (API) registration record.
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
