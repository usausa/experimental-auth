namespace AuthServer.Models;

public sealed class AuditLog
{
    public long Id { get; set; }
    public DateTime OccurredAt { get; set; }
    public string Event { get; set; } = default!;
    public string Outcome { get; set; } = default!;
    public string? ClientId { get; set; }
    public string? UserId { get; set; }
    public string? Subject { get; set; }
    public string? IpAddress { get; set; }
    public string? Detail { get; set; }
}
