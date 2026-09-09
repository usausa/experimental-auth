namespace AuthServer.Components.Pages;

using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

// ユーザーごとのカスタムクレーム値を編集する。定義されている全クレームを 1 行ずつ表示し、空欄なら削除する。
public partial class UserClaimsDialog
{
    private sealed class ClaimRow
    {
        public string ClaimType { get; init; } = default!;
        public string ValueType { get; init; } = default!;
        public string Label { get; init; } = default!;
        public string Help { get; init; } = default!;
        public string Value { get; set; } = string.Empty;
    }

    [CascadingParameter]
    public IMudDialogInstance MudDialog { get; set; } = default!;

    [Inject]
    public CustomClaimService CustomClaimService { get; set; } = default!;

    [Inject]
    public AuditLogService AuditLogService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    [Parameter]
    public string UserId { get; set; } = string.Empty;

    [Parameter]
    public string Username { get; set; } = string.Empty;

    private List<ClaimRow> rows = [];

    protected override async Task OnInitializedAsync()
    {
        var definitions = await CustomClaimService.QueryDefinitionListAsync();
        var values = (await CustomClaimService.QueryUserClaimListAsync(UserId)).ToDictionary(c => c.ClaimType, c => c.Value, StringComparer.Ordinal);
        rows = definitions
            .Select(d => new ClaimRow
            {
                ClaimType = d.ClaimType,
                ValueType = d.ValueType,
                Label = $"{d.ClaimType} ({d.ValueType})",
                Help = (d.RequiredScope is null ? "always emitted" : $"requires scope '{d.RequiredScope}'") +
                       (d.ValueType == CustomClaimService.TypeJson ? "; enter a JSON value" : String.Empty),
                Value = values.TryGetValue(d.ClaimType, out var v) ? v : String.Empty
            })
            .ToList();
    }

    private async Task SaveAsync()
    {
        foreach (var row in rows)
        {
            if (String.IsNullOrWhiteSpace(row.Value))
            {
                continue;
            }

            var error = CustomClaimService.ValidateValue(row.ValueType, row.Value.Trim());
            if (error is not null)
            {
                Snackbar.Add($"{row.ClaimType}: {error}", Severity.Warning);
                return;
            }
        }

        var changed = new List<string>();
        foreach (var row in rows)
        {
            await CustomClaimService.SetUserClaimAsync(UserId, row.ClaimType, row.Value);
            changed.Add(String.IsNullOrWhiteSpace(row.Value) ? row.ClaimType + "=(removed)" : row.ClaimType + "=" + row.Value.Trim());
        }

        await AuditLogService.RecordAsync(new AuditEntry(
            AuditEvents.UserClaimsChanged, AuditOutcome.Success, null, UserId, Username, null, "via admin UI; " + String.Join("; ", changed)));
        Snackbar.Add($"Claims saved for '{Username}'.", Severity.Success);
        MudDialog.Close(DialogResult.Ok(true));
    }

    private void Cancel() => MudDialog.Cancel();
}
