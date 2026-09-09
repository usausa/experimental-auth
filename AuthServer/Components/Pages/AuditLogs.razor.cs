namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

// 監査ログの参照画面。イベント種別 / 結果 / クライアント / 自由検索で絞り込み、新しい順に表示する。
public partial class AuditLogs
{
    private static readonly string[] Outcomes = [AuditOutcome.Success, AuditOutcome.Failure, AuditOutcome.Info];

    [Inject]
    public AuditLogService AuditLogService { get; set; } = default!;

    private List<AuditLog> logs = [];
    private List<string> eventTypes = [];
    private string? eventFilter;
    private string? outcomeFilter;
    private string clientFilter = string.Empty;
    private string searchText = string.Empty;
    private int limit = 100;
    private bool isLoading;

    protected override Task OnInitializedAsync() => LoadAsync();

    private async Task LoadAsync()
    {
        isLoading = true;
        eventTypes = [.. await AuditLogService.QueryEventTypesAsync()];
        var filter = new AuditLogFilter(
            eventFilter,
            outcomeFilter,
            String.IsNullOrWhiteSpace(clientFilter) ? null : clientFilter.Trim(),
            String.IsNullOrWhiteSpace(searchText) ? null : searchText.Trim());
        logs = [.. await AuditLogService.QueryAsync(filter, limit)];
        isLoading = false;
    }

    private static Color GetOutcomeColor(string outcome) => outcome switch
    {
        AuditOutcome.Success => Color.Success,
        AuditOutcome.Failure => Color.Error,
        _ => Color.Info
    };
}
