namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

// カスタムクレーム定義の一覧・追加・編集・削除。値の設定は Users 画面のクレームダイアログで行う。
public partial class CustomClaims
{
    [Inject]
    public CustomClaimService CustomClaimService { get; set; } = default!;

    [Inject]
    public AuditLogService AuditLogService { get; set; } = default!;

    [Inject]
    public IDialogService DialogService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    private List<ClaimDefinition> definitions = [];
    private bool isLoading;

    protected override Task OnInitializedAsync() => LoadAsync();

    private async Task LoadAsync()
    {
        isLoading = true;
        definitions = [.. await CustomClaimService.QueryDefinitionListAsync()];
        isLoading = false;
    }

    private async Task ShowAddDialogAsync()
    {
        var parameters = new DialogParameters<ClaimDefinitionEditDialog> { { x => x.IsNew, true } };
        var dialog = await DialogService.ShowAsync<ClaimDefinitionEditDialog>("Add Claim", parameters);
        var result = await dialog.Result;
        if (result is { Canceled: false })
        {
            await LoadAsync();
        }
    }

    private async Task ShowEditDialogAsync(ClaimDefinition definition)
    {
        var parameters = new DialogParameters<ClaimDefinitionEditDialog>
        {
            { x => x.IsNew, false },
            { x => x.ClaimType, definition.ClaimType },
            { x => x.InitialDescription, definition.Description ?? string.Empty },
            { x => x.InitialValueType, definition.ValueType },
            { x => x.InitialRequiredScope, definition.RequiredScope ?? string.Empty },
            { x => x.InitialInAccessToken, definition.InAccessToken },
            { x => x.InitialInIdToken, definition.InIdToken },
            { x => x.InitialInUserInfo, definition.InUserInfo }
        };
        var dialog = await DialogService.ShowAsync<ClaimDefinitionEditDialog>("Edit Claim", parameters);
        var result = await dialog.Result;
        if (result is { Canceled: false })
        {
            await LoadAsync();
        }
    }

    private async Task DeleteAsync(ClaimDefinition definition)
    {
        var confirmed = await DialogService.ShowMessageBoxAsync(
            "Delete Claim",
            $"Delete claim '{definition.ClaimType}'? Values set for users will be removed as well.",
            yesText: "Delete",
            cancelText: "Cancel");
        if (confirmed is true)
        {
            await CustomClaimService.DeleteDefinitionAsync(definition.ClaimType);
            await AuditLogService.RecordAsync(new AuditEntry(
                AuditEvents.ClaimDefinitionChanged, AuditOutcome.Success, null, null, definition.ClaimType, null, "deleted via admin UI"));
            Snackbar.Add($"Claim '{definition.ClaimType}' deleted.", Severity.Success);
            await LoadAsync();
        }
    }
}
