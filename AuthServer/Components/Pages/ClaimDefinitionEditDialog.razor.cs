namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

public partial class ClaimDefinitionEditDialog
{
    [CascadingParameter]
    public IMudDialogInstance MudDialog { get; set; } = default!;

    [Inject]
    public CustomClaimService CustomClaimService { get; set; } = default!;

    [Inject]
    public AuditLogService AuditLogService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    [Parameter]
    public bool IsNew { get; set; }

    [Parameter]
    public string ClaimType { get; set; } = string.Empty;

    [Parameter]
    public string InitialDescription { get; set; } = string.Empty;

    [Parameter]
    public string InitialValueType { get; set; } = CustomClaimService.TypeString;

    [Parameter]
    public string InitialRequiredScope { get; set; } = string.Empty;

    [Parameter]
    public bool InitialInAccessToken { get; set; }

    [Parameter]
    public bool InitialInIdToken { get; set; } = true;

    [Parameter]
    public bool InitialInUserInfo { get; set; } = true;

    private static IReadOnlyList<string> ValueTypes => CustomClaimService.ValueTypes;

    private string claimType = string.Empty;
    private string description = string.Empty;
    private string valueType = CustomClaimService.TypeString;
    private string requiredScope = string.Empty;
    private bool inAccessToken;
    private bool inIdToken = true;
    private bool inUserInfo = true;

    protected override void OnInitialized()
    {
        claimType = ClaimType;
        description = InitialDescription;
        valueType = InitialValueType;
        requiredScope = InitialRequiredScope;
        inAccessToken = InitialInAccessToken;
        inIdToken = InitialInIdToken;
        inUserInfo = InitialInUserInfo;
    }

    private async Task SaveAsync()
    {
        var type = claimType.Trim();
        var validationError = CustomClaimService.ValidateClaimType(type);
        if (validationError is not null)
        {
            Snackbar.Add(validationError, Severity.Warning);
            return;
        }

        if (!inAccessToken && !inIdToken && !inUserInfo)
        {
            Snackbar.Add("Select at least one place to emit the claim.", Severity.Warning);
            return;
        }

        if (IsNew && (await CustomClaimService.QueryDefinitionAsync(type) is not null))
        {
            Snackbar.Add($"Claim '{type}' is already defined.", Severity.Warning);
            return;
        }

        var definition = new ClaimDefinition
        {
            ClaimType = type,
            Description = String.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            ValueType = valueType,
            RequiredScope = String.IsNullOrWhiteSpace(requiredScope) ? null : requiredScope.Trim(),
            InAccessToken = inAccessToken,
            InIdToken = inIdToken,
            InUserInfo = inUserInfo
        };
        await CustomClaimService.SaveDefinitionAsync(definition);
        await AuditLogService.RecordAsync(new AuditEntry(
            AuditEvents.ClaimDefinitionChanged, AuditOutcome.Success, null, null, type, null,
            $"{(IsNew ? "created" : "updated")} via admin UI; type={valueType}; scope={definition.RequiredScope ?? "(any)"}; at={inAccessToken}; id={inIdToken}; userinfo={inUserInfo}"));
        Snackbar.Add($"Claim '{type}' {(IsNew ? "created" : "updated")}.", Severity.Success);
        MudDialog.Close(DialogResult.Ok(true));
    }

    private void Cancel() => MudDialog.Cancel();
}
