namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

public partial class ResourceServerEditDialog
{
    [CascadingParameter]
    public IMudDialogInstance MudDialog { get; set; } = default!;

    [Inject]
    public ResourceServerService ResourceServerService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    [Parameter]
    public bool IsNew { get; set; }

    [Parameter]
    public string ResourceServerId { get; set; } = string.Empty;

    [Parameter]
    public string InitialName { get; set; } = string.Empty;

    [Parameter]
    public string InitialAudience { get; set; } = string.Empty;

    [Parameter]
    public string InitialDescription { get; set; } = string.Empty;

    [Parameter]
    public bool InitialIsActive { get; set; } = true;

    private string name = string.Empty;
    private string audience = string.Empty;
    private string description = string.Empty;
    private bool isActive = true;

    protected override void OnInitialized()
    {
        name = InitialName;
        audience = InitialAudience;
        description = InitialDescription;
        isActive = IsNew || InitialIsActive;
    }

    private async Task SaveAsync()
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            Snackbar.Add("Name is required.", Severity.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(audience))
        {
            Snackbar.Add("Audience URL is required.", Severity.Warning);
            return;
        }

        if (await ResourceServerService.AudienceExistsAsync(audience.Trim(), IsNew ? null : ResourceServerId))
        {
            Snackbar.Add("Audience URL is already registered.", Severity.Warning);
            return;
        }

        if (IsNew)
        {
            var server = new ResourceServer
            {
                Name = name.Trim(),
                Audience = audience.Trim(),
                Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
                IsActive = isActive
            };
            await ResourceServerService.CreateAsync(server);
            Snackbar.Add("Resource server added.", Severity.Success);
        }
        else
        {
            var server = new ResourceServer
            {
                ResourceServerId = ResourceServerId,
                Name = name.Trim(),
                Audience = audience.Trim(),
                Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
                IsActive = isActive
            };
            await ResourceServerService.UpdateAsync(server);
            Snackbar.Add("Resource server updated.", Severity.Success);
        }

        MudDialog.Close(DialogResult.Ok(true));
    }

    private void Cancel() => MudDialog.Cancel();
}
