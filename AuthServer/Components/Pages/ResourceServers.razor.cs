namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

public partial class ResourceServers
{
    [Inject]
    public ResourceServerService ResourceServerService { get; set; } = default!;

    [Inject]
    public IDialogService DialogService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    private List<ResourceServer> resourceServers = [];
    private bool isLoading;

    protected override Task OnInitializedAsync() => LoadAsync();

    private async Task LoadAsync()
    {
        isLoading = true;
        resourceServers = [.. await ResourceServerService.GetAllAsync()];
        isLoading = false;
    }

    private async Task ShowAddDialogAsync()
    {
        var parameters = new DialogParameters<ResourceServerEditDialog> { { x => x.IsNew, true } };
        var dialog = await DialogService.ShowAsync<ResourceServerEditDialog>("Add Resource Server", parameters);
        var result = await dialog.Result;
        if (result is { Canceled: false })
        {
            await LoadAsync();
        }
    }

    private async Task ShowEditDialogAsync(ResourceServer server)
    {
        var parameters = new DialogParameters<ResourceServerEditDialog>
        {
            { x => x.IsNew, false },
            { x => x.ResourceServerId, server.ResourceServerId },
            { x => x.InitialName, server.Name },
            { x => x.InitialAudience, server.Audience },
            { x => x.InitialDescription, server.Description ?? string.Empty },
            { x => x.InitialIsActive, server.IsActive }
        };
        var dialog = await DialogService.ShowAsync<ResourceServerEditDialog>("Edit Resource Server", parameters);
        var result = await dialog.Result;
        if (result is { Canceled: false })
        {
            await LoadAsync();
        }
    }

    private async Task DeleteAsync(ResourceServer server)
    {
        var confirmed = await DialogService.ShowMessageBoxAsync(
            "Delete Resource Server",
            $"Delete '{server.Name}'?",
            yesText: "Delete",
            cancelText: "Cancel");
        if (confirmed is true)
        {
            await ResourceServerService.DeleteAsync(server.ResourceServerId);
            Snackbar.Add("Resource server deleted.", Severity.Success);
            await LoadAsync();
        }
    }
}
