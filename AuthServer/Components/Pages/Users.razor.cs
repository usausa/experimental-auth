namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Components;
using MudBlazor;

public partial class Users
{
    [Inject]
    public UserService UserService { get; set; } = default!;

    [Inject]
    public IDialogService DialogService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    private List<User> users = [];
    private string searchText = string.Empty;
    private bool isLoading;

    private IEnumerable<User> FilteredUsers => string.IsNullOrEmpty(searchText)
        ? users
        : users.Where(u =>
            u.Username.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
            (u.Name?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
            (u.Email?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false));

    protected override async Task OnInitializedAsync() => await LoadAsync();

    private async Task LoadAsync()
    {
        isLoading = true;
        users = [.. await UserService.GetAllAsync()];
        isLoading = false;
    }

    private async Task ShowAddDialogAsync()
    {
        var parameters = new DialogParameters<UserEditDialog> { { x => x.IsNew, true } };
        var dialog = await DialogService.ShowAsync<UserEditDialog>("Add User", parameters);
        var result = await dialog.Result;
        if (result is { Canceled: false })
        {
            await LoadAsync();
        }
    }

    private async Task ShowEditDialogAsync(User user)
    {
        var parameters = new DialogParameters<UserEditDialog>
        {
            { x => x.IsNew, false },
            { x => x.UserId, user.UserId },
            { x => x.InitialUsername, user.Username },
            { x => x.InitialEmail, user.Email ?? string.Empty },
            { x => x.InitialName, user.Name ?? string.Empty },
            { x => x.InitialGivenName, user.GivenName ?? string.Empty },
            { x => x.InitialFamilyName, user.FamilyName ?? string.Empty },
            { x => x.InitialEmailVerified, user.EmailVerified },
            { x => x.InitialIsActive, user.IsActive }
        };
        var dialog = await DialogService.ShowAsync<UserEditDialog>("Edit User", parameters);
        var result = await dialog.Result;
        if (result is { Canceled: false })
        {
            await LoadAsync();
        }
    }

    private async Task ShowPasswordDialogAsync(User user)
    {
        var parameters = new DialogParameters<UserPasswordDialog>
        {
            { x => x.UserId, user.UserId },
            { x => x.Username, user.Username }
        };
        await DialogService.ShowAsync<UserPasswordDialog>("Change Password", parameters);
    }

    private async Task DeleteAsync(User user)
    {
        var confirmed = await DialogService.ShowMessageBoxAsync(
            "Delete User",
            $"Delete user '{user.Username}'? This action cannot be undone.",
            yesText: "Delete",
            cancelText: "Cancel");

        if (confirmed != true)
        {
            return;
        }

        await UserService.DeleteAsync(user.UserId);
        Snackbar.Add($"User '{user.Username}' deleted.", Severity.Success);
        await LoadAsync();
    }
}
