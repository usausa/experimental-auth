namespace AuthServer.Components.Pages;

using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

public partial class UserPasswordDialog
{
    [CascadingParameter]
    public IMudDialogInstance MudDialog { get; set; } = default!;

    [Inject]
    public UserService UserService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    [Parameter]
    public string UserId { get; set; } = string.Empty;

    [Parameter]
    public string Username { get; set; } = string.Empty;

    private string newPassword = string.Empty;
    private string confirmPassword = string.Empty;

    private async Task SaveAsync()
    {
        if (String.IsNullOrWhiteSpace(newPassword))
        {
            Snackbar.Add("Password is required.", Severity.Warning);
            return;
        }

        if (newPassword != confirmPassword)
        {
            Snackbar.Add("Passwords do not match.", Severity.Warning);
            return;
        }

        await UserService.ChangePasswordAsync(UserId, newPassword);
        Snackbar.Add($"Password changed for '{Username}'.", Severity.Success);
        MudDialog.Close(DialogResult.Ok(true));
    }

    private void Cancel() => MudDialog.Cancel();
}
