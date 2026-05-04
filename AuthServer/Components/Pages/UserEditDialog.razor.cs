namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Components;
using MudBlazor;

public partial class UserEditDialog
{
    [CascadingParameter]
    public IMudDialogInstance MudDialog { get; set; } = default!;

    [Inject]
    public UserService UserService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    [Parameter]
    public bool IsNew { get; set; }

    [Parameter]
    public string UserId { get; set; } = string.Empty;

    [Parameter]
    public string InitialUsername { get; set; } = string.Empty;

    [Parameter]
    public string InitialEmail { get; set; } = string.Empty;

    [Parameter]
    public string InitialName { get; set; } = string.Empty;

    [Parameter]
    public string InitialGivenName { get; set; } = string.Empty;

    [Parameter]
    public string InitialFamilyName { get; set; } = string.Empty;

    [Parameter]
    public bool InitialEmailVerified { get; set; }

    [Parameter]
    public bool InitialIsActive { get; set; } = true;

    private string username = string.Empty;
    private string password = string.Empty;
    private string email = string.Empty;
    private string name = string.Empty;
    private string givenName = string.Empty;
    private string familyName = string.Empty;
    private bool emailVerified;
    private bool isActive = true;

    protected override void OnInitialized()
    {
        username = InitialUsername;
        email = InitialEmail;
        name = InitialName;
        givenName = InitialGivenName;
        familyName = InitialFamilyName;
        emailVerified = InitialEmailVerified;
        isActive = IsNew || InitialIsActive;
    }

    private async Task SaveAsync()
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            Snackbar.Add("Username is required.", Severity.Warning);
            return;
        }

        if (IsNew && string.IsNullOrWhiteSpace(password))
        {
            Snackbar.Add("Password is required.", Severity.Warning);
            return;
        }

        if (await UserService.UsernameExistsAsync(username.Trim(), IsNew ? null : UserId))
        {
            Snackbar.Add($"Username '{username.Trim()}' is already in use.", Severity.Warning);
            return;
        }

        if (IsNew)
        {
            var user = new User
            {
                Username = username.Trim(),
                Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
                Name = string.IsNullOrWhiteSpace(name) ? null : name.Trim(),
                GivenName = string.IsNullOrWhiteSpace(givenName) ? null : givenName.Trim(),
                FamilyName = string.IsNullOrWhiteSpace(familyName) ? null : familyName.Trim(),
                EmailVerified = emailVerified,
                IsActive = isActive
            };
            await UserService.CreateAsync(user, password);
            Snackbar.Add($"User '{user.Username}' created.", Severity.Success);
        }
        else
        {
            var existing = await UserService.FindByIdAsync(UserId);
            if (existing is null)
            {
                Snackbar.Add("User not found.", Severity.Error);
                MudDialog.Cancel();
                return;
            }

            existing.Username = username.Trim();
            existing.Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim();
            existing.Name = string.IsNullOrWhiteSpace(name) ? null : name.Trim();
            existing.GivenName = string.IsNullOrWhiteSpace(givenName) ? null : givenName.Trim();
            existing.FamilyName = string.IsNullOrWhiteSpace(familyName) ? null : familyName.Trim();
            existing.EmailVerified = emailVerified;
            existing.IsActive = isActive;
            await UserService.UpdateAsync(existing);
            Snackbar.Add($"User '{existing.Username}' updated.", Severity.Success);
        }

        MudDialog.Close(DialogResult.Ok(true));
    }

    private void Cancel() => MudDialog.Cancel();
}
