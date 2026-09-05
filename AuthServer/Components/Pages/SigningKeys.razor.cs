namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Options;

using MudBlazor;

public partial class SigningKeys
{
    [Inject]
    public SigningKeyService SigningKeyService { get; set; } = default!;

    [Inject]
    public IOptions<AuthServerOptions> Options { get; set; } = default!;

    [Inject]
    public IDialogService DialogService { get; set; } = default!;

    [Inject]
    public ISnackbar Snackbar { get; set; } = default!;

    private List<SigningKey> keys = [];
    private bool isLoading;

    private int GraceDays => Options.Value.SigningKeyGraceDays;

    protected override void OnInitialized() => Load();

    private void Load()
    {
        isLoading = true;
        keys = [.. SigningKeyService.GetAllKeys()];
        isLoading = false;
    }

    private async Task RotateAsync()
    {
        var confirmed = await DialogService.ShowMessageBoxAsync(
            "Rotate Signing Key",
            $"Generate a new signing key now? The current key will stay valid for {GraceDays} day(s) and then retire.",
            yesText: "Rotate",
            cancelText: "Cancel");
        if (confirmed is true)
        {
            var kid = SigningKeyService.RotateKey(TimeSpan.FromDays(GraceDays));
            Snackbar.Add($"Signing key rotated. New kid: {kid}", Severity.Success);
            Load();
        }
    }

    private static bool IsCurrent(SigningKey key) => key.IsActive && (key.ExpiresAt is null);

    private static string GetStatus(SigningKey key) =>
        !key.IsActive ? "Retired" : key.ExpiresAt is null ? "Current" : "Grace period";

    private static Color GetStatusColor(SigningKey key) =>
        !key.IsActive ? Color.Default : key.ExpiresAt is null ? Color.Success : Color.Warning;
}
