namespace AuthServer.Components.Pages;

using AuthServer.Models;
using AuthServer.Services;

using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Options;

using MudBlazor;

public partial class SigningKeys
{
    private enum KeyStatus
    {
        Pending,
        Current,
        Grace,
        Retired
    }

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
    private string algorithm = SigningKeyService.Rs256;

    private int GraceDays => Options.Value.SigningKeyGraceDays;

    private int PrePublishSeconds => Options.Value.SigningKeyPrePublishSeconds;

    protected override void OnInitialized()
    {
        algorithm = Options.Value.SigningKeyAlgorithm;
        Load();
    }

    private void Load()
    {
        isLoading = true;
        keys = [.. SigningKeyService.GetAllKeys()];
        isLoading = false;
    }

    private async Task ScheduleAsync()
    {
        var confirmed = await DialogService.ShowMessageBoxAsync(
            "Schedule Key Rotation",
            $"Publish a new {algorithm} key in JWKS now and start signing with it in {PrePublishSeconds} seconds?",
            yesText: "Schedule",
            cancelText: "Cancel");
        if (confirmed is true)
        {
            var kid = SigningKeyService.ScheduleRotation(algorithm);
            Snackbar.Add($"Rotation scheduled. Pending kid: {kid}", Severity.Success);
            Load();
        }
    }

    private async Task RotateNowAsync()
    {
        var confirmed = await DialogService.ShowMessageBoxAsync(
            "Rotate Signing Key Now",
            $"Generate a new {algorithm} key and start signing with it immediately? The current key will stay valid for {GraceDays} day(s) and then retire.",
            yesText: "Rotate",
            cancelText: "Cancel");
        if (confirmed is true)
        {
            var kid = SigningKeyService.RotateKey(algorithm);
            Snackbar.Add($"Signing key rotated. New kid: {kid}", Severity.Success);
            Load();
        }
    }

    private static KeyStatus GetStatus(SigningKey key)
    {
        if (!key.IsActive)
        {
            return KeyStatus.Retired;
        }

        if (key.ExpiresAt is not null)
        {
            return KeyStatus.Grace;
        }

        return (key.ActivatesAt is not null) && (key.ActivatesAt.Value.ToUniversalTime() > DateTime.UtcNow)
            ? KeyStatus.Pending
            : KeyStatus.Current;
    }

    private static string GetStatusText(SigningKey key) => GetStatus(key) switch
    {
        KeyStatus.Pending => "Pending",
        KeyStatus.Current => "Current",
        KeyStatus.Grace => "Grace period",
        _ => "Retired"
    };

    private static Color GetStatusColor(SigningKey key) => GetStatus(key) switch
    {
        KeyStatus.Pending => Color.Info,
        KeyStatus.Current => Color.Success,
        KeyStatus.Grace => Color.Warning,
        _ => Color.Default
    };
}
