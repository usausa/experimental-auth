namespace AuthServer.Components.Pages;

using AuthServer.Services;

using Microsoft.AspNetCore.Components;

using MudBlazor;

// Device Authorization Grant の承認画面 (RFC 8628 §3.3)。
// user_code とユーザーの資格情報を 1 つのフォームで受け取り、承認または拒否する。
// リダイレクトもサーバー側セッションも使わないため、方式 A (ブラウザリダイレクト) を待たずに提供できる。
public partial class DeviceActivation
{
    [Inject]
    public DeviceCodeService DeviceCodeService { get; set; } = default!;

    [Inject]
    public UserService UserService { get; set; } = default!;

    // verification_uri_complete の ?user_code=XXXX-XXXX を初期値に使う
    [SupplyParameterFromQuery(Name = "user_code")]
    public string? UserCodeQuery { get; set; }

    private string userCode = string.Empty;
    private string username = string.Empty;
    private string password = string.Empty;
    private bool busy;
    private bool completed;
    private string? errorMessage;
    private string resultMessage = string.Empty;
    private Severity resultSeverity = Severity.Success;
    private DeviceCodeRecord? pendingRequest;

    protected override async Task OnParametersSetAsync()
    {
        if (!String.IsNullOrEmpty(UserCodeQuery) && String.IsNullOrEmpty(userCode))
        {
            userCode = UserCodeQuery;
            pendingRequest = await DeviceCodeService.FindPendingByUserCodeAsync(userCode);
            if (pendingRequest is null)
            {
                errorMessage = "This code is unknown, expired, or already used. Request a new code on your device.";
            }
        }
    }

    private Task ApproveAsync() => DecideAsync(approve: true);

    private Task DenyAsync() => DecideAsync(approve: false);

    private async Task DecideAsync(bool approve)
    {
        errorMessage = null;
        if (String.IsNullOrWhiteSpace(userCode))
        {
            errorMessage = "Device code is required.";
            return;
        }

        if (String.IsNullOrWhiteSpace(username) || String.IsNullOrWhiteSpace(password))
        {
            errorMessage = "Username and password are required.";
            return;
        }

        busy = true;
        try
        {
            // 拒否も本人確認を要求する (第三者が他人の要求を勝手に拒否できないようにする)
            var user = await UserService.AuthenticateAsync(username, password);
            if (user is null)
            {
                errorMessage = "Invalid username or password.";
                return;
            }

            var result = approve
                ? await DeviceCodeService.ApproveAsync(userCode, user.UserId)
                : await DeviceCodeService.DenyAsync(userCode);

            switch (result)
            {
                case DeviceApprovalResult.Approved:
                    completed = true;
                    resultSeverity = Severity.Success;
                    resultMessage = "Device approved. You can return to your device now.";
                    break;
                case DeviceApprovalResult.Denied:
                    completed = true;
                    resultSeverity = Severity.Warning;
                    resultMessage = "Request denied. The device will not receive any tokens.";
                    break;
                case DeviceApprovalResult.Expired:
                    errorMessage = "This code has expired. Request a new code on your device.";
                    break;
                case DeviceApprovalResult.AlreadyDecided:
                    errorMessage = "This code has already been used.";
                    break;
                default:
                    errorMessage = "Unknown device code. Check the code shown on your device.";
                    break;
            }
        }
        finally
        {
            busy = false;
            password = string.Empty;
        }
    }
}
