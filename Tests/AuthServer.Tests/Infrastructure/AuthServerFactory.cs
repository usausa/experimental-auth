namespace AuthServer.Tests.Infrastructure;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;

// AuthServer を TestServer 上で起動する。DB はテストクラスごとに独立した一時ディレクトリの SQLite で、seed を有効にする。
// レート制限は既定で無効にしておき (機能テストが上限に当たらないように)、レート制限のテストでは派生クラスで有効化する。
// 要求は https スキームで送る (SEC-01 の HTTPS リダイレクトに掛からないようにするため)。
public class AuthServerFactory : WebApplicationFactory<Program>
{
    private readonly string dataDirectory = Path.Combine(Path.GetTempPath(), "AuthServer.Tests", Guid.NewGuid().ToString("N"));

    public AuthServerFactory()
    {
        ClientOptions.BaseAddress = new Uri("https://localhost");
    }

    // 派生クラスで追加・上書きする設定
    protected virtual IEnumerable<KeyValuePair<string, string?>> Settings => [];

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        // UseSetting はホスト構成として Program.cs の実行中から見える (ConfigureAppConfiguration は Build 時まで遅延されるため、
        // 起動時に読む Data:Directory や RateLimiting には効かない)
        builder.UseSetting("Data:Directory", dataDirectory);
        builder.UseSetting("Seed:Enabled", "true");
        builder.UseSetting("RateLimiting:Enabled", "false");
        builder.UseSetting("AuthServer:DeviceCodePollIntervalSeconds", "1");
        foreach (var (key, value) in Settings)
        {
            builder.UseSetting(key, value);
        }
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync().ConfigureAwait(false);
        DeleteDataDirectory();
        GC.SuppressFinalize(this);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            DeleteDataDirectory();
        }
    }

    // 同期・非同期どちらの破棄経路からも呼ばれるので、二重に呼ばれても問題ないようにする
    private void DeleteDataDirectory()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            if (Directory.Exists(dataDirectory))
            {
                Directory.Delete(dataDirectory, recursive: true);
            }
        }
        catch (IOException)
        {
            // 一時ファイルが残っても次回以降のテストには影響しない
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
