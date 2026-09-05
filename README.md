# experimental-auth

OAuth 2.0 / OpenID Connect 準拠の認証サーバーを .NET 10 でスクラッチ実装する学習プロジェクトです。

---

## システム構成

| コンポーネント | 種別 | フレームワーク | デフォルト URL |
|--------------|------|--------------|--------------|
| **AuthServer** | Web API + Web UI | .NET 10 Minimal API + Blazor Server | `http://localhost:5080` |
| **ResourceServer** | Web API | .NET 10 Minimal API | `http://localhost:5180` |
| **TestClient** | CLI ツール | .NET 10 Console | — |

---

## TestClient の使い方

### 起動方法

```bash
cd TestClient
dotnet run -- <command> [options]
```

### コマンド一覧

| コマンド | 説明 |
|---------|------|
| `discovery` | AuthServer の OIDC Discovery エンドポイントを取得・表示する |
| `token` | アクセストークンを取得してローカルに保存する |
| `api` | 保存済みアクセストークンで ResourceServer の保護 API を呼び出す |
| `refresh` | リフレッシュトークンで新しいアクセストークンを取得する |
| `userinfo` | UserInfo エンドポイントからユーザー情報を取得する |
| `introspect` | トークンイントロスペクションを実行する |
| `revoke` | トークンを失効させる |

### ユースケース別使用例

#### ユースケース 1: ユーザー認証(authorization_code + PKCE)

API クライアントがユーザー資格情報を直接送信して認可コードを取得し、アクセストークン・ID Token・リフレッシュトークンを受け取るフローです。  
AuthServer は **API 専用サーバー**のため、ブラウザリダイレクトは行いません。認可コードは `POST /connect/authorize` の JSON レスポンスとして返されます。

```bash
# 1. authorization_code + PKCE でトークンを取得(認可コード取得とトークン交換を自動実行)
dotnet run -- token \
  --auth http://localhost:5080 \
  --grant authorization_code \
  --client-id test-webapp \
  --client-secret webapp-secret \
  --scope "openid profile email api.read" \
  --username alice \
  --password password

# 2. 取得したアクセストークンで保護 API を呼び出す
dotnet run -- api \
  --resource http://localhost:5180 \
  --path /api/protected

# 3. UserInfo エンドポイントでユーザー情報を取得する
dotnet run -- userinfo \
  --auth http://localhost:5080

# 4. リフレッシュトークンでアクセストークンを更新する
dotnet run -- refresh \
  --auth http://localhost:5080 \
  --client-id test-webapp \
  --client-secret webapp-secret

# 5. 再更新後にもう一度 API を呼び出す
dotnet run -- api \
  --resource http://localhost:5180 \
  --path /api/protected
```

#### ユースケース 2: M2M 通信(client_credentials)

サーバー間通信のように、ユーザーを介さずクライアントがアクセストークンを取得して保護 API を呼び出す最もシンプルなフローです。

```bash
# 1. Discovery ドキュメントでサーバー設定を確認(任意)
dotnet run -- discovery --auth http://localhost:5080

# 2. client_credentials グラントでアクセストークンを取得
dotnet run -- token \
  --auth http://localhost:5080 \
  --grant client_credentials \
  --client-id test-client \
  --client-secret test-secret \
  --scope "api.read api.write"

# 3. 取得したトークンで保護 API を呼び出す
dotnet run -- api \
  --resource http://localhost:5180 \
  --path /api/protected \
  --method GET

# 4. トークンのメタ情報を確認する(未実装: Phase 4)
dotnet run -- introspect \
  --auth http://localhost:5080 \
  --client-id test-client \
  --client-secret test-secret

# 5. 使い終わったらトークンを失効させる(未実装: Phase 4)
dotnet run -- revoke \
  --auth http://localhost:5080 \
  --client-id test-client \
  --client-secret test-secret
```

#### ユースケース 3: カスタム AuthServer / ResourceServer を指定する

デフォルト以外のサーバーを使うときは各コマンドに `--auth` / `--resource` を指定します。

```bash
dotnet run -- token \
  --auth http://myauthserver:8080 \
  --client-id my-client \
  --client-secret my-secret \
  --scope "api.read"

dotnet run -- api \
  --resource http://myresourceserver:8180 \
  --path /api/data
```

#### ユースケース 4: トークンファイルを明示的に指定する

複数のテスト環境を並行して扱うときは `--token-file` で保存先を分けます。

```bash
# 環境 A のトークンを取得して保存
dotnet run -- token \
  --auth http://localhost:5080 \
  --client-id test-client \
  --client-secret test-secret \
  --token-file /tmp/tokens-env-a.json

# 環境 A のトークンで API を呼び出す
dotnet run -- api \
  --resource http://localhost:5180 \
  --token-file /tmp/tokens-env-a.json
```

### 各コマンドのオプション一覧

#### `token`

| オプション | 短縮形 | デフォルト値 | 説明 |
|-----------|-------|------------|------|
| `--auth` | `-a` | `http://localhost:5080` | AuthServer の URL |
| `--grant` | `-g` | `client_credentials` | グラントタイプ (`client_credentials` \| `authorization_code`) |
| `--client-id` | — | `test-client` | クライアント ID |
| `--client-secret` | — | `test-secret` | クライアントシークレット |
| `--scope` | `-s` | `api.read api.write` | スコープ(スペース区切り) |
| `--username` | `-u` | — | ユーザー名(`authorization_code` グラント用) |
| `--password` | `-p` | — | パスワード(`authorization_code` グラント用) |
| `--token-file` | `-f` | `~/.testclient/tokens.json` | トークン保存先パス |

#### `api`

| オプション | 短縮形 | デフォルト値 | 説明 |
|-----------|-------|------------|------|
| `--resource` | `-r` | `http://localhost:5180` | ResourceServer の URL |
| `--path` | — | `/api/protected` | 呼び出す API パス |
| `--method` | `-m` | `GET` | HTTP メソッド (`GET` \| `POST` \| `PUT` \| `DELETE`) |
| `--token-file` | `-f` | `~/.testclient/tokens.json` | トークン読み込み元パス |

#### `refresh`

| オプション | 短縮形 | デフォルト値 | 説明 |
|-----------|-------|------------|------|
| `--auth` | `-a` | `http://localhost:5080` | AuthServer の URL |
| `--client-id` | — | `test-client` | クライアント ID |
| `--client-secret` | — | `test-secret` | クライアントシークレット |
| `--token-file` | `-f` | `~/.testclient/tokens.json` | トークンファイルパス |

#### `introspect` / `revoke`

| オプション | 短縮形 | デフォルト値 | 説明 |
|-----------|-------|------------|------|
| `--auth` | `-a` | `http://localhost:5080` | AuthServer の URL |
| `--client-id` | — | `test-client` | クライアント ID |
| `--client-secret` | — | `test-secret` | クライアントシークレット |
| `--token-file` | `-f` | `~/.testclient/tokens.json` | トークンファイルパス |

#### `userinfo` / `discovery`

| オプション | 短縮形 | デフォルト値 | 説明 |
|-----------|-------|------------|------|
| `--auth` | `-a` | `http://localhost:5080` | AuthServer の URL |
| `--token-file` | `-f` | `~/.testclient/tokens.json` | トークンファイルパス(`userinfo` のみ) |

### トークンの保存場所

取得したトークンは `~/.testclient/tokens.json` に保存されます。各コマンドはこのファイルを参照してトークンを利用します。

---

## AuthServer エンドポイント一覧

| エンドポイント | メソッド | 実装状況 | Phase | 概要 |
|--------------|---------|---------|-------|------|
| `/.well-known/openid-configuration` | GET | ✅ 実装済み | 1 | OIDC Discovery ドキュメントを返す |
| `/.well-known/jwks.json` | GET | ✅ 実装済み | 1 | JWT 署名検証用の公開鍵セット (JWKS) を返す |
| `/connect/token` | POST | ✅ 実装済み | 1〜2 | アクセストークン・ID Token・リフレッシュトークンを発行する(`client_credentials` / `authorization_code` / `refresh_token` グラント対応) |
| `/connect/authorize` | POST | ✅ 実装済み | 2 | ユーザー認証情報を受け取り認可コードを発行する(PKCE 対応・API 専用 JSON レスポンス) |
| `/connect/userinfo` | GET | ✅ 実装済み | 2 | Bearer トークンを持つユーザーのクレームを返す(OIDC UserInfo エンドポイント) |
| `/connect/revoke` | POST | 🔲 未実装 | 4 | アクセストークンまたはリフレッシュトークンを失効させる(RFC 7009) |
| `/connect/introspect` | POST | 🔲 未実装 | 4 | トークンのアクティブ状態・メタ情報を返す(RFC 7662) |
| `/connect/logout` | GET/POST | 🔲 未実装 | 4 | RP-Initiated Logout(セッション破棄) |
| `/connect/device_authorization` | POST | 🔲 未実装 | 5 | Device Authorization Grant の開始エンドポイント(RFC 8628) |
| `/connect/register` | POST | 🔲 未実装 | 5 | Dynamic Client Registration(RFC 7591) |

> **`/connect/authorize` の設計について**
> 本サーバーは API 専用サーバーとして実装しているため、`/connect/authorize` は
> 標準のブラウザリダイレクト方式(GET)ではなく、クライアントが資格情報を直接送信する
> POST 方式のみを提供しています。この方式ではユーザーのパスワードがクライアントを
> 経由するため、信頼モデルとしては ROPC 相当です。
> 標準方式との差異は `__spec.md` §6.3 を参照してください。

---

## 実装仕様と実装状況

### 準拠仕様と実装状況

本プロジェクトが対象とする仕様はすべて IETF RFC / OpenID Foundation の正式仕様です。

| 機能 | 仕様 | 普及度 | 実装状況 | Phase |
|------|------|--------|---------|-------|
| OpenID Provider Discovery | OIDC Discovery 1.0 | 事実上必須 | ✅ 実装済み | 1 |
| JWKS (公開鍵公開) | RFC 7517 | JWT 検証の標準 | ✅ 実装済み | 1 |
| Token Endpoint | RFC 6749 §3.2 | 必須 | ✅ 実装済み | 1 |
| client_credentials グラント | RFC 6749 §4.4 | M2M 通信の標準 | ✅ 実装済み | 1 |
| JWT アクセストークン (RS256) | RFC 7519 / RFC 7515 | 標準 | ✅ 実装済み | 1 |
| ResourceServer JWT Bearer 認証 | RFC 6750 | 標準 | ✅ 実装済み | 1 |
| スコープベースの認可 | RFC 6749 §3.3 | 標準 | ✅ 実装済み | 1 |
| ユーザー管理 UI (MudBlazor) | — | — | ✅ 実装済み | 2 |
| Authorization Endpoint (API 専用 POST) | RFC 6749 §3.1 | 必須 | ✅ 実装済み | 2 |
| Authorization Endpoint (標準リダイレクト GET) | RFC 6749 §3.1 | 現在の標準 | 🔲 未実装 | 2 |
| Authorization Code Flow | RFC 6749 §4.1 | 現在の標準フロー | 🟡 API 専用方式のみ | 2 |
| PKCE (S256) | RFC 7636 | 現在必須 | ✅ 実装済み | 2 |
| Refresh Token (ローテーションあり) | RFC 6749 §6 | 標準 | ✅ 実装済み | 2 |
| ID Token 生成 | OIDC Core 1.0 §2 | OIDC 必須 | 🟡 `at_hash` / `auth_time` / `amr` 未実装 | 2 |
| UserInfo エンドポイント | OIDC Core 1.0 §5.3 | OIDC 必須 | ✅ 実装済み | 2 |
| 同意画面 / 同意情報管理 | OIDC Core 1.0 §3.1.2 | 標準 | 🔲 未実装 | 3 |
| Token Revocation | RFC 7009 | 広く実装 | 🔲 未実装 | 4 |
| Token Introspection | RFC 7662 | 広く実装 | 🔲 未実装 | 4 |
| RP-Initiated Logout | OIDC RP-Logout 1.0 | 標準 | 🔲 未実装 | 4 |
| 鍵ローテーション | RFC 7517 | 推奨 | 🔲 未実装 | 4 |
| Device Authorization Grant | RFC 8628 | CLI/IoT 向け標準 | 🔲 未実装 | 5 |
| Dynamic Client Registration | RFC 7591 / 7592 | SaaS 向け標準 | 🔲 未実装 | 5 |

### spec 範囲外の拡張機能(実装予定なし / 参考)

| 機能 | 仕様 | 性格 |
|------|------|------|
| PAR (Pushed Authorization Request) | RFC 9126 | 最新セキュリティ強化 |
| DPoP (Proof of Possession) | RFC 9449 | 最新セキュリティ強化 |
| Request Object / JAR | RFC 9101 | 最新セキュリティ強化 |
| CIBA (Backchannel Authentication) | OpenID CIBA 1.0 | スマートフォン承認フロー |
| Pairwise Subject Types | OIDC Core §8 | プライバシー保護 |
| Front-Channel Logout | OIDC Front-Channel Logout 1.0 | セッション管理拡張 |
| Back-Channel Logout | OIDC Back-Channel Logout 1.0 | セッション管理拡張 |
| Resource Indicators | RFC 8707 | マイクロサービス向け |
| TOTP / MFA | RFC 6238 / 4226 | 認証強化 |
| Passkey / WebAuthn | W3C WebAuthn Level 2 | パスワードレス認証 |
| SAML 2.0 / WS-Federation | SAML 2.0 Core | レガシーエンタープライズ統合 |
| SCIM 2.0 | RFC 7642–7644 | ユーザープロビジョニング |
| LDAP 認証統合 | — | エンタープライズ統合 |
| 外部 IdP 連携 (ソーシャルログイン) | — | フェデレーション |
| 監査ログ | — | 運用・可観測性 |
