# experimental-auth

OAuth 2.0 / OpenID Connect 準拠の認証サーバーを .NET 10 でスクラッチ実装する学習プロジェクトです。

---

## システム構成

| コンポーネント | 種別 | フレームワーク | デフォルト URL |
|--------------|------|--------------|--------------|
| **AuthServer** | Web API + Web UI | .NET 10 Minimal API + Blazor Server | `http://localhost:5051` |
| **ResourceServer** | Web API | .NET 10 Minimal API | `http://localhost:5132` |
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

### 基本的な使用フロー

```bash
# 1. サーバー情報を確認
dotnet run -- discovery

# 2. アクセストークンを取得（client_credentials）
dotnet run -- token

# 3. 保護リソースへアクセス
dotnet run -- api
```

### token コマンドのオプション

| オプション | デフォルト値 | 説明 |
|-----------|------------|------|
| `--auth-server` | `http://localhost:5051` | AuthServer の URL |
| `--grant-type` | `client_credentials` | グラントタイプ |
| `--client-id` | `test-client` | クライアント ID |
| `--client-secret` | `test-secret` | クライアントシークレット |
| `--scope` | `api.read` | スコープ |

### api コマンドのオプション

| オプション | デフォルト値 | 説明 |
|-----------|------------|------|
| `--resource-server` | `http://localhost:5132` | ResourceServer の URL |
| `--endpoint` | `/api/protected` | 呼び出す API パス |

### トークンの保存場所

取得したトークンは `~/.testclient/tokens.json` に保存されます。各コマンドはこのファイルを参照してトークンを利用します。

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
| Authorization Endpoint | RFC 6749 §3.1 | 必須 | 🔲 未実装 | 2 |
| Authorization Code Flow | RFC 6749 §4.1 | 現在の標準フロー | 🔲 未実装 | 2 |
| PKCE | RFC 7636 | 現在必須 | 🔲 未実装 | 2 |
| Login 画面 (Blazor) | — | — | 🔲 未実装 | 2 |
| Refresh Token | RFC 6749 §6 | 標準 | 🔲 未実装 | 2 |
| ID Token 生成 | OIDC Core 1.0 §2 | OIDC 必須 | 🔲 未実装 | 3 |
| UserInfo エンドポイント | OIDC Core 1.0 §5.3 | OIDC 必須 | 🔲 未実装 | 3 |
| Consent 画面 (Blazor) | — | 推奨 | 🔲 未実装 | 3 |
| Token Revocation | RFC 7009 | 広く実装 | 🔲 未実装 | 4 |
| Token Introspection | RFC 7662 | 広く実装 | 🔲 未実装 | 4 |
| RP-Initiated Logout | OIDC RP-Logout 1.0 | 標準 | 🔲 未実装 | 4 |
| 鍵ローテーション | RFC 7517 | 推奨 | 🔲 未実装 | 4 |
| Device Authorization Grant | RFC 8628 | CLI/IoT 向け標準 | 🔲 未実装 | 5 |
| Dynamic Client Registration | RFC 7591 / 7592 | SaaS 向け標準 | 🔲 未実装 | 5 |

### spec 範囲外の拡張機能（実装予定なし / 参考）

`__spec.md` のスコープには含まれないが、他の実装で採用されている拡張機能です。  
詳細は [`__Other/FEATURE_ANALYSIS.md`](__Other/FEATURE_ANALYSIS.md) および [`ENHANCEMENT_ROADMAP.md`](ENHANCEMENT_ROADMAP.md) を参照してください。

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

---

## 参考ドキュメント

| ファイル | 内容 |
|---------|------|
| [`__spec.md`](__spec.md) | 実装仕様書（エンドポイント・ユースケース・フェーズ定義） |
| [`TODO.md`](TODO.md) | フェーズ別実装チェックリスト |
| [`__Other/FEATURE_ANALYSIS.md`](__Other/FEATURE_ANALYSIS.md) | 他実装との機能比較・差分分析 |
| [`ENHANCEMENT_ROADMAP.md`](ENHANCEMENT_ROADMAP.md) | 機能強化の優先順位ロードマップ |
