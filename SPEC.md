# 認証サーバー実装仕様書

## 1. 目的

OAuth 2.0 および OpenID Connect の仕様に準拠した認証サーバーを .NET 10.0 / C#（`LangVersion=preview`）でスクラッチ実装し、以下を達成する。

| # | 目的 |
|---|------|
| 1 | OAuth 2.0 / OIDC の認証・認可フローを実装を通じて深く理解する |
| 2 | JWT の発行・署名・検証の仕組みを実践的に学ぶ |
| 3 | 認証サーバー・リソースサーバー・クライアントの三者間の通信プロトコルを体得する |
| 4 | ASP.NET Core の認証ミドルウェアとの統合方法を理解する |

---

## 2. システム構成

### 2.1 コンポーネント一覧

| コンポーネント | 種別 | フレームワーク | 役割 |
|--------------|------|--------------|------|
| 認証サーバー (AuthServer) | Web API + Web UI | .NET 10.0 Minimal API + Blazor Server | トークン発行・ユーザー認証・認可判定・鍵公開・管理UI |
| リソースサーバー (ResourceServer) | Web API | .NET 10.0 Minimal API | 保護されたリソースの提供。JWT Bearer 認証で保護 |
| テストクライアント (TestClient) | CLI アプリ | .NET 10.0 Console | トークン取得・API 呼び出しの検証 |

### 2.2 認証サーバー内部構成

認証サーバーは単一のASP.NET Coreアプリケーション内に以下の2つの機能レイヤーを持つ。

| レイヤー | 技術 | 責務 |
|---------|------|------|
| API レイヤー | Minimal API | OAuth 2.0 / OIDC プロトコルエンドポイント（トークン発行、Discovery 等） |
| UI レイヤー | Blazor Server | ログイン画面、同意画面、デバイスコード入力画面、管理画面 |

```
┌─────────────────────────────────────────┐
│           AuthServer                     │
├─────────────────────────────────────────┤
│                                         │
│  ┌─────────────────┐  ┌──────────────┐ │
│  │  Minimal API     │  │ Blazor Server│ │
│  │                  │  │              │ │
│  │ /connect/token   │  │ /account/*   │ │
│  │ /connect/authorize│  │  - Login     │ │
│  │ /connect/userinfo│  │  - Consent   │ │
│  │ /connect/revoke  │  │  - Device    │ │
│  │ /connect/introspect│ │  - Manage   │ │
│  │ /.well-known/*   │  │              │ │
│  └────────┬─────────┘  └──────┬───────┘ │
│           │                    │         │
│           ▼                    ▼         │
│  ┌──────────────────────────────────────┐│
│  │         サービス層                    ││
│  │  TokenService / ClientService /      ││
│  │  UserService / KeyService / etc.     ││
│  └──────────────────┬───────────────────┘│
│                     ▼                    │
│  ┌──────────────────────────────────────┐│
│  │      データアクセス層 (Dapper)        ││
│  │          SQLite Database             ││
│  └──────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

### 2.3 データストア

| 項目 | 技術 | 説明 |
|------|------|------|
| RDBMS | SQLite | 軽量・ファイルベース・開発環境に最適 |
| ORM / データアクセス | Dapper | 軽量マッパー。SQL を直接記述し学習効果を高める |
| マイグレーション | 手動 SQL スクリプト | 起動時に自動適用 |

**永続化対象:**

| データ | テーブル名 | 説明 |
|--------|-----------|------|
| クライアント情報 | `clients` | client_id, client_secret_hash, redirect_uris, grant_types 等 |
| ユーザー情報 | `users` | user_id, username, password_hash, email, claims 等 |
| 認可コード | `authorization_codes` | code, client_id, user_id, scopes, code_challenge, expires_at |
| リフレッシュトークン | `refresh_tokens` | token_hash, client_id, user_id, scopes, expires_at, revoked |
| デバイスコード | `device_codes` | device_code, user_code, client_id, scopes, status, expires_at |
| 同意情報 | `consents` | user_id, client_id, scopes, granted_at |
| 失効トークン | `revoked_tokens` | jti, revoked_at, expires_at |
| 署名鍵 | `signing_keys` | kid, algorithm, private_key_pem, public_key_pem, created_at, is_active |
| リソースサーバー | `resource_servers` | resource_server_id, name, audience, description, is_active |
| マイグレーション | `schema_migrations` | version, applied_at |

### 2.4 アーキテクチャ図

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           全体構成                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────┐     ┌───────────────────┐     ┌──────────────────┐  │
│  │               │     │                   │     │                  │  │
│  │  TestClient   │────►│   AuthServer      │     │  ResourceServer  │  │
│  │  (CLI)        │◄────│   Minimal API     │     │  (Minimal API)   │  │
│  │               │     │   + Blazor Server │     │                  │  │
│  └───────┬───────┘     │   + SQLite/Dapper │     └────────┬─────────┘  │
│          │              └─────────┬─────────┘              │            │
│          │                        │                        │            │
│          │   Bearer Token         │   JWKS / Discovery     │            │
│          │───────────────────────────────────────────────► │            │
│          │◄───────────────────────────────────────────────│            │
│          │                        │◄───────────────────────│            │
│          │                        │───────────────────────►│            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.5 ポート構成（開発環境）

| コンポーネント | URL | 備考 |
|--------------|-----|------|
| AuthServer | `http://localhost:5080` | Issuer。API + Blazor UI |
| ResourceServer | `http://localhost:5180` | Authority = AuthServer。`aud` もこの値 |
| AppHost (Aspire ダッシュボード) | `http://localhost:15000` | オーケストレーション |
| TestClient | — | コンソールアプリ |

現状は開発利便性のため HTTP で構成しています。ResourceServer の `RequireHttpsMetadata` は
既定で `true` であり、`appsettings.Development.json` のみ `false` に下げています。
本番相当の設定では Authority を HTTPS にし、この上書きを行わないでください。

---

## 3. 準拠仕様

### 3.1 必須準拠仕様

| # | 仕様名 | 識別子 | 本実装での適用範囲 |
|---|--------|--------|------------------|
| 1 | The OAuth 2.0 Authorization Framework | RFC 6749 | 認可エンドポイント、トークンエンドポイント、グラントタイプ定義 |
| 2 | The OAuth 2.0 Authorization Framework: Bearer Token Usage | RFC 6750 | リソースサーバーでのトークン受け取り方法 |
| 3 | Proof Key for Code Exchange by OAuth Public Clients | RFC 7636 | Authorization Code Flow での PKCE 必須化 |
| 4 | JSON Web Token (JWT) | RFC 7519 | アクセストークン・ID トークンのフォーマット |
| 5 | JSON Web Signature (JWS) | RFC 7515 | トークン署名 |
| 6 | JSON Web Key (JWK) | RFC 7517 | 公開鍵の公開フォーマット |
| 7 | JSON Web Algorithms (JWA) | RFC 7518 | 署名アルゴリズム（RS256） |
| 8 | OpenID Connect Core 1.0 | OIDC Core 1.0 | ID Token 発行、UserInfo、認証フロー |
| 9 | OpenID Connect Discovery 1.0 | OIDC Discovery 1.0 | `.well-known/openid-configuration` |

### 3.2 任意準拠仕様

| # | 仕様名 | 識別子 | 本実装での適用範囲 |
|---|--------|--------|------------------|
| 10 | OAuth 2.0 Token Revocation | RFC 7009 | トークン失効エンドポイント |
| 11 | OAuth 2.0 Token Introspection | RFC 7662 | トークン検査エンドポイント |
| 12 | OAuth 2.0 Device Authorization Grant | RFC 8628 | CLI 向けデバイスフロー |
| 13 | OAuth 2.0 Dynamic Client Registration Protocol | RFC 7591 | クライアント動的登録 |
| 14 | OAuth 2.0 Dynamic Client Registration Management Protocol | RFC 7592 | クライアント管理 |
| 15 | OpenID Connect RP-Initiated Logout 1.0 | OIDC RP-Logout 1.0 | ログアウト |
| 16 | OpenID Connect Session Management 1.0 | OIDC Session 1.0 | セッション状態確認 |
| 17 | OpenID Connect Dynamic Client Registration 1.0 | OIDC DynReg 1.0 | OIDC 拡張のクライアント登録 |

---

## 4. エンドポイント一覧

### 4.1 一覧表

凡例: ✅ 実装済み / 🟡 一部実装 / 🔲 未実装 / ⏸ 現行設計では対象外

| # | カテゴリ | エンドポイント | パス | メソッド | 必須/任意 | 準拠仕様 | Phase | 実装 | 説明 |
|---|---------|--------------|------|---------|----------|---------|-------|------|------|
| E-01 | メタデータ | OpenID Provider Configuration | `/.well-known/openid-configuration` | GET | **必須** | OIDC Discovery §4 | 1 | ✅ | サーバーメタデータ公開 |
| E-02 | メタデータ | JWK Set | `/.well-known/jwks.json` | GET | **必須** | RFC 7517 | 1 | ✅ | 署名検証用公開鍵 |
| E-03 | トークン | Token Endpoint | `/connect/token` | POST | **必須** | RFC 6749 §3.2 | 1 | ✅ | トークン発行 |
| E-04 | 認可 | Authorization Endpoint | `/connect/authorize` | POST | **必須** | RFC 6749 §3.1, OIDC Core §3.1.2 | 2 | 🟡 | 認可コード発行。**API 専用方式のみ実装**（§6.3 参照）。標準のブラウザリダイレクト方式 (GET) は未実装 |
| E-05 | ユーザー情報 | UserInfo Endpoint | `/connect/userinfo` | GET | **必須**(OIDC) | OIDC Core §5.3 | 3 | ✅ | ユーザークレーム返却。POST 版は未実装 |
| E-06 | トークン管理 | Token Revocation | `/connect/revoke` | POST | 任意(推奨) | RFC 7009 | 4 | ✅ | トークン失効。RT は `is_revoked`、AT は JTI を失効リストへ。ResourceServer は失効を参照しない（§6.5 方式 3） |
| E-07 | トークン管理 | Token Introspection | `/connect/introspect` | POST | 任意(推奨) | RFC 7662 | 4 | ✅ | トークン検査。認証済みクライアントは任意のトークンを検査可能 |
| E-08 | セッション | End Session (Logout) | `/connect/logout` | GET | 任意 | OIDC RP-Logout §2 | 4 | 🔲 | ログアウト |
| E-09 | デバイス | Device Authorization | `/connect/device/authorize` | POST | 任意 | RFC 8628 §3.1 | 5 | 🔲 | デバイスコード発行 |
| E-10 | クライアント管理 | Dynamic Registration | `/connect/register` | POST | 任意 | RFC 7591 | 5 | 🔲 | クライアント登録 |
| E-11 | クライアント管理 | Client Configuration | `/connect/register/{client_id}` | GET/PUT/DELETE | 任意 | RFC 7592 | 5 | 🔲 | クライアント管理 |
| E-12 | UI (Blazor) | Login | `/account/login` | — (Blazor) | 標準方式で必須 | — | 2 | ⏸ | ユーザー認証画面。API 専用方式では不要（§6.3 参照） |
| E-13 | UI (Blazor) | Consent | `/account/consent` | — (Blazor) | 任意(推奨) | — | 3 | 🔲 | スコープ同意画面 |
| E-14 | UI (Blazor) | Device Code Input | `/account/device` | — (Blazor) | 任意 | — | 5 | 🔲 | デバイスコード入力画面 |
| E-15 | UI (Blazor) | User Registration | `/account/register` | — (Blazor) | 任意 | — | 5 | 🔲 | ユーザー登録画面 |
| E-16 | UI (Blazor) | Password Change | `/account/password` | — (Blazor) | 任意 | — | 5 | 🔲 | パスワード変更画面 |
| E-17 | UI (Blazor) | Password Reset | `/account/password-reset` | — (Blazor) | 任意 | — | 5 | 🔲 | パスワードリセット画面 |
| E-18 | UI (Blazor) | Consent Management | `/account/consents` | — (Blazor) | 任意 | — | 5 | 🔲 | 同意管理画面 |

管理 UI として `/users`（ユーザー管理）と `/resource-servers`（リソースサーバー管理）を MudBlazor で実装済みです。これらは OAuth/OIDC のプロトコル面ではなく運用管理用のため、上表には含めていません。

### 4.2 Token Endpoint 対応 Grant Type

| # | grant_type | 必須/任意 | 準拠仕様 | Phase | 実装 | 説明 |
|---|-----------|----------|---------|-------|------|------|
| G-01 | `client_credentials` | **必須** | RFC 6749 §4.4 | 1 | ✅ | サーバー間認証 |
| G-02 | `authorization_code` | **必須** | RFC 6749 §4.1, RFC 7636 | 2 | ✅ | 認可コード交換（PKCE必須） |
| G-03 | `refresh_token` | **必須**(推奨) | RFC 6749 §6 | 2 | ✅ | トークンリフレッシュ（ローテーションあり） |
| G-04 | `urn:ietf:params:oauth:grant-type:device_code` | 任意 | RFC 8628 §3.4 | 5 | 🔲 | デバイスフロー |
| G-05 | `password` (ROPC) | 非推奨 | RFC 6749 §4.3 | — | 🔲 | セキュリティ上非推奨。grant_type としては実装しない（ただし現行の E-04 は資格情報を直接受け取るため、実質的に ROPC 相当の性質を持つ。§6.3 参照） |

---

## 5. ユースケース一覧

### 5.1 クライアント側ユースケース

クライアント（TestClient または外部アプリケーション）が実行するユースケース。

| # | ユースケース | 概要 | 使用エンドポイント | 前提条件 | Phase |
|---|------------|------|-------------------|---------|-------|
| UC-C01 | メタデータ取得 | 認証サーバーの構成情報を取得する | E-01 | なし | 1 |
| UC-C02 | Client Credentials でトークン取得 | クライアント自身の認証情報でアクセストークンを取得する | E-03 (G-01) | クライアント登録済み | 1 |
| UC-C03 | 保護リソースへのアクセス | Bearer トークンを付与してリソースサーバーの API を呼び出す | ResourceServer API | アクセストークン取得済み | 1 |
| UC-C04 | Authorization Code Flow 開始 | ブラウザ経由で認可コードを取得する | E-04 → E-12 → E-13 | クライアント登録済み、PKCE パラメータ生成 | 2 |
| UC-C05 | 認可コードをトークンに交換 | 取得した認可コードでトークンを取得する | E-03 (G-02) | 認可コード取得済み | 2 |
| UC-C06 | トークンリフレッシュ | リフレッシュトークンで新しいアクセストークンを取得する | E-03 (G-03) | リフレッシュトークン取得済み | 2 |
| UC-C07 | ユーザー情報取得 | ログインユーザーのプロフィール情報を取得する | E-05 | `openid` スコープ付きアクセストークン | 3 |
| UC-C08 | トークン失効要求 | 不要になったトークンを無効化する | E-06 | トークン保持 | 4 |
| UC-C09 | ログアウト | 認証サーバーのセッションを破棄する | E-08 | `id_token` 保持 | 4 |
| UC-C10 | デバイスフロー開始 | デバイスコードとユーザーコードを取得する | E-09 | クライアント登録済み | 5 |
| UC-C11 | デバイスフロー ポーリング | トークンエンドポイントをポーリングしてトークン取得を待つ | E-03 (G-04) | デバイスコード取得済み | 5 |
| UC-C12 | クライアント動的登録 | 新しいクライアントを認証サーバーに登録する | E-10 | 初期アクセストークン（任意） | 5 |
| UC-C13 | クライアント情報更新 | 登録済みクライアントの設定を変更する | E-11 (PUT) | registration_access_token | 5 |
| UC-C14 | クライアント削除 | クライアント登録を抹消する | E-11 (DELETE) | registration_access_token | 5 |
| UC-C15 | 同意済み一覧確認 | ユーザーが同意したクライアント・スコープを確認する | E-18 | ユーザー認証済み | 5 |
| UC-C16 | 同意取り消し | 特定クライアントへの同意を取り消す | E-18 | ユーザー認証済み | 5 |

### 5.2 サーバー側ユースケース

認証サーバーまたはリソースサーバーが内部で実行する処理。

| # | ユースケース | 概要 | 関連エンドポイント | 処理主体 | Phase |
|---|------------|------|-------------------|---------|-------|
| UC-S01 | JWT 署名鍵生成 | 起動時に RSA 鍵ペアを生成（または DB から読み込み）し、署名・検証に使用する | E-02 (公開鍵公開) | AuthServer | 1 |
| UC-S02 | JWT アクセストークン生成 | クレームを含む JWT を生成し署名する | E-03 | AuthServer | 1 |
| UC-S03 | クライアント認証 | `client_id` / `client_secret` によるクライアント認証を行う | E-03, E-06, E-07 | AuthServer | 1 |
| UC-S04 | Discovery メタデータ構築 | サーバー構成情報を JSON で構築して返却する | E-01 | AuthServer | 1 |
| UC-S05 | JWT 署名検証 | リソースサーバーが JWKS を取得し JWT の署名を検証する | E-01, E-02 | ResourceServer | 1 |
| UC-S06 | スコープ・クレーム検証 | JWT 内のスコープ・クレームに基づきアクセス制御を行う | — | ResourceServer | 1 |
| UC-S07 | ユーザー認証 | ユーザー名・パスワードを検証する | E-12 | AuthServer | 2 |
| UC-S08 | 認可コード生成・保存 | ランダムな認可コードを生成し、関連情報と共に DB に保存する | E-04 | AuthServer | 2 |
| UC-S09 | 認可コード検証・消費 | 認可コードの有効性を検証し、使用済みにする（リプレイ攻撃防止） | E-03 (G-02) | AuthServer | 2 |
| UC-S10 | PKCE 検証 | `code_verifier` と保存済み `code_challenge` を照合する | E-03 (G-02) | AuthServer | 2 |
| UC-S11 | リフレッシュトークン生成・保存 | Opaque なリフレッシュトークンを生成し DB に保存する | E-03 | AuthServer | 2 |
| UC-S12 | リフレッシュトークン検証・ローテーション | リフレッシュトークンの有効性を検証し、新しいものに置き換える | E-03 (G-03) | AuthServer | 2 |
| UC-S13 | ID Token 生成 | OIDC 仕様に基づく ID Token（JWT）を生成する | E-03, E-04 | AuthServer | 3 |
| UC-S14 | 同意情報管理 | ユーザーの同意状態を DB に保存・参照する | E-13, E-18 | AuthServer | 3 |
| UC-S15 | トークン失効処理 | 指定トークンを失効リストに追加する | E-06 | AuthServer | 4 |
| UC-S16 | トークン失効チェック | JWT 検証時に失効リストを確認する | — | AuthServer / ResourceServer | 4 |
| UC-S17 | トークンイントロスペクション | トークンのメタ情報を構築して返却する | E-07 | AuthServer | 4 |
| UC-S18 | 鍵ローテーション | 新しい署名鍵を生成し、旧鍵と共に JWKS で公開する。鍵は DB に永続化 | E-02 | AuthServer | 4 |
| UC-S19 | セッション管理 | ユーザーセッションの作成・破棄を管理する | E-08, E-12 | AuthServer | 4 |
| UC-S20 | デバイスコード生成・管理 | デバイスコード・ユーザーコードの生成とポーリング状態管理 | E-09, E-14 | AuthServer | 5 |
| UC-S21 | クライアント動的登録処理 | クライアント情報の検証・保存・credentials 発行 | E-10, E-11 | AuthServer | 5 |
| UC-S22 | ユーザー登録処理 | ユーザー情報の検証・パスワードハッシュ化・DB 保存 | E-15 | AuthServer | 5 |
| UC-S23 | パスワードリセット処理 | リセットトークン生成・検証・パスワード更新 | E-17 | AuthServer | 5 |

---

## 6. 実装順序・優先度

### 6.1 Phase 定義

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5
 最小動作    認可コード    OIDC準拠     運用機能      拡張機能
   ✅         🟡           🟡           🟡           🔲
```

**現在の実装状況:**

| Phase | 状態 | 内容 |
|-------|------|------|
| Phase 1 | ✅ 完了 | Discovery / JWKS / `client_credentials` / RS256 署名 / ResourceServer 連携 |
| Phase 2 | 🟡 一部完了 | 認可コード + PKCE(S256) + リフレッシュトークン（ローテーション込み）を **方式 B（API 専用）** で実装済み。標準のブラウザリダイレクト方式（方式 A）と `/account/login` は未実装（§6.3 参照） |
| Phase 3 | 🟡 一部完了 | ID Token（`nonce` / `auth_time` / `at_hash` / `amr`）と UserInfo、Discovery 拡張を実装済み。同意画面・同意情報管理は未実装（方式 A 前提） |
| Phase 4 | 🟡 一部完了 | 失効 / 検査 / 鍵ローテーション / クリーンアップ / マイグレーション機構を実装済み（M1）。ログアウト・セッションは方式 A 前提で未実装（M3） |
| Phase 5 | 🔲 未着手 | デバイスフロー / 動的登録 / ユーザー向け Blazor 画面群 |

進捗の詳細と残タスクは `TODO.md` を参照してください（§13）。

### 6.2 Phase 1: 最小動作構成

**目標**: CLI からトークンを取得し、リソースサーバーの保護 API にアクセスできる。

| 実装対象 | 種別 | 詳細 |
|---------|------|------|
| SQLite DB 初期化 | インフラ | スキーマ作成、初期クライアントデータ投入 |
| Dapper データアクセス層 | インフラ | クライアント情報の CRUD |
| RSA 鍵ペア生成・DB 永続化 | 内部処理 | 起動時に DB から読み込み、なければ生成して保存 |
| E-01 `/.well-known/openid-configuration` | エンドポイント | メタデータ返却 |
| E-02 `/.well-known/jwks.json` | エンドポイント | 公開鍵返却 |
| E-03 `/connect/token` (client_credentials) | エンドポイント | JWT アクセストークン発行 |
| UC-S01〜UC-S04 | 内部処理 | 鍵生成、トークン生成、クライアント認証、Discovery |
| UC-S05〜UC-S06 | ResourceServer | JWT 検証、スコープ検証 |
| ResourceServer 保護 API | エンドポイント | `GET /api/protected` |
| TestClient | CLI | client_credentials フロー実装 |

**Phase 1 完了時のフロー:**

```
TestClient                    AuthServer                   ResourceServer
    │                              │                              │
    │ GET /openid-configuration    │                              │
    │─────────────────────────────►│                              │
    │◄─────────────────────────────│                              │
    │                              │                              │
    │ POST /connect/token          │                              │
    │ grant_type=client_credentials│                              │
    │ client_id=xxx                │                              │
    │ client_secret=yyy            │                              │
    │ scope=api.read               │                              │
    │─────────────────────────────►│                              │
    │◄── { access_token (JWT) } ───│                              │
    │                              │                              │
    │ GET /api/protected                                          │
    │ Authorization: Bearer {JWT}                                 │
    │────────────────────────────────────────────────────────────►│
    │                              │  GET /openid-configuration   │
    │                              │◄─────────────────────────────│
    │                              │─────────────────────────────►│
    │                              │  GET /jwks.json              │
    │                              │◄─────────────────────────────│
    │                              │─────────────────────────────►│
    │◄──────────────────────────── 200 OK { data } ──────────────│
```

### 6.3 Phase 2: Authorization Code Flow + PKCE

**目標**: ユーザー認証を伴う認可コードフローが動作する。

本フェーズには **方式 A（標準・ブラウザリダイレクト）** と **方式 B（API 専用）** の 2 つの実現方法があり、
**現在は方式 B のみ実装済み**です。方式 A は将来の実装対象として残します。

| 実装対象 | 種別 | 方式 | 実装 | 詳細 |
|---------|------|------|------|------|
| users テーブル・データアクセス | インフラ | 共通 | ✅ | ユーザー CRUD、パスワードハッシュ検証 |
| authorization_codes テーブル | インフラ | 共通 | ✅ | 認可コードの保存・取得・削除 |
| refresh_tokens テーブル | インフラ | 共通 | ✅ | リフレッシュトークンの保存・取得・更新 |
| E-04 `/connect/authorize` (POST) | エンドポイント | B | ✅ | パラメータ検証、PKCE、資格情報検証、認可コードを JSON 返却 |
| E-04 `/connect/authorize` (GET) | エンドポイント | A | 🔲 | パラメータ検証、PKCE、ログインへリダイレクト |
| E-12 `/account/login` (Blazor) | UI | A | 🔲 | ユーザー名・パスワード認証画面 |
| E-03 `/connect/token` (authorization_code) | エンドポイント | 共通 | ✅ | 認可コード → トークン交換、PKCE 検証 |
| E-03 `/connect/token` (refresh_token) | エンドポイント | 共通 | ✅ | リフレッシュトークンでのトークン再発行 |
| UC-S07〜UC-S12 | 内部処理 | 共通 | ✅ | ユーザー認証、認可コード、PKCE、リフレッシュトークン |

#### 方式 A: 標準のブラウザリダイレクト方式（未実装・将来対象）

RFC 6749 §4.1 / OIDC Core §3.1 に沿った本来のフローです。ユーザーの資格情報が
クライアントを一切経由しない点が本質で、これが Authorization Code Flow を
ROPC より安全にしている理由です。学習目的としてはこちらの実装価値が高く、
`TODO.md` の「仕様と実装の乖離」に計上しています。

#### 方式 B: API 専用方式（実装済み）

AuthServer を純粋な API サーバーとして扱うため、ブラウザリダイレクトを行わず
`POST /connect/authorize` でクライアントが `username` / `password` を直接送信し、
認可コードを JSON レスポンスで受け取ります。

```
POST /connect/authorize
  response_type=code & client_id & redirect_uri & scope
  & code_challenge & code_challenge_method=S256
  & nonce & state
  & username & password
→ 200 { "code": "...", "state": "..." }
```

検証内容は方式 A と共通です（`redirect_uri` の登録済み完全一致、スコープの許可判定、
`code_challenge_method` は S256 必須、認可コードは 120 秒・ワンタイム）。

> **設計上の注意**
> 方式 B はクライアントがユーザーのパスワードを取り扱うため、資格情報の流れとしては
> ROPC (G-05) と同等であり、認可コードと PKCE を挟んでも本質的な信頼モデルは
> 方式 A と異なります。フェデレーションや外部 IdP 連携、`prompt` パラメーター、
> 同意画面（E-13）は方式 B のままでは成立しません。
> 学習目的（§1）を満たすには方式 A の実装が必要です。

**方式 A のフロー（未実装・目標形）:**

```
User/Browser        TestClient         AuthServer              ResourceServer
     │                  │                   │                        │
     │                  │ GET /connect/authorize                     │
     │                  │ ?response_type=code                        │
     │                  │ &client_id=xxx                             │
     │                  │ &redirect_uri=http://localhost:5173/callback│
     │                  │ &scope=openid api.read                     │
     │                  │ &state=abc                                 │
     │                  │ &code_challenge=xxx                        │
     │                  │ &code_challenge_method=S256                │
     │  ◄───────────────│──────────────────►│                        │
     │                  │                   │                        │
     │  302 → /account/login               │                        │
     │  ◄───────────────────────────────────│                        │
     │                  │                   │                        │
     │  [Blazor Server ログイン画面]         │                        │
     │  username / password 入力            │                        │
     │  ─────────────────────────────────── ►│                        │
     │                  │                   │  認証成功               │
     │                  │                   │  認可コード生成・DB保存  │
     │  302 → redirect_uri?code=yyy&state=abc                       │
     │  ◄───────────────────────────────────│                        │
     │                  │                   │                        │
     │                  │ POST /connect/token                        │
     │                  │ grant_type=authorization_code              │
     │                  │ code=yyy                                   │
     │                  │ code_verifier=zzz                          │
     │                  │ redirect_uri=http://localhost:5173/callback │
     │                  │──────────────────►│                        │
     │                  │                   │  認可コード検証         │
     │                  │                   │  PKCE検証              │
     │                  │                   │  認可コード消費(DB削除)  │
     │                  │◄──────────────────│                        │
     │                  │ { access_token, refresh_token, id_token }  │
     │                  │                   │                        │
```

**方式 B のフロー（実装済み・現行動作）:**

```
TestClient                     AuthServer                 ResourceServer
    │                              │                            │
    │ POST /connect/authorize      │                            │
    │ response_type=code           │                            │
    │ client_id=test-webapp        │                            │
    │ redirect_uri=...             │                            │
    │ scope=openid profile email api.read                       │
    │ code_challenge=xxx           │                            │
    │ code_challenge_method=S256   │                            │
    │ nonce=n-0S6_WzA2Mj           │                            │
    │ username=alice & password=***│                            │
    │─────────────────────────────►│                            │
    │                              │  クライアント検証           │
    │                              │  redirect_uri 完全一致      │
    │                              │  スコープ許可判定           │
    │                              │  ユーザー認証(PBKDF2)       │
    │                              │  認可コード生成・DB保存      │
    │◄─────────────────────────────│                            │
    │ 200 { "code": "yyy", "state": "abc" }                     │
    │                              │                            │
    │ POST /connect/token          │                            │
    │ grant_type=authorization_code│                            │
    │ code=yyy & code_verifier=zzz │                            │
    │ redirect_uri=...             │                            │
    │─────────────────────────────►│                            │
    │                              │  認可コード検証・消費        │
    │                              │  PKCE(S256)検証            │
    │                              │  redirect_uri 一致検証      │
    │◄─────────────────────────────│                            │
    │ { access_token, id_token, refresh_token }                 │
    │                              │                            │
    │ GET /api/protected  Authorization: Bearer {AT}            │
    │──────────────────────────────────────────────────────────►│
    │◄──────────────────────────────────────────────────────────│
```

ブラウザおよび User の関与がなく、資格情報が TestClient を経由する点が方式 A との差です。

### 6.4 Phase 3: OIDC 準拠

**目標**: OpenID Connect Core 1.0 の最低要件を満たす。

Phase 2 の実装に伴い、本フェーズの一部を先行実装済みです。

| 実装対象 | 種別 | 実装 | 詳細 |
|---------|------|------|------|
| consents テーブル・データアクセス | インフラ | 🔲 | 同意情報の保存・参照。テーブル定義のみ存在 |
| E-05 `/connect/userinfo` | エンドポイント | ✅ | `sub`, `name`, `email`, `email_verified` 等返却 |
| E-13 `/account/consent` (Blazor) | UI | 🔲 | スコープ同意画面。方式 B では成立しないため方式 A とセット |
| UC-S13 ID Token 生成 | 内部処理 | ✅ | `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `at_hash`, `amr` を実装 |
| UC-S14 同意情報管理 | 内部処理 | 🔲 | ユーザー×クライアント×スコープの同意状態 DB 管理 |
| Discovery メタデータ拡張 | エンドポイント | 🟡 | `userinfo_endpoint`, `scopes_supported`, `claims_supported`, `subject_types_supported` を反映。`response_modes_supported` は方式 A 実装後（§9 参照） |

**ID Token クレーム構成（目標形）:**

```json
{
  "iss": "http://localhost:5080",
  "sub": "user123",
  "aud": "client_app",
  "exp": 1700000000,
  "iat": 1699996400,
  "auth_time": 1699996400,
  "nonce": "n-0S6_WzAq",
  "at_hash": "xxx",
  "amr": ["pwd"]
}
```

**ID Token クレーム構成（現在の実装）:**

```json
{
  "iss": "http://localhost:5080",
  "aud": "test-webapp",
  "sub": "user-001",
  "exp": 1788591415,
  "iat": 1788587815,
  "nbf": 1788587815,
  "auth_time": 1788587815,
  "jti": "0616a0146d1c4ec9b9c2e1368a0ad442",
  "azp": "test-webapp",
  "nonce": "n-0S6_WzA2Mj",
  "amr": ["pwd"],
  "at_hash": "_Nn9OuewiQxGLPTojmiiDg",
  "name": "Alice Tester",
  "given_name": "Alice",
  "family_name": "Tester",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "email_verified": true
}
```

目標形との対応:

- `auth_time` は認可コードの `created_at`（方式 B では資格情報検証の直後に発行するため認証時刻と一致）
- `at_hash` はアクセストークンの SHA-256 左 128bit を base64url 化（RS256 のため）
- `amr` は方式 B がパスワード認証のみのため `["pwd"]` 固定
- 有効期限は `AuthServer:IdTokenLifetimeSeconds`（既定 3600 秒）で個別に設定可能
- 数値・真偽値・配列のクレームは `SecurityTokenDescriptor.Claims` 経由で型を保って出力（`ClaimsIdentity` 経由では文字列化される）

**Phase 3 完了時の追加フロー:**

```
TestClient                    AuthServer
    │                              │
    │ GET /connect/userinfo        │
    │ Authorization: Bearer {AT}   │
    │─────────────────────────────►│
    │                              │  トークン検証
    │                              │  スコープ確認 (openid, profile, email)
    │                              │  DBからユーザー情報取得
    │◄─────────────────────────────│
    │ {                            │
    │   "sub": "user123",          │
    │   "name": "山田 太郎",        │
    │   "email": "taro@example.com",│
    │   "email_verified": true     │
    │ }                            │
```

**同意フロー（Authorization Code Flow に組み込み）:**

```
User/Browser                          AuthServer
     │                                     │
     │  [ログイン成功後]                     │
     │                                     │  同意済みか DB 確認
     │                                     │  → 未同意の場合
     │  302 → /account/consent             │
     │  ◄─────────────────────────────────│
     │                                     │
     │  [Blazor Server 同意画面]            │
     │  "client_app が以下の権限を要求しています"│
     │  ☑ プロフィール情報の読み取り          │
     │  ☑ メールアドレスの読み取り            │
     │  [許可] [拒否]                       │
     │                                     │
     │  許可ボタン押下                       │
     │  ─────────────────────────────────► │
     │                                     │  同意情報を DB に保存
     │                                     │  認可コード生成
     │  302 → redirect_uri?code=yyy&state=abc│
     │  ◄─────────────────────────────────│
```

### 6.5 Phase 4: 運用機能

**目標**: トークンの失効・検査・ログアウト・鍵ローテーションなど、本番運用に必要な機能を実装する。

前半（トークンライフサイクル: マイルストーン M1）を実装済みです。ログアウトとセッション管理は方式 A（M3）が前提のため未実装です。

| 実装対象 | 種別 | 実装 | 詳細 |
|---------|------|------|------|
| revoked_tokens テーブル・データアクセス | インフラ | ✅ | `RevokedTokenService`。失効したアクセストークンの JTI を保存・照合 |
| signing_keys テーブル拡張 | インフラ | ✅ | 現用 / 猶予期間 / 退役の 3 状態を `is_active` と `expires_at` で表現 |
| スキーママイグレーション機構 | インフラ | ✅ | `schema_migrations` で適用済みバージョンを管理。v1: `authorization_codes.consumed_at`、v2: `refresh_tokens.source_code_hash` |
| E-06 `/connect/revoke` | エンドポイント | ✅ | `token` + `token_type_hint`。無効・未知・他クライアントのトークンでも 200（存在を漏らさない） |
| E-07 `/connect/introspect` | エンドポイント | ✅ | `active`, `token_type`, `client_id`, `sub`, `scope`, `aud`, `iss`, `jti`, `iat`, `nbf`, `exp`（+ `username`） |
| E-08 `/connect/logout` | エンドポイント | 🔲 | 方式 A 前提（M3） |
| UC-S15 トークン失効処理 | 内部処理 | ✅ | RT は `is_revoked`、AT は JTI を `revoked_tokens` に登録 |
| UC-S16 トークン失効チェック | 内部処理 | ✅ | AuthServer 内（UserInfo / Introspection）で照合。ResourceServer は照合しない（方式 3） |
| UC-S17 イントロスペクション | 内部処理 | ✅ | JWT（アクセストークン）と参照型（リフレッシュトークン）の両対応 |
| UC-S18 鍵ローテーション | 内部処理 | ✅ | 管理画面 `/signing-keys` から手動、または `SigningKeyRotationDays` で自動。旧鍵は猶予期間中 JWKS に公開 |
| UC-S19 セッション管理 | 内部処理 | 🔲 | 方式 A 前提（M3） |
| 期限切れデータのクリーンアップ | 内部処理 | ✅ | `MaintenanceService` が `MaintenanceIntervalMinutes` ごとに認可コード・RT・失効リストを削除し、猶予期間切れの鍵を退役 |

#### アクセストークン失効の反映範囲（方式 3）

アクセストークンは自己完結型の JWT のため、失効を即時に反映するには ResourceServer 側が失効リストを参照する必要があります。
本プロジェクトでは次の 3 案から **方式 3** を採用しました。

| 方式 | 内容 | 採否 |
|------|------|------|
| 1 | ResourceServer が毎回（またはキャッシュ付きで）`/connect/introspect` を呼ぶ | 不採用。RS が AS に依存し、JWT のオフライン検証の利点を失う |
| 2 | ResourceServer が JTI 失効リストを定期取得する | 不採用。同期遅延があり、実装コストに対する利点が小さい |
| 3 | AT の失効は即時反映しない（RFC 7009 §2 も許容）。RT を確実に失効させ、AT は短寿命で対処 | **採用** |

したがって、失効済みアクセストークンは AuthServer 自身のエンドポイント（UserInfo / Introspection）では拒否されますが、
ResourceServer では有効期限まで受理されます。`AccessTokenLifetimeSeconds`（既定 3600 秒）が失効の反映遅延の上限になります。

**トークン失効フロー（方式 3）:**

```
TestClient              AuthServer                          ResourceServer
    │                       │                                   │
    │ POST /connect/revoke  token=RT  hint=refresh_token        │
    │──────────────────────►│ refresh_tokens.is_revoked = 1     │
    │◄──────────────────────│ 200 OK                            │
    │                       │                                   │
    │ POST /connect/revoke  token=AT  hint=access_token         │
    │──────────────────────►│ JWT 検証 → jti を revoked_tokens へ │
    │◄──────────────────────│ 200 OK                            │
    │                       │                                   │
    │ POST /connect/introspect  token=AT                        │
    │──────────────────────►│ 検証 OK → 失効リスト照合 → 該当     │
    │◄──────────────────────│ { "active": false }               │
    │                       │                                   │
    │ GET /connect/userinfo  Authorization: Bearer AT           │
    │──────────────────────►│ 失効リスト照合                     │
    │◄──────────────────────│ 401 invalid_token (revoked)       │
    │                       │                                   │
    │ GET /api/protected  Authorization: Bearer AT              │
    │──────────────────────────────────────────────────────────►│ 署名・有効期限のみ検証
    │◄──────────────────────────────────────────────────────────│ 200 OK（有効期限まで受理）
```

**認可コード再使用・リフレッシュトークンリプレイ時のファミリー失効（SEC-04）:**

```
[認可コード再使用]
  code C を交換 → RT1 発行 (refresh_tokens.source_code_hash = hash(C))
  code C を再提示 → consumed_at あり = Reused
      → source_code_hash = hash(C) の RT をすべて is_revoked = 1
      → invalid_grant

[リフレッシュトークンリプレイ]
  RT1 を提示 → RT2 発行。RT1 は is_revoked = 1, replaced_by_token_hash = hash(RT2)
  RT1 を再提示 → is_revoked かつ replaced_by あり = ローテーション後の旧トークンの再利用
      → 同じ source_code_hash の RT (RT2 を含む) をすべて is_revoked = 1
      → invalid_grant
```

**鍵ローテーションフロー:**

```
AuthServer (内部)                                        ResourceServer
    │                                                         │
    │  [ローテーション: 管理画面 /signing-keys または自動]       │
    │  1. 新 RSA 鍵ペア生成 (kid=key-2), is_active=1           │
    │  2. 旧鍵 (key-1) に expires_at = now + 猶予期間           │
    │     ※ is_active は 1 のまま (猶予期間)                   │
    │  3. JWKS に新旧両方を公開 (Cache-Control: max-age)        │
    │     { "keys": [ key-2, key-1 ] }                         │
    │                                                         │  key-2 で署名された JWT を受信
    │                                                         │  → キャッシュ済み JWKS に kid 無し
    │                                                         │  → この要求は 401 にし、JWKS 再取得を予約
    │  GET /.well-known/jwks.json                              │    (ASP.NET Core JwtBearer の既定動作)
    │◄────────────────────────────────────────────────────────│
    │                                                         │  次の要求から key-2 の JWT を検証成功
    │                                                         │  key-1 の JWT も猶予期間中は検証成功
    │  [猶予期間経過後: MaintenanceService]                     │
    │  4. key-1 を is_active=0 (退役)。JWKS から消える           │
```

`JwksCacheMaxAgeSeconds`（既定 3600 秒）は猶予期間 `SigningKeyGraceDays`（既定 7 日）より十分短くしてください。
キャッシュが猶予期間を越えると、退役済みの鍵で署名されたトークンを検証しようとする ResourceServer が現れます。

ASP.NET Core の JwtBearer は、未知の `kid` を受けた要求そのものは失敗させ（401）、JWKS の再取得を予約してから
次の要求で新鍵を使います。実測でもローテーション直後の最初の 1 要求だけが 401 になり、以降は 200 でした。
これを避けるには、新鍵を先に JWKS へ公開しておき、`JwksCacheMaxAgeSeconds` の経過後に署名鍵を切り替える
2 段階ローテーション（事前公開）が必要です。`TODO.md` の M2 候補に挙げています。

### 6.6 Phase 5: 拡張機能

**目標**: デバイスフロー・動的クライアント登録・ユーザー管理など、発展的な機能を実装する。

| 実装対象 | 種別 | 詳細 |
|---------|------|------|
| device_codes テーブル・データアクセス | インフラ | デバイスコードの保存・状態管理 |
| E-09 `/connect/device/authorize` | エンドポイント | `device_code`, `user_code`, `verification_uri`, `interval` 返却 |
| E-14 `/account/device` (Blazor) | UI | ユーザーコード入力・認証画面 |
| E-03 `/connect/token` (device_code) | エンドポイント | ポーリング応答 |
| E-10 `/connect/register` | エンドポイント | クライアント動的登録 |
| E-11 `/connect/register/{client_id}` | エンドポイント | クライアント情報 CRUD |
| E-15 `/account/register` (Blazor) | UI | ユーザー新規登録 |
| E-16 `/account/password` (Blazor) | UI | パスワード変更 |
| E-17 `/account/password-reset` (Blazor) | UI | パスワードリセット |
| E-18 `/account/consents` (Blazor) | UI | 同意管理 |
| UC-S20〜UC-S23 | 内部処理 | デバイスコード管理、クライアント登録、ユーザー管理 |

**Phase 5 デバイスフロー完全シーケンス:**

```
User/Browser     CLI App              AuthServer
     │              │                      │
     │              │ POST /connect/device/authorize
     │              │ client_id=cli_app     │
     │              │ scope=openid api.read │
     │              │─────────────────────►│
     │              │                      │  device_codes テーブルに INSERT
     │              │◄─────────────────────│
     │              │ {                    │
     │              │  "device_code": "DC-xxx",
     │              │  "user_code": "ABCD-EFGH",
     │              │  "verification_uri": "http://localhost:5080/account/device",
     │              │  "verification_uri_complete": "http://localhost:5080/account/device?user_code=ABCD-EFGH",
     │              │  "expires_in": 600,  │
     │              │  "interval": 5       │
     │              │ }                    │
     │              │                      │
     │  [CLI画面表示]│                      │
     │  "以下のURLにアクセスしてコードを入力してください"
     │  "URL: http://localhost:5080/account/device"
     │  "コード: ABCD-EFGH"               │
     │              │                      │
     │  ブラウザでアクセス                   │
     │──────────────────────────────────── ►│
     │              │                      │  [Blazor Server デバイスコード入力画面]
     │◄────────────────────────────────────│
     │  コード入力 + ログイン               │
     │──────────────────────────────────── ►│
     │              │                      │  認証・認可処理
     │              │                      │  device_codes テーブル UPDATE
     │              │                      │  (status = authorized)
     │◄──────── 「認証完了」画面 ───────────│
     │              │                      │
     │              │ POST /connect/token   │
     │              │ grant_type=urn:ietf:params:oauth:grant-type:device_code
     │              │ device_code=DC-xxx    │
     │              │ client_id=cli_app     │
     │              │─────────────────────►│  (ポーリング1回目)
     │              │                      │  DB確認: status=pending
     │              │◄─────────────────────│
     │              │ {"error":"authorization_pending"}
     │              │                      │
     │              │  ... interval 秒待機 ...
     │              │                      │
     │              │ POST /connect/token   │  (ポーリングN回目)
     │              │─────────────────────►│
     │              │                      │  DB確認: status=authorized
     │              │◄─────────────────────│
     │              │ {                    │
     │              │  "access_token": "...",
     │              │  "token_type": "Bearer",
     │              │  "expires_in": 3600, │
     │              │  "refresh_token": "...",
     │              │  "id_token": "..."   │
     │              │ }                    │
```

---

## 7. エラーレスポンス仕様

### 7.1 OAuth 2.0 標準エラーレスポンス（Token Endpoint）

| HTTP Status | error | 発生条件 |
|-------------|-------|---------|
| 400 | `invalid_request` | 必須パラメータ不足、不正なパラメータ |
| 400 | `invalid_client` | クライアント認証失敗 |
| 400 | `invalid_grant` | 認可コード無効、リフレッシュトークン期限切れ |
| 400 | `unauthorized_client` | クライアントに許可されていない grant_type |
| 400 | `unsupported_grant_type` | サポートしていない grant_type |
| 400 | `invalid_scope` | 不正なスコープ |
| 400 | `authorization_pending` | デバイスフロー：ユーザー未認証 |
| 400 | `slow_down` | デバイスフロー：ポーリング間隔短すぎ |
| 400 | `expired_token` | デバイスフロー：デバイスコード期限切れ |
| 400 | `access_denied` | デバイスフロー：ユーザーが拒否 |

**エラーレスポンス形式:**

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired.",
  "error_uri": "https://tools.ietf.org/html/rfc6749#section-5.2"
}
```

### 7.2 Authorization Endpoint エラー

| 条件 | 処理 |
|------|------|
| `redirect_uri` 不正 or 未登録 | エラー画面表示（リダイレクトしない） |
| `client_id` 不正 | エラー画面表示（リダイレクトしない） |
| その他のエラー | `redirect_uri` にエラーパラメータ付きでリダイレクト |

**リダイレクトエラー形式:**

```
https://client.example.com/callback
  ?error=access_denied
  &error_description=The+resource+owner+denied+the+request
  &state=abc
```

### 7.3 リソースサーバーエラー（RFC 6750）

| HTTP Status | WWW-Authenticate | 条件 |
|-------------|-----------------|------|
| 401 | `Bearer` | トークン未提供 |
| 401 | `Bearer error="invalid_token"` | トークン期限切れ・署名不正。失効は反映されない（§6.5 方式 3） |
| 403 | `Bearer error="insufficient_scope", scope="api.write"` | スコープ不足 |

---

## 8. セキュリティ要件

### 8.1 必須セキュリティ対策

| # | 対策 | 対象 | 実装 | 詳細 |
|---|------|------|------|------|
| SEC-01 | HTTPS 必須 | 全通信 | 🔲 | 開発環境でも自己署名証明書で TLS を使用。現在は HTTP 構成（§2.5）。ResourceServer の `RequireHttpsMetadata` は既定 `true`（Development のみ `false`） |
| SEC-02 | PKCE 必須 | Authorization Code Flow | ✅ | S256 のみ許可。`code_challenge` 省略時はエラー |
| SEC-03 | state パラメータ検証 | Authorization Endpoint | ✅ | CSRF 防止。サーバーは `state` を認可コードと共に保存し応答で返却、TestClient が送信値との一致を検証（RFC 6749 §10.12 の役割分担どおり） |
| SEC-04 | 認可コード一回限り使用 | Token Endpoint | ✅ | `consumed_at` で消費済みを記録。再提示時はそのコードから派生した RT ファミリー（`source_code_hash`）をすべて失効。ローテーション後の旧 RT の再提示も同様にファミリー失効 |
| SEC-05 | redirect_uri 完全一致検証 | Authorization Endpoint | ✅ | 登録済み URI との完全一致。トークン交換時にも再照合 |
| SEC-06 | パスワードハッシュ化 | ユーザー管理 | ✅ | PBKDF2-SHA256 / 60 万回反復 + `FixedTimeEquals` |
| SEC-07 | トークン有効期限 | JWT | 🟡 | 実装値: アクセストークン 1 時間 (3600 秒)、**リフレッシュトークン 1 日 (86400 秒)**、**認可コード 2 分 (120 秒)**。当初仕様（30 日 / 10 分）とは異なる |
| SEC-08 | 暗号学的乱数使用 | コード・トークン生成 | ✅ | `RandomNumberGenerator.GetBytes(32)` を使用 |
| SEC-09 | レート制限 | Token Endpoint, Login | 🔲 | ブルートフォース防止。未実装 |
| SEC-10 | CORS 制限 | 全エンドポイント | 🔲 | 許可オリジンを明示的に設定。未実装 |

認可コード・リフレッシュトークンはいずれも SHA-256 ハッシュ（小文字 16 進）で保存し、
平文は DB に残しません。リフレッシュトークンはローテーション時に旧トークンを失効させ、
`replaced_by_token_hash` で追跡します。アクセストークンの失効は `revoked_tokens` に JTI を登録して表現し、
AuthServer 自身のエンドポイント（UserInfo / Introspection）で照合します。ResourceServer はオフライン検証のみのため、
アクセストークンの失効は有効期限まで反映されません（§6.5 方式 3）。

### 8.2 JWT クレーム構成

**アクセストークン:**

```json
{
  "iss": "http://localhost:5080",
  "sub": "user123",
  "aud": "http://localhost:5180",
  "exp": 1700000000,
  "iat": 1699996400,
  "nbf": 1699996400,
  "jti": "unique-token-id",
  "client_id": "test-client",
  "scope": "openid profile api.read"
}
```

**JWT ヘッダー:**

```json
{
  "alg": "RS256",
  "typ": "at+jwt",
  "kid": "key-1"
}
```

---

## 9. Discovery メタデータ完全定義

### 9.1 現在の実装

`GET /.well-known/openid-configuration` の実際のレスポンス（`Endpoints/DiscoveryEndpoint.cs`）:

```json
{
  "issuer": "http://localhost:5080",
  "authorization_endpoint": "http://localhost:5080/connect/authorize",
  "token_endpoint": "http://localhost:5080/connect/token",
  "userinfo_endpoint": "http://localhost:5080/connect/userinfo",
  "jwks_uri": "http://localhost:5080/.well-known/jwks.json",
  "revocation_endpoint": "http://localhost:5080/connect/revoke",
  "introspection_endpoint": "http://localhost:5080/connect/introspect",
  "grant_types_supported": [
    "client_credentials", "authorization_code", "refresh_token"
  ],
  "response_types_supported": ["code"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post", "client_secret_basic"
  ],
  "revocation_endpoint_auth_methods_supported": [
    "client_secret_post", "client_secret_basic"
  ],
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_post", "client_secret_basic"
  ],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": [
    "openid", "profile", "email", "api.read", "api.write"
  ],
  "code_challenge_methods_supported": ["S256"],
  "subject_types_supported": ["public"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "nbf", "jti", "azp", "nonce", "auth_time", "amr", "at_hash",
    "name", "given_name", "family_name", "preferred_username", "email", "email_verified"
  ],
  "request_uri_parameter_supported": false
}
```

未反映の項目: `device_authorization_endpoint`, `end_session_endpoint`, `registration_endpoint`,
`response_modes_supported`, `offline_access` スコープ。いずれも対応エンドポイントが未実装のためです。
`response_modes_supported` は方式 B（JSON 応答）に該当する標準値がないため、方式 A 実装時に追加します。
`request_uri_parameter_supported` は省略時の既定値が `true` のため、未対応を明示するために `false` を出力しています。

なお `authorization_endpoint` は POST 専用（§6.3 方式 B）であり、
標準の Authorization Code Flow を期待するクライアントとは互換性がありません。

### 9.2 全 Phase 完了時の目標

```json
{
  "issuer": "http://localhost:5080",
  "authorization_endpoint": "http://localhost:5080/connect/authorize",
  "token_endpoint": "http://localhost:5080/connect/token",
  "userinfo_endpoint": "http://localhost:5080/connect/userinfo",
  "jwks_uri": "http://localhost:5080/.well-known/jwks.json",
  "revocation_endpoint": "http://localhost:5080/connect/revoke",
  "introspection_endpoint": "http://localhost:5080/connect/introspect",
  "device_authorization_endpoint": "http://localhost:5080/connect/device/authorize",
  "end_session_endpoint": "http://localhost:5080/connect/logout",
  "registration_endpoint": "http://localhost:5080/connect/register",
  "scopes_supported": [
    "openid", "profile", "email", "offline_access", "api.read", "api.write"
  ],
  "response_types_supported": [
    "code", "id_token", "id_token token", "code id_token"
  ],
  "response_modes_supported": [
    "query", "fragment", "form_post"
  ],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic", "client_secret_post"
  ],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "auth_time",
    "nonce", "name", "email", "email_verified"
  ],
  "code_challenge_methods_supported": ["S256"],
  "revocation_endpoint_auth_methods_supported": [
    "client_secret_basic", "client_secret_post"
  ],
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_basic", "client_secret_post"
  ]
}
```

---

## 10. データベーススキーマ

### 10.1 テーブル定義

```sql
-- クライアント情報
CREATE TABLE clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT,
    client_name TEXT NOT NULL,
    grant_types TEXT NOT NULL,          -- JSON array
    redirect_uris TEXT,                 -- JSON array
    scopes TEXT NOT NULL,               -- スペース区切り
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post',
    post_logout_redirect_uris TEXT,     -- JSON array
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ユーザー情報
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    resource_server_id TEXT NOT NULL REFERENCES resource_servers(resource_server_id),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    name TEXT,
    given_name TEXT,
    family_name TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 認可コード
CREATE TABLE authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    nonce TEXT,
    state TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- リフレッシュトークン
CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    replaced_by_token_hash TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- デバイスコード
CREATE TABLE device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, authorized, denied, expired
    expires_at TEXT NOT NULL,
    last_polled_at TEXT,
    poll_interval INTEGER NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- 同意情報
CREATE TABLE consents (
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (client_id) REFERENCES clients(client_id)
);

-- 失効トークン
CREATE TABLE revoked_tokens (
    jti TEXT PRIMARY KEY,
    token_type TEXT NOT NULL,        -- access_token, refresh_token
    revoked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL          -- 期限切れ後にクリーンアップ可能
);

-- 署名鍵
CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL DEFAULT 'RS256',
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    expires_at TEXT
);

-- リソースサーバー
CREATE TABLE resource_servers (
    resource_server_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    audience TEXT NOT NULL UNIQUE,
    description TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- マイグレーション管理 (適用済みバージョン)
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- マイグレーションで追加される列
-- v1: 消費時刻。DELETE ではなく消費済みマークにして再使用を検知する
ALTER TABLE authorization_codes ADD COLUMN consumed_at TEXT;
-- v2: 発行元の認可コード。同じコードから派生した RT (ファミリー) をまとめて失効させる
ALTER TABLE refresh_tokens ADD COLUMN source_code_hash TEXT;
```

**実装との差異** (`AuthServer/Database/DatabaseInitializer.cs`):

- 実装では `users.resource_server_id` 以外に `FOREIGN KEY` 制約を宣言していません
  (`authorization_codes`, `refresh_tokens`, `device_codes`, `consents` の各外部キー)
- 基本スキーマ (v0) は `CREATE TABLE IF NOT EXISTS` で作成し、以降の変更は `schema_migrations` で管理するマイグレーションとして
  バージョン順にトランザクション内で適用します（`DatabaseInitializer.Migrations`）。基本スキーマは変更せず、変更は必ずマイグレーションとして追記します
- `resource_servers` は当初の仕様になく、リソースサーバー管理 UI の追加に伴って導入されたテーブルです

### 10.2 初期データ

`AuthServer/Database/DataSeeder.cs` が投入する内容です。`Seed:Enabled` が `true` のとき
（未設定時は Development 環境のみ）、かつ `clients` テーブルが空のときのみ実行されます。

| 種別 | ID | シークレット / パスワード | 備考 |
|------|----|--------------------------|------|
| クライアント | `test-client` | `test-secret` | `client_credentials` 用 |
| クライアント | `test-webapp` | `webapp-secret` | `authorization_code` + `refresh_token` 用 |
| リソースサーバー | `resource-server-001` | — | audience = `http://localhost:5180` |
| ユーザー | `alice` (`user-001`) | `password` | Alice Tester / alice@example.com |

```sql
-- 開発用クライアント（client_credentials 用）
INSERT INTO clients (client_id, client_secret_hash, client_name, grant_types, redirect_uris,
                     scopes, token_endpoint_auth_method, post_logout_redirect_uris,
                     is_active, created_at, updated_at)
VALUES ('test-client', '<hashed_secret>', 'Test Client (client_credentials)',
        '["client_credentials"]', NULL,
        'api.read api.write', 'client_secret_post', NULL, 1, <utc_now>, <utc_now>);

-- 開発用クライアント（Authorization Code Flow 用）
INSERT INTO clients (client_id, client_secret_hash, client_name, grant_types, redirect_uris,
                     scopes, token_endpoint_auth_method, post_logout_redirect_uris,
                     is_active, created_at, updated_at)
VALUES ('test-webapp', '<hashed_secret>', 'Test Web App (authorization_code)',
        '["authorization_code","refresh_token"]', '["http://localhost:5173/callback"]',
        'openid profile email api.read', 'client_secret_post', NULL, 1, <utc_now>, <utc_now>);

-- 既定のリソースサーバー（users より先に投入する必要あり）
INSERT INTO resource_servers (resource_server_id, name, audience, description,
                              is_active, created_at, updated_at)
VALUES ('resource-server-001', 'ResourceServer', 'http://localhost:5180',
        'Default resource server', 1, <utc_now>, <utc_now>);

-- 開発用ユーザー
INSERT INTO users (user_id, resource_server_id, username, password_hash, email, email_verified,
                   name, given_name, family_name, is_active, created_at, updated_at)
VALUES ('user-001', 'resource-server-001', 'alice', '<hashed_password>', 'alice@example.com', 1,
        'Alice Tester', 'Alice', 'Tester', 1, <utc_now>, <utc_now>);
```

パスワード / シークレットは `PasswordHasher.Hash()`（PBKDF2-SHA256 / 60 万回反復）でハッシュ化して保存します。
`created_at` / `updated_at` は `DateTime.UtcNow` のラウンドトリップ書式（`"o"`）文字列です。

---

## 11. スコープ定義

| スコープ | 種別 | 説明 | 返却クレーム | 実装 |
|---------|------|------|------------|------|
| `openid` | OIDC 標準 | OIDC 認証要求を示す | `sub` | ✅ |
| `profile` | OIDC 標準 | プロフィール情報 | `name`, `family_name`, `given_name`, `preferred_username` | ✅ |
| `email` | OIDC 標準 | メールアドレス | `email`, `email_verified` | ✅ |
| `offline_access` | OIDC 標準 | リフレッシュトークン発行 | — | 🔲 |
| `api.read` | カスタム | リソースサーバー読み取り | — | ✅ |
| `api.write` | カスタム | リソースサーバー書き込み | — | ✅ |

`offline_access` は未実装です。現在のリフレッシュトークンは、クライアントの `grant_types` に
`refresh_token` が含まれていれば `offline_access` の要求有無に関わらず発行されます。
Discovery の `scopes_supported` にも含めていません。

---

## 12. 技術スタック・依存関係

| カテゴリ | パッケージ/技術 | 用途 |
|---------|---------------|------|
| Web フレームワーク | ASP.NET Core Minimal API (.NET 10.0) | API エンドポイント |
| UI フレームワーク | Blazor Server (.NET 10.0) | 管理画面 |
| UI コンポーネント | `MudBlazor` 9.9.0 | ユーザー / リソースサーバー管理 UI |
| オーケストレーション | .NET Aspire 13.5.3 (`AppHost` / `ServiceDefaults`) | 起動構成・OpenTelemetry・ヘルスチェック |
| データアクセス | `Dapper` 2.1.79 | SQL マッピング |
| データベース | SQLite (`Microsoft.Data.Sqlite` 10.0.11) | 永続化ストレージ |
| JWT 生成 | `Microsoft.IdentityModel.JsonWebTokens` 8.22.0 | AuthServer: トークン生成 (`JsonWebTokenHandler`) |
| JWT 検証 | `Microsoft.AspNetCore.Authentication.JwtBearer` 10.0.11 | ResourceServer: トークン検証 |
| API ドキュメント | `Microsoft.AspNetCore.OpenApi` 10.0.11 + `Scalar.AspNetCore` 2.17.2 | OpenAPI 公開・UI |
| 暗号 | `System.Security.Cryptography` | RSA 鍵生成、ランダム値生成 |
| パスワードハッシュ | 自前実装 (`Services/PasswordHasher.cs`) | PBKDF2-SHA256 / 60 万回反復 |
| JSON | `System.Text.Json` | シリアライズ/デシリアライズ |
| HTTP クライアント | `System.Net.Http.HttpClient` | TestClient |
| CLI | `System.CommandLine` 2.0.11 + `Usa.Smart.CommandLine.Hosting` 2.15.0 | TestClient のコマンド定義 |
| ログ | `Microsoft.Extensions.Logging` | 全コンポーネント |
| テスト | — | **テストプロジェクトは未作成**。現状は TestClient による手動疎通確認のみ |

**外部ライブラリへの依存を最小化し、学習目的で可能な限り標準ライブラリのみで実装する。**

`System.IdentityModel.Tokens.Jwt`（旧 API）ではなく `Microsoft.IdentityModel.JsonWebTokens` の
`JsonWebTokenHandler` を使用しています。`AuthServer.slnx` に含まれるのは
`AppHost` / `AuthServer` / `ResourceServer` / `ServiceDefaults` / `TestClient` の 5 プロジェクトです。

`ServiceDefaults` は OpenTelemetry 1.18.0 / `Microsoft.Extensions.ServiceDiscovery` 10.9.0 /
`Microsoft.Extensions.Http.Resilience` 10.9.0 を参照します。新しい Aspire テンプレートは
ServiceDefaults を Host に統合していますが、本プロジェクトは AuthServer と ResourceServer の
2 つが共有するため独立プロジェクトとして維持しています。

`AppHost` では Aspire の推移的依存である `MessagePack` を 3.1.8 に固定しています
（GHSA-hv8m-jj95-wg3x 対応）。この固定を外すと脆弱性警告が復活します。

---

## 13. 実装チェックリスト

実装状況の追跡は **`TODO.md` に一本化**しています。
本節に重複したチェックリストは置かず、`TODO.md` を唯一の進捗管理先としてください。

`TODO.md` には以下を集約しています。

- Phase 1〜5 の実装チェックリスト（本仕様書の各 Phase に対応）
- コードレビューで指摘された未対応項目
- 仕様と実装の乖離に起因する課題

仕様書側の各 Phase 節（§6.2〜§6.6）には実装状況の概要を記載しています。

---

以上が本認証サーバー実装プロジェクトの完全仕様です。Phase 1 から順に実装を進めることで、段階的に OAuth 2.0 / OIDC の理解を深めることができます。