# 実装 TODO

`__spec.md` の実装チェックリスト兼、本プロジェクトの唯一のバックログです。
完了済みは `[x]`、未着手は `[ ]` で管理します。

*最終更新: 2026-09-05*

---

## 優先対応: コードレビュー指摘（未対応分）

2026-08-06 のコードレビューで指摘され、まだ対応していない項目です。
High「署名鍵の RSA インスタンスが破棄済みでトークン発行が必ず失敗する」は
2026-09-05 に修正・実機検証済みのため本一覧から除外しています。

### 🟡 中: テストデータの投入が環境で分岐していない

`AuthServer/Program.cs` / `AuthServer/Database/DataSeeder.cs`

`DataSeeder` は「`clients` テーブルが空なら投入」という条件のみで `IsDevelopment()` の判定がなく、
新規環境で起動すると本番でも以下の既知資格情報が有効になります。いずれもソース上に平文で存在します。

| 種別 | ID | シークレット |
|---|---|---|
| クライアント | `test-client` | `test-secret` |
| クライアント | `test-webapp` | `webapp-secret` |
| ユーザー | `alice` | `password` |

- [ ] `app.Environment.IsDevelopment()` での分岐、または設定フラグ（`Seed:Enabled`）で制御する

### 🟡 中: 既知の脆弱性を持つパッケージへの依存

Release ビルドで **28 件の警告**が出ており、`AGENTS.md` の「ビルド警告ゼロ」に違反した状態です。

```
NU1903: Microsoft.OpenApi 2.0.0            高 (GHSA-v5pm-xwqc-g5wc)  … AuthServer / ResourceServer
NU1903: SQLitePCLRaw.lib.e_sqlite3 2.1.11  高 (GHSA-2m69-gcr7-jv3q)  … AuthServer
NU1902/NU1903: MessagePack 2.5.192         中〜高（複数）             … AppHost
```

- [ ] `Microsoft.OpenApi` を更新する
- [ ] `SQLitePCLRaw.lib.e_sqlite3` を更新する（`Experimental-Telemetry` と共通のため同時対応が効率的）
- [ ] `MessagePack` を更新する（Aspire 経由の推移的依存）

### 🟡 中: グラントタイプの判定が JSON 文字列の部分一致

`AuthServer/Endpoints/TokenEndpoint.cs`、`AuthServer/Endpoints/AuthorizeEndpoint.cs`

```csharp
if (!client.GrantTypes.Contains("client_credentials", StringComparison.Ordinal))
```

`Client.GrantTypes` は `["client_credentials"]` のような JSON 配列文字列で保存されています。
現在のシードデータでは正しく動作しますが、部分一致のため将来 `"client_credentials_jwt"` の
ような値が入ると意図せず一致します。同一エンドポイント内のスコープ検査は分割して完全一致で
照合しているため、グラントタイプ側も揃えるのが自然です。

- [ ] JSON をパースして配列比較に統一する（`TokenEndpoint` 4 箇所 + `AuthorizeEndpoint` 1 箇所）

### 🟢 低: `RequireHttpsMetadata` の既定が false

`ResourceServer/Program.cs`

```csharp
var requireHttps = jwt.GetValue("RequireHttpsMetadata", false);
```

- [ ] 既定値を `true` にし、開発時のみ設定で下げる
- [ ] 少なくとも README に本番設定として明記する

---

## 仕様と実装の乖離

- [ ] `/connect/authorize` を標準のブラウザリダイレクト方式（`__spec.md` §6.3 方式 A）で実装する
      現在は方式 B（API 専用・資格情報直送）のみ。方式 B は信頼モデルが ROPC 相当のため、
      同意画面・`prompt` パラメーター・外部 IdP 連携が成立しません
- [ ] ID Token の `email_verified` が文字列 `"true"` で出力される（OIDC Core §5.1 では boolean）。
      UserInfo 側は boolean で返しており不整合
- [ ] ID Token の有効期限がアクセストークンと同じ `AccessTokenLifetimeSeconds` を流用している
- [ ] トークン有効期限が当初仕様と異なる（`__spec.md` SEC-07）。
      リフレッシュトークンは仕様 30 日に対し実装 1 日（86400 秒）、
      認可コードは仕様 10 分に対し実装 2 分（120 秒）。仕様と実装のどちらに寄せるか要判断
- [ ] 認可コード再使用時に、そのコードから発行済みのトークンを失効させる処理が未実装
      （`__spec.md` SEC-04）。現在は DELETE によるワンタイム化のみ
- [ ] HTTPS 構成が未対応（`__spec.md` SEC-01）。現在は AuthServer / ResourceServer とも HTTP
- [ ] レート制限が未実装（`__spec.md` SEC-09）。Token / Authorize エンドポイントのブルートフォース対策
- [ ] CORS 設定が未実装（`__spec.md` SEC-10）

---

## Phase 1: 最小動作構成

**目標**: TestClient → AuthServer から `client_credentials` でアクセストークンを取得し、
ResourceServer の保護 API (`GET /api/protected`) を呼び出せること。

- [x] ソリューション・プロジェクト作成 (既存)
- [x] SQLite DB 初期化・マイグレーション機構 (`AuthServer/Database/DatabaseInitializer.cs`)
- [x] Dapper によるデータアクセス基盤 (`AuthServer/Database/DbConnectionFactory.cs`)
- [x] RSA 鍵ペア生成・DB 永続化 (`signing_keys` テーブル / `Services/SigningKeyService.cs`)
- [x] クライアント情報データアクセス (`Services/ClientService.cs`)
- [x] パスワード/シークレットハッシュ化 (`Services/PasswordHasher.cs` PBKDF2-SHA256)
- [x] `/.well-known/openid-configuration` 実装 (`Endpoints/DiscoveryEndpoint.cs`)
- [x] `/.well-known/jwks.json` 実装 (`Endpoints/JwksEndpoint.cs`)
- [x] `client_secret_post` / `client_secret_basic` によるクライアント認証
- [x] `/connect/token` (client_credentials) 実装 (`Endpoints/TokenEndpoint.cs`)
- [x] JWT アクセストークン生成 (RS256 署名 / `Services/TokenService.cs`)
- [x] 初期データ (テスト用 client / user) の投入 (`Database/DataSeeder.cs`)
- [x] ResourceServer: `AddJwtBearer` 設定
- [x] ResourceServer: 保護エンドポイント実装 (`GET /api/protected`)
- [x] ResourceServer: スコープベースの認可ポリシー (`api.read` / `api.write`)
- [x] TestClient: client_credentials フロー実装
- [x] TestClient: コマンドベース CLI へ移行 (`token` / `api` / `refresh` / `discovery` 他)
- [x] TestClient: トークンファイル永続化 (`~/.testclient/tokens.json`)
- [x] 結合テスト: トークン取得 → API 呼び出し成功 (TestClient で実機確認済み)
- [ ] 結合テスト: ResourceServer に不正トークンで 401 応答確認
      （AuthServer の `/connect/userinfo` 側は 401 を実機確認済み）

## Phase 2: Authorization Code Flow + PKCE

`__spec.md` §6.3 の **方式 B（API 専用）** で実装済み。方式 A（標準リダイレクト）は未着手です。
2026-09-05 に AuthServer を実起動して全項目を実機検証しました。

- [x] MudBlazor 導入 (AuthServer に `MudBlazor` パッケージ追加 / MainLayout・NavMenu 更新)
- [x] ユーザー情報モデル (`Models/User.cs`)
- [x] `UserService` 実装 (CRUD + パスワード変更 + ユーザー名重複チェック)
- [x] ユーザー管理 UI: 一覧・追加・編集・パスワード変更・削除 (`Pages/Users.razor`)
- [x] Dapper による認可コードデータアクセス実装 (`Services/AuthorizationCodeService.cs`)
- [x] Dapper によるリフレッシュトークンデータアクセス実装 (`Services/RefreshTokenService.cs`)
- [x] `/connect/authorize` 実装（パラメータ検証、PKCE、state） (`Endpoints/AuthorizeEndpoint.cs`)
- [x] 認可コード生成・DB 保存（SHA-256 ハッシュ保存 / 有効期限 120 秒）
- [x] `/connect/token` (authorization_code) 実装
- [x] PKCE 検証（S256）
- [x] 認可コード一回限り使用の検証
- [x] redirect_uri 完全一致検証
- [x] リフレッシュトークン生成・DB 保存
- [x] `/connect/token` (refresh_token) 実装
- [x] リフレッシュトークンローテーション（旧トークン失効 + `replaced_by_token_hash` 記録）
- [x] TestClient: Authorization Code Flow 実装（方式 B のためローカル HTTP リスナーは不要）
- [x] TestClient: トークンリフレッシュ実装
- [x] 結合テスト: Authorization Code Flow 全体フロー
- [x] 結合テスト: PKCE 不一致で拒否確認（`invalid_grant`）
- [x] 結合テスト: 認可コード再利用で拒否確認（`invalid_grant`）
- [ ] `/connect/authorize` の GET（ブラウザリダイレクト）実装 ※方式 A
- [ ] `/account/login` Blazor ページ実装 ※方式 A
- [ ] `state` の厳密検証（現在は受け取って返すのみで CSRF 対策として機能していない）

## Phase 3: OIDC 準拠

ID Token と UserInfo は Phase 2 の実装に伴い先行して対応済みです。

- [x] ID Token 生成（`nonce`）
- [x] Authorization Code Flow レスポンスに `id_token` 追加
- [x] `/connect/userinfo` 実装 (`Endpoints/UserInfoEndpoint.cs`)
- [x] スコープに基づくクレーム返却制御（`openid`, `profile`, `email`）
- [x] Discovery メタデータに `authorization_endpoint` / `userinfo_endpoint` を追加
- [x] TestClient: UserInfo 取得実装 (`userinfo` コマンド)
- [x] 結合テスト: UserInfo レスポンス検証
- [ ] ID Token に `at_hash`, `auth_time`, `amr` を追加
- [ ] Discovery メタデータ拡張（`claims_supported`, `subject_types_supported`, `response_modes_supported` 等）
- [ ] Dapper による同意情報データアクセス実装
- [ ] `/account/consent` Blazor ページ実装 ※方式 A が前提
- [ ] 同意済みスコープの DB 保存・参照
- [ ] 同意済みの場合は同意画面スキップ
- [ ] TestClient: ID Token のデコード・表示（現在は切り詰めた生文字列を表示するのみ）
- [ ] 結合テスト: ID Token クレーム検証
- [ ] 結合テスト: 同意フロー動作確認

## Phase 4: 運用機能

- [ ] Dapper による失効トークンデータアクセス実装
- [ ] `/connect/revoke` 実装
- [ ] 失効リスト管理（JTI ベース、DB 永続化）
- [ ] `/connect/introspect` 実装
- [ ] `/connect/logout` 実装
- [ ] セッション管理（Cookie ベース）
- [ ] Blazor ログアウト確認画面
- [ ] 鍵ローテーション機能（新鍵生成・旧鍵猶予期間・DB 管理）
- [ ] JWKS キャッシュ制御ヘッダー（`Cache-Control`）
- [ ] 期限切れ認可コード・リフレッシュトークンのクリーンアップジョブ
- [ ] 期限切れ失効トークンのクリーンアップジョブ
- [ ] TestClient: トークン失効実装
- [ ] TestClient: ログアウト実装
- [ ] 結合テスト: トークン失効後の API 呼び出し拒否確認
- [ ] 結合テスト: イントロスペクション応答確認
- [ ] 結合テスト: 鍵ローテーション後のトークン検証確認

## Phase 5: 拡張機能

- [ ] Dapper によるデバイスコードデータアクセス実装
- [ ] `/connect/device/authorize` 実装
- [ ] `/account/device` Blazor ページ実装（コード入力・認証）
- [ ] デバイスフローポーリング処理（`authorization_pending`, `slow_down`）
- [ ] `/connect/register` 実装（クライアント動的登録）
- [ ] `/connect/register/{client_id}` CRUD 実装
- [ ] `/account/register` Blazor ページ実装（ユーザー登録）
- [ ] `/account/password` Blazor ページ実装（パスワード変更）
- [ ] `/account/password-reset` Blazor ページ実装（パスワードリセット）
- [ ] `/account/consents` Blazor ページ実装（同意管理・取り消し）
- [ ] TestClient: デバイスフロー実装
- [ ] 結合テスト: デバイスフロー全体フロー
- [ ] 結合テスト: クライアント動的登録・管理
- [ ] 結合テスト: ユーザー登録・パスワード変更

---

## 参考

- `__spec.md` — 実装仕様書。Phase ごとの設計と実装状況の概要
- `__ENHANCEMENT_ROADMAP.md` — spec 範囲外の将来機能候補（Phase B 以降）
