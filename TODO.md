# 実装 TODO

`__spec.md` の実装チェックリストです。完了済みは `[x]`、未着手は `[ ]` で管理します。

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
- [x] 結合テスト: トークン取得 → API 呼び出し成功 (TestClient で実機確認済み)
- [ ] 結合テスト: 不正トークンで 401 応答確認

## Phase 2: Authorization Code Flow + PKCE

- [x] MudBlazor 導入 (AuthServer に `MudBlazor` パッケージ追加 / MainLayout・NavMenu 更新)
- [x] ユーザー情報モデル (`Models/User.cs`)
- [x] `UserService` 実装 (CRUD + パスワード変更 + ユーザー名重複チェック)
- [x] ユーザー管理 UI: 一覧・追加・編集・パスワード変更・削除 (`Pages/Users.razor`)
- [ ] Dapper による認可コードデータアクセス実装
- [ ] Dapper によるリフレッシュトークンデータアクセス実装
- [ ] `/connect/authorize` 実装（パラメータ検証、PKCE、state）
- [ ] `/account/login` Blazor ページ実装
- [ ] 認可コード生成・DB 保存
- [ ] `/connect/token` (authorization_code) 実装
- [ ] PKCE 検証（S256）
- [ ] 認可コード一回限り使用の検証
- [ ] redirect_uri 完全一致検証
- [ ] リフレッシュトークン生成・DB 保存
- [ ] `/connect/token` (refresh_token) 実装
- [ ] リフレッシュトークンローテーション
- [ ] TestClient: Authorization Code Flow 実装（ローカル HTTP リスナー）
- [ ] TestClient: トークンリフレッシュ実装
- [ ] 結合テスト: Authorization Code Flow 全体フロー
- [ ] 結合テスト: PKCE 不一致で拒否確認
- [ ] 結合テスト: 認可コード再利用で拒否確認

## Phase 3: OIDC 準拠

- [ ] ID Token 生成（`nonce`, `at_hash`, `auth_time`, `amr`）
- [ ] Authorization Code Flow レスポンスに `id_token` 追加
- [ ] `/connect/userinfo` 実装
- [ ] スコープに基づくクレーム返却制御（`openid`, `profile`, `email`）
- [ ] Dapper による同意情報データアクセス実装
- [ ] `/account/consent` Blazor ページ実装
- [ ] 同意済みスコープの DB 保存・参照
- [ ] 同意済みの場合は同意画面スキップ
- [ ] Discovery メタデータ拡張（`userinfo_endpoint`, `claims_supported` 等）
- [ ] TestClient: UserInfo 取得実装
- [ ] TestClient: ID Token のデコード・表示
- [ ] 結合テスト: ID Token クレーム検証
- [ ] 結合テスト: UserInfo レスポンス検証
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

