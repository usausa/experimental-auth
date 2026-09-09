# 実装 TODO

`SPEC.md` の実装チェックリスト兼、本プロジェクトの唯一のバックログです。
完了済みは `[x]`、未着手は `[ ]` で管理します。

凡例:

- 🌐 = **M3b の画面（ログイン / 同意 / ログアウト確認）が前提**。方式 A のリダイレクトとセッションは M3a で実装済みなので、
  これらの画面がないと成立しない項目にだけ付けます（2026-09-09 に定義を見直し。以前は「リダイレクトフローが前提」の意味でした）
- 🖥️ = エンドユーザー向けまたは管理者向けのブラウザ画面が必要（リダイレクトフローには依存しない）

*最終更新: 2026-09-09*

---

## マイルストーン計画

2026-09-05 に決定した進め方です。ブラウザリダイレクト（方式 A）は API-only の作業を終えてから着手します。

| M | 内容 | 状態 |
|---|------|------|
| M1 | トークンライフサイクル（Phase 4 前半）: `/connect/revoke`・`/connect/introspect`・JTI 失効リスト・SEC-04 ファミリー失効・スキーママイグレーション機構・鍵ローテーション・クリーンアップジョブ・TestClient `revoke` / `introspect` | ✅ 完了（2026-09-05） |
| M2 | API-only 候補の一部: 鍵の事前公開（2 段階ローテーション）、Device Authorization Grant（承認画面 🖥️ + TestClient `device`）、Resource Indicators（RFC 8707、トークン要求時）、ES256、トークン有効期限の全設定化と推奨値（`SPEC.md` §8.3） | ✅ 完了（2026-09-05） |
| M2' | API-only 追加分（2026-09-06 に前倒し）: JWT Replay 検出（`private_key_jwt` クライアント認証 + `jti` の一回性、`replay_guard` テーブル）、登録済みクライアント認証方式の強制、`nonce` の厳密検証、監査ログ + 確認画面 🖥️（`/audit-logs`）、カスタムクレーム + 管理画面 🖥️（`/claims`、Users 画面のクレーム編集） | ✅ 完了（2026-09-06） |
| M2'' | セキュリティ要件の残り（2026-09-09）: HTTPS 構成（SEC-01）、レート制限（SEC-09）、CORS（SEC-10）と、xUnit + WebApplicationFactory の結合テスト（`Tests/`） | ✅ 完了（2026-09-09） |
| M3a | 🌐 ブラウザリダイレクト（方式 A）の画面なしで作れる部分: セッション Cookie（`/account/session`）、GET `/connect/authorize` のリダイレクト応答とエラーリダイレクト、`response_mode`（`query` / `form_post`）、`prompt=none`、`max_age`、TestClient `authorize`（ローカル HTTP リスナー） | ✅ 完了（2026-09-09） |
| M3b | 🌐 画面が要る残り: `/account/login`、同意画面と `consents` の読み書き、`/connect/logout` とログアウト確認画面、`prompt=login` / `consent`、外部 IdP、Front-Channel / Back-Channel Logout | 🔲 次 |

**アクセストークン失効の方針（方式 3）**: ResourceServer はオフライン検証のみで失効リストを参照しない。
失効はリフレッシュトークンに対して確実に効かせ、アクセストークンは短寿命で対処する。
AuthServer 自身のエンドポイント（UserInfo / Introspection）は失効リストを照合する（`SPEC.md` §6.5）。

---

## コードレビュー指摘（2026-08-06）

5 件すべて 2026-09-05 に対応済みです。

| 重要度 | 指摘 | 対応 |
|---|---|---|
| 🔴 高 | 署名鍵の RSA インスタンスが破棄済みでトークン発行が必ず失敗する | `SigningKeyService` が RSA の所有権を持ち `IDisposable` で破棄 |
| 🟡 中 | テストデータの投入が環境で分岐していない | `Seed:Enabled`（未設定時は Development のみ）で制御 |
| 🟡 中 | 既知の脆弱性を持つパッケージへの依存 | ライブラリ更新でビルド警告 0 件 |
| 🟡 中 | グラントタイプの判定が JSON 文字列の部分一致 | `Client.AllowsGrantType()` で配列展開・完全一致 |
| 🟢 低 | `RequireHttpsMetadata` の既定が false | 既定 `true`、Development のみ `false` |

---

## 仕様と実装の乖離

- [x] 🌐 `/connect/authorize` を標準のブラウザリダイレクト方式（`SPEC.md` §6.3 方式 A）で実装する（M3a、2026-09-09）
      GET はセッション Cookie で利用者を判断してリダイレクトで認可コードを返します。方式 B も従来どおり残しています。
      ログイン画面が未実装のため、未ログインの要求は `login_required` を返します（残りは M3b）
- [x] HTTPS 構成（`SPEC.md` SEC-01）。開発環境も dev 証明書で HTTPS のみをリッスン（AuthServer `https://localhost:5080`、ResourceServer `https://localhost:5180`）。
      本番相当では HTTP → HTTPS リダイレクトと HSTS。ResourceServer の `RequireHttpsMetadata` は全環境で `true`（2026-09-09）
- [x] レート制限（`SPEC.md` SEC-09）。クライアント IP ごとの固定ウィンドウ。`/connect/authorize` は `RateLimiting:AuthenticationPermitLimit`（既定 10/分）、
      トークン系は `TokenPermitLimit`（既定 60/分）。超過は 429 + `Retry-After`。Blazor の承認画面（SignalR）は対象外（2026-09-09）
- [x] CORS（`SPEC.md` SEC-10）。`Cors:AllowedOrigins` のオリジンだけにプロトコルエンドポイントを許可し、Discovery / JWKS は任意オリジンの GET を許可（2026-09-09）
- [x] RFC 6749 §5.1 のキャッシュ制御（`SPEC.md` SEC-14、2026-09-09）。`Security/NoStoreExtensions.cs` のエンドポイントフィルターで
      `Cache-Control: no-store` と `Pragma: no-cache` を付与。対象はトークン・認可（GET / POST）・UserInfo・失効・検査・デバイス認可・セッション。
      Discovery と JWKS は公開メタデータなので対象外
- [x] OIDC Core §5.3.1 の UserInfo POST（MUST、2026-09-09）。Authorization ヘッダーとフォームの `access_token` の両方に対応し、
      両方で送られた場合は `invalid_request`（RFC 6750 §2）
- [x] OIDC Core §3.1.2.1 の POST 認可要求（MUST、2026-09-09）。`POST /connect/authorize` は GET と同じ認可パラメーターを
      form-urlencoded で受け取り、同じ応答を返す。方式 B は `/connect/authorize/direct`（`SPEC.md` E-20）へ移設した
- [ ] フォーム系エンドポイントの Content-Type 不一致エラーが OAuth 形式でない。`Accepts` メタデータに基づいて ASP.NET Core が
      先に 400 とプレーンテキストを返すため、`{"error":"invalid_request"}` にならない（Content-Type 無しの場合はハンドラーに届くので OAuth 形式）
- [x] RFC 6749 §6 のリフレッシュ時スコープ縮小（2026-09-09）。`scope` を指定した場合は元の付与範囲のサブセットであることを検証し、
      範囲外は `invalid_scope`。省略時は元の範囲をそのまま使う。リフレッシュトークン自体は元の付与範囲を保持するため、
      次回以降また広げられる（audience と同じ扱い）
- [x] `redirect_uri` のスキーム検証（`javascript:` / `data:` を弾き、`http` / `https` の絶対 URI でフラグメントなしを要求）。
      認可エンドポイントの脆弱実装対策として追加（`SPEC.md` SEC-05、2026-09-09）
- [x] 自動テスト。`Tests/AuthServer.Tests`（xUnit + WebApplicationFactory、一時 SQLite、seed 有効）と `Tests/ResourceServer.Tests`（AuthServer の TestServer を JWKS の取得先に差し替えた結合テスト）。`dotnet test AuthServer.slnx` で実行（2026-09-09）

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
- [x] クライアント認証: `client_secret_post` / `client_secret_basic` / `private_key_jwt`（RFC 7523。RS256 / ES256、`jti` の一回性）/ `none`（公開クライアント）。登録済みの `token_endpoint_auth_method` を強制（`Services/ClientAuthenticator.cs`、M2'）
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
- [x] 結合テスト: ResourceServer に不正トークンで 401 応答確認
      （2026-09-05 実機確認: トークンなし 401 / 不正トークン 401 / 有効 200 / スコープ不足 403）

## Phase 2: Authorization Code Flow + PKCE

`SPEC.md` §6.3 の **方式 B（API 専用）** で実装済み。方式 A（標準リダイレクト）は未着手です。
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
- [x] TestClient: Authorization Code Flow 実装（方式 B のためローカル HTTP リスナーは不要。`nonce` を生成して送信し、ID Token の `nonce` と一致しなければトークンを破棄 — M2'）
- [x] TestClient: トークンリフレッシュ実装
- [x] 結合テスト: Authorization Code Flow 全体フロー
- [x] 結合テスト: PKCE 不一致で拒否確認（`invalid_grant`）
- [x] 結合テスト: 認可コード再利用で拒否確認（`invalid_grant`）
- [x] 🌐 `/connect/authorize` の GET（ブラウザリダイレクト）実装（M3a。`response_mode` は `query` / `form_post`、エラーは RFC 6749 §4.1.2.1 に従って `redirect_uri` へ返す）
- [ ] 🌐 `/account/login` Blazor ページ実装 ※M3b
- [ ] サーバー側セッションストア（`ITicketStore`）※M3b の前提だが実装自体に画面は不要。現在はクレームをセッション Cookie に直接入れており、
      サーバー側にセッションの記録がない。管理画面からの強制ログアウト、Back-Channel Logout の `sid`、
      ログイン中セッションの一覧はいずれもこれがないと作れない
- [ ] 🌐 サンプルクライアントは 2 種類必要 ※M3b。BFF はホストと同一オリジンで動き、認可サーバーへの通信がすべてサーバー側の
      バックチャネルになるため、**CORS の利用者にはならない**（2026-09-09 の調査で判明）。
      (1) 標準 OpenID Connect ハンドラーのクライアント … 方式 A の検証。ハンドラーの `ResponseMode` 既定値が `form_post` なので、
          繋いだ時点で `form_post` 経路も実利用される。`end_session_endpoint` が無いと `SignOut` が失敗する点に注意
      (2) 素の SPA（public client + PKCE）… CORS の利用者を作る
      Blazor 側のトークン保管（`IJwtAccessor` 相当）は (1) で検討する
- [ ] 🌐 TestClient: ブラウザを起動して実際のログインを挟む ※M3b（`cmd /c start <認可 URL>` で開く。`&` を `^&` にエスケープする必要がある。
      認可コードの受信は `authorize` コマンドのローカル HTTP リスナーをそのまま使える）
- [x] エンドユーザーのセッション（`/account/session` で Cookie を発行 / 確認 / 破棄。`SessionLifetimeSeconds`、HttpOnly / Secure / SameSite=Lax）。ログイン画面もこのエンドポイントを使う（M3a）
- [ ] TestClient: 401 を受けたらリフレッシュして元の要求を 1 回だけリトライする `DelegatingHandler`（サーバー側がこの流れを支えられることは
      `TokenLifecycleScenarioTests` で確認済み）。現在は有効期限切れを検出して `refresh` の実行を促すだけ。要求の再送にはクローンが要り、
      同時多発の 401 でリフレッシュが多重実行されないよう直列化も要る
- [x] TestClient: 方式 A の実行（`authorize` コマンド。セッション確立 → GET 認可 → ローカル HTTP リスナーで `redirect_uri` を受信 → トークン交換 → `state` / `nonce` 検証）
- [x] `state` の検証（サーバーは保存・返却、TestClient が送信値との一致を検証。方式 A では redirect 先で同様に検証する）

## Phase 3: OIDC 準拠

ID Token と UserInfo は Phase 2 の実装に伴い先行して対応済みです。

- [x] ID Token 生成（`nonce`。M2' で `openid` 要求時に必須化・形式検証・同一クライアントでの再利用拒否）
- [x] Authorization Code Flow レスポンスに `id_token` 追加
- [x] `/connect/userinfo` 実装 (`Endpoints/UserInfoEndpoint.cs`)
- [x] スコープに基づくクレーム返却制御（`openid`, `profile`, `email`）
- [x] Discovery メタデータに `authorization_endpoint` / `userinfo_endpoint` を追加
- [x] TestClient: UserInfo 取得実装 (`userinfo` コマンド)
- [x] 結合テスト: UserInfo レスポンス検証
- [x] ID Token に `at_hash`, `auth_time`, `amr` を追加（`email_verified` も boolean 化、有効期限は `IdTokenLifetimeSeconds` に分離）
- [x] Discovery メタデータ拡張（`claims_supported`, `subject_types_supported`, `request_uri_parameter_supported`）
- [x] 🖥️ カスタムクレーム（`claim_definitions` / `user_claims`。`/claims` で定義し、Users 画面でユーザーごとの値を設定。型 string / number / boolean / json、必要スコープ、AT / ID Token / UserInfo の出力先を指定。`claims_supported` / `scopes_supported` に動的反映。M2'）
- [x] 🌐 Discovery に `response_modes_supported` を追加（`query` / `form_post`）
- [ ] RFC 9207 認可応答の `iss`。複数の認可サーバーを使うクライアントに対する mixup 攻撃対策で、方式 A を実装したことで関係するようになった。
      Discovery に `authorization_response_iss_parameter_supported` を追加する。実装量は小さい
- [ ] ID Token の `sid`。セッションを実装したので意味を持ち、Back-Channel Logout の前提にもなる
- [x] 401 応答への `WWW-Authenticate`（2026-09-09）。RFC 9110 §15.5.2 が MUST、RFC 6749 §5.2 と RFC 7662 §2.1 も要求する。
      クライアント認証を行うトークン・失効・検査・デバイス認可の 4 エンドポイントに `Basic realm="<path>"` を添える
- [ ] GET `/connect/authorize` が未知の `client_id` に返す 401 には `WWW-Authenticate` が無い。この状況は認証の失敗ではないため、
      400 に改める方が RFC 9110 §15.5.2 と整合する（挙動変更になるためテストの追随が必要）
- [ ] Discovery を実装から動的に生成する。グラント・応答タイプ・クライアント認証方式をハードコードしているため、実装とずれる余地がある
      （`claims_supported` と `scopes_supported` はカスタムクレーム定義から動的生成済み）
- [ ] 🖥️ カスタムクレームのドット記法（`address.street` のような入れ子パス）。OIDC 標準の `address` クレームをハードコードなしに表現できる
- [ ] 🌐 Dapper による同意情報データアクセス実装 ※M3
- [ ] 🌐 `/account/consent` Blazor ページ実装 ※M3。設計は次の 4 点をセットにする（2026-09-09 の調査より）。
      (1) ticket 方式 … 認可要求はサーバー側に保持し、フォームには決定内容だけを置く。ブラウザーを往復させると検証が 2 経路に増える
      (2) CSRF トークン (3) `X-Frame-Options: DENY`（同意ボタンへの上被せ対策） (4) `Cache-Control: no-store`
      あわせて、保存済み同意の再利用条件（スコープ集合の完全一致を要求するか、部分集合を許すか）を決める
- [ ] 🌐 同意済みスコープの DB 保存・参照 ※M3
- [ ] 🌐 同意済みの場合は同意画面スキップ ※M3
- [x] TestClient: ID Token のデコード・表示（`token` コマンドがペイロードのクレームを一覧表示）
- [x] 結合テスト: ID Token クレーム検証（各クレームの JSON 型、`at_hash` の独立計算との一致を確認）
- [ ] 🌐 結合テスト: 同意フロー動作確認 ※M3

## Phase 4: 運用機能

前半（トークンライフサイクル）は M1 で実装済み。ログアウト・セッション関連は方式 A（M3）が前提です。
2026-09-05 に AuthServer / ResourceServer を実起動して全項目を実機検証しました。

- [x] Dapper による失効トークンデータアクセス実装 (`Services/RevokedTokenService.cs`)
- [x] スキーママイグレーション機構（`schema_migrations`、v1 `consumed_at` / v2 `source_code_hash`）
- [x] `/connect/revoke` 実装 (`Endpoints/RevocationEndpoint.cs`)
- [x] 失効リスト管理（JTI ベース、DB 永続化）
- [x] `/connect/introspect` 実装 (`Endpoints/IntrospectionEndpoint.cs`)
- [x] 認可コード再使用時のファミリー失効（SEC-04）と、ローテーション後の RT リプレイ検知
- [x] クライアント認証の共通化 (`Services/ClientAuthenticator.cs`。M2' で static クラスから DI サービスに変更) と AT 検証の共通化 (`TokenService.ValidateAccessTokenAsync`、`typ=at+jwt` 必須)
- [x] 鍵ローテーション機能（新鍵生成・旧鍵猶予期間・DB 管理。管理画面 `/signing-keys` と `SigningKeyRotationDays` による自動）
- [x] JWKS キャッシュ制御ヘッダー（`Cache-Control`、`JwksCacheMaxAgeSeconds`）
- [x] 期限切れ認可コード・リフレッシュトークンのクリーンアップジョブ (`Services/MaintenanceService.cs`)
- [x] 期限切れ失効トークンのクリーンアップジョブ（猶予期間切れの鍵の退役も同じジョブ）
- [x] リプレイ検出の共通基盤（`replay_guard`。一回限りの値を期限つきで記録し、期限切れは保守ジョブが削除。M2'）
- [ ] セキュリティヘッダー（`SPEC.md` SEC-15）。CSP・`X-Frame-Options`・`X-Content-Type-Options`・`Referrer-Policy`・`Permissions-Policy`。
      現在は `UseHsts` のみ。ログイン画面と同意画面（M3b）を作る前に入れる。`form_post` でクライアントへ POST する構成では
      CSP の `form-action` に相手ホストの許可が要る点に注意
- [ ] 監査ログにクライアント認証方式を記録する。要求内容の JSON も残すと追跡しやすい
- [x] 🖥️ 監査ログ（`audit_logs`。クライアント認証失敗・トークン発行 / 拒否・認可・デバイス承認 / 拒否・失効・リプレイ検出・鍵操作・管理画面の変更を記録。`/audit-logs` で絞り込み表示。`AuditLogRetentionDays` 経過分は保守ジョブが削除。M2'）
- [x] TestClient: トークン失効実装（`revoke --token-type all|access|refresh`）
- [x] TestClient: イントロスペクション実装（`introspect --token-type access|refresh`）
- [x] 結合テスト: 失効後は AuthServer（UserInfo / Introspection）が拒否し、ResourceServer は有効期限まで受理する（方式 3 の想定どおり）
- [x] 結合テスト: イントロスペクション応答確認（AT / RT / 失効済み / 不正 / ID Token は inactive）
- [x] 結合テスト: 鍵ローテーション後のトークン検証確認（旧鍵のトークンは猶予期間中受理。新鍵のトークンは JwtBearer の既定動作で最初の 1 要求のみ 401、JWKS 再取得後は受理）
- [x] 鍵の事前公開（2 段階ローテーション。管理画面の Schedule Rotation / `SigningKeyPrePublishSeconds`。M2 で実測: 事前公開期間中に JWKS を取得済みの ResourceServer は新鍵の最初の要求から 200）
- [x] 署名アルゴリズムの選択（RS256 / ES256。JWKS に EC 鍵を `crv` / `x` / `y` で公開、`SigningKeyAlgorithm` で既定を指定）
- [x] ResourceServer の JWKS 自動再取得間隔を設定化（`Jwt:JwksRefreshSeconds`、既定 1800。事前公開期間以下にする）
- [ ] `/connect/logout` 実装。`id_token_hint` が有効で `post_logout_redirect_uri` が登録済みなら確認画面なしで完結する。
      確認画面が要るのは `id_token_hint` が無い場合だけ（OIDC RP-Initiated Logout §2）
- [ ] 🌐 セッション管理（Cookie ベース） ※M3
- [ ] 🌐 Blazor ログアウト確認画面 ※M3
- [ ] 🌐 TestClient: ログアウト実装 ※M3

## Phase 5: 拡張機能

- [x] Dapper によるデバイスコードデータアクセス実装 (`Services/DeviceCodeService.cs`)
- [x] `/connect/device/authorize` 実装 (`Endpoints/DeviceAuthorizationEndpoint.cs`。公開クライアント `test-device` を seed に追加)
- [x] 🖥️ `/account/device` Blazor ページ実装（`Pages/DeviceActivation.razor`、`PublicLayout`。単一フォームで完結し、リダイレクトもセッションも不要）
- [x] デバイスフローポーリング処理（`authorization_pending`, `slow_down`, `access_denied`, `expired_token`。承認後の交換は 1 回のみ）
- [ ] 🖥️ `/account/register` Blazor ページ実装（ユーザー登録）
- [ ] 🖥️ `/account/password` Blazor ページ実装（パスワード変更。現在のパスワード入力で認証し、セッションは不要）
- [ ] 🖥️ `/account/password-reset` Blazor ページ実装（パスワードリセット。メール送信基盤が別途必要）
- [ ] 🌐 `/account/consents` Blazor ページ実装（同意管理・取り消し） ※M3（同意機能が前提）
- [x] TestClient: デバイスフロー実装（`device` コマンド。`slow_down` で間隔を +5 秒）
- [x] TestClient: `--auth-method`（`client_secret_post` / `client_secret_basic` / `private_key_jwt` / `none`）と `--client-key`、`keygen`（P-256 鍵ペア生成）/ `assertion`（クライアントアサーション出力）コマンド（M2'）
- [x] 🖥️ 結合テスト: デバイスフロー全体フロー（2026-09-05 実機確認: ブラウザで承認 → TestClient がトークン取得 → ResourceServer 200。`slow_down` / 他クライアントの拒否も確認）
- [ ] 🖥️ 結合テスト: ユーザー登録・パスワード変更

---

## Phase B: spec 範囲外の機能強化候補

`__Other/FEATURE_ANALYSIS.md` の調査結果をもとにした、`SPEC.md` に含まれない機能の候補です。
M2 で ES256 と Resource Indicators、M2' で JWT Replay 検出・`nonce` 厳密検証・監査ログ・カスタムクレーム管理 UI を実装しました。残りは M3（方式 A）の後に必要なものを選びます。優先度は以下の 3 軸で付けています。

| 軸 | 内容 |
|----|------|
| 学習価値 | RFC / OIDC 仕様の理解が深まるか。標準化された仕様か |
| 現実的需要 | 実際の認証システムで広く使われているか |
| 実装コスト | 現在のコードベースへの追加が現実的か |

> 🌐 を付けた項目（`prompt`、PAR、JAR、外部 IdP、Front-Channel / Back-Channel Logout）は、
> ブラウザリダイレクトとサーバー側セッションが前提です。`SPEC.md` §6.3 の方式 A（M3）を先に実装しないと着手できません。
> 🖥️ の項目は画面が必要ですが、リダイレクトフローには依存しないため M2 でも実装できます。

### B-1. 最優先（学習価値・需要ともに高い）

- [x] ★★★ **JWT Replay 検出** — RFC 7519 §4.1.7。`replay_guard` に一回限りの値（kind + value）を期限つきで記録。`private_key_jwt` の `jti`（RFC 7523 §3）と認可要求の `nonce` に適用し、再提示は `invalid_client` / `invalid_request` で拒否して監査ログ `replay_detected` に記録。AT の `jti` は失効リスト、認可コード / RT の再提示はファミリー失効（SEC-04）で扱う（M2'）
- [x] 🌐 ★★★ **`prompt` パラメーター対応**（`none`）と `max_age` — OIDC Core §3.1.2.1。`prompt=none` は既存セッションを検出し、なければ `login_required`（M3a）
- [ ] 🌐 `prompt=login` / `consent` / `select_account` の本来の挙動 ※M3b。現在はそれぞれ `login_required` / `consent_required` / `account_selection_required` を返すだけで、再認証・同意・アカウント選択の画面がない
- [ ] ★★☆ **PAR（Pushed Authorization Request）** — RFC 9126。`POST /connect/par` がクライアント認証つきで認可パラメーターを受け取り、
      `urn:ietf:params:oauth:request_uri:<id>` を `expires_in`（10 分程度）つきで返す。認可エンドポイントは `request_uri` だけを受けて
      保存済みのパラメーターを復元する。パラメーターが URL に出ないため改ざんも防げる。方式 A ができたので画面なしで実装できる。コスト: 中
- [x] ★★☆ **複数署名アルゴリズム対応（ES256）** — RFC 7518。管理画面でローテーション時に RS256 / ES256 を選択。JWKS・検証・Discovery を対応（M2）

### B-2. 高優先（実際のシステムで頻出）

- [ ] 🌐 ★★☆ **Front-Channel Logout** — OIDC Front-Channel Logout 1.0。各 RP へ iframe でセッション終了を通知。コスト: 中 ※M3
- [ ] ★★☆ **Back-Channel Logout** — OIDC Back-Channel Logout 1.0。Logout Token (JWT) をサーバー間で送付。OP 側セッションの終了が発火点のため方式 A が前提。コスト: 中 ※M3
- [x] ★★☆ **`nonce` の厳密検証** — OIDC Core §3.1.2.1。`openid` 要求時は必須（`RequireNonce`）、空白を含まない印字可能 ASCII 512 文字以内、同一クライアントでの再利用を拒否（認可コード + ID Token の寿命の間記録）。TestClient は ID Token の `nonce` 一致を検証（M2'）
- [ ] 🌐 ★★☆ **外部 IdP 連携（ソーシャルログイン）** — Google / GitHub 等を外部 IdP として受け入れる Federation。コスト: 高 ※M3
- [x] 🖥️ ★★☆ **監査ログ** — `audit_logs` + `/audit-logs` 画面（イベント / 結果 / クライアント / 自由検索で絞り込み）。保持期間は `AuditLogRetentionDays`（M2'）
- [ ] 🖥️ ★★☆ **パスキー / WebAuthn（FIDO2）** — ユーザーごとに公開鍵を登録し、認証時に署名を検証する。ログイン画面が前提で、
      検証は外部ライブラリに依存する。`amr` を `["pwd"]` 固定から実際の認証方式に変える必要がある。コスト: 高
- [ ] 🖥️ ★☆☆ **TOTP / MFA** — RFC 6238 / RFC 4226。パスワード + TOTP の 2 要素認証。検証は方式 B の `POST /connect/authorize` に `totp` を足せば API で完結し、登録（QR 表示）だけ画面が必要。コスト: 中
- [ ] ★★☆ **ACR / AMR のモデル化** — ACR を「名前 + 順序付き AMR リスト」としてテーブルに持ち、`acr_values` → クライアント既定値 →
      サーバー既定値の順で解決する。現在 `amr` は `["pwd"]` 固定。パスキー・TOTP・外部 IdP はいずれもこの受け皿がないと後から差し込めないため、
      それらに着手する前に入れると効く。Discovery の `acr_values_supported` と対。コスト: 中
- [ ] 🖥️ ★☆☆ **メール確認** — OIDC Core §5.1。`email_verified` クレームと連動。確認リンクの着地画面とメール送信基盤が必要。コスト: 中

### B-3. 中優先（学習価値は高いが実装コストが大きい）

- [ ] ★★☆ **Request Object / JAR** — RFC 9101。認可リクエストを JWT 化して署名・暗号化。リダイレクト型の認可要求が対象のため方式 A が前提。コスト: 高 ※M3
- [x] ★★☆ **Resource Indicators** — RFC 8707。トークン要求時の `resource`（複数可）を登録済みリソースサーバーに解決し `aud`（文字列 / 配列）へ。RT は元の付与範囲を保持し、refresh で絞り込み可（M2）
- [ ] Resource Indicators: 認可要求時（`/connect/authorize`、`/connect/device/authorize`）の `resource` 束縛（RFC 8707 §2.1）。現在はトークン要求時（§2.2）のみ
- [x] 🖥️ ★☆☆ **カスタムクレーム管理 UI** — `/claims` で定義（型 string / number / boolean / json、必要スコープ、AT / ID Token / UserInfo の出力先）、Users 画面でユーザーごとの値を設定。予約クレーム名は定義不可（M2'）

### B-4. 対象外（実装しない）

本プロジェクトの学習目的から外れるため、着手しない方針のものです。

| 機能 | 理由 |
|------|------|
| SAML 2.0 / WS-Federation | レガシーエンタープライズ向け。目的との乖離が大きい |
| Windows 統合認証 | 環境依存。クロスプラットフォーム志向に合わない |
| LDAP 統合 | 別システム依存。本質的理解に直結しない |
| Docker ラベル / Kubernetes 認証 | インフラ層の話で OAuth/OIDC の範囲外 |
| Authlete SaaS 型 | 外部委譲はフルスクラッチ学習の趣旨に反する |
| 複数 DB バックエンド | SQLite で十分。運用課題 |
| CIBA（OpenID CIBA 1.0） | 2026-09-06 に不要と判断。バックチャネルで別デバイスに承認を求める流れは、実装済みの Device Authorization Grant で学習範囲を代替できる |
| Dynamic Client Registration（RFC 7591 / 7592） | 2026-09-09 に不要と判断。クライアントは seed / DB で管理する。`/connect/register` と Clients 管理画面は作らない |
| Pairwise Subject Types（OIDC Core §8） | 2026-09-09 に不要と判断。`sub` は `public` のみ |
| DPoP（RFC 9449） | 2026-09-09 に不要と判断。Bearer トークンの盗難対策は短寿命 AT + RT ローテーション + `private_key_jwt` で足りるとする |
| ユーザーグループ / ロール管理 | 2026-09-09 に不要と判断。必要ならカスタムクレーム（`roles` などを json 型で定義）で代替する |
| SCIM 2.0（RFC 7643 / 7644） | 2026-09-09 に不要と判断。ユーザー管理は管理画面で行う |
| UMA 2.0 | 2026-09-09 に不要と判断。リソース所有者が第三者への認可を管理する仕組みで、OAuth / OIDC の中核から外れるうえ規模も大きい |
| FAPI の Grant Management | 2026-09-09 に不要と判断。同意を grant として識別・再利用・失効する仕組みで、本サンプルの同意画面（M3b）の範囲を超える |
| JARM（`response_mode=jwt`） | 2026-09-09 に不要と判断。認可応答自体を JWT 化して署名する仕様。`query` / `form_post` で足りるとする |

### 着手順

冒頭の「マイルストーン計画」を参照してください。M2 / M2'（JWT Replay 検出 / `nonce` 厳密検証 / 監査ログ / カスタムクレーム）/ M2''（HTTPS / レート制限 / CORS / 自動テスト）は完了し、次は M3（🌐 方式 A）です。
🌐 なしで残る候補は ACR / AMR のモデル化、🖥️ の TOTP / MFA とメール確認、Resource Indicators の認可要求時束縛です。
「仕様と実装の乖離」に挙げた MUST 4 件（キャッシュ制御、UserInfo の POST、POST 認可要求と方式 B の移設、リフレッシュ時のスコープ縮小）は
2026-09-09 にすべて対応しました。次はセキュリティヘッダーを、ログイン画面と同意画面を作る前に入れます。

---

## 参考

- `SPEC.md` — 実装仕様書。Phase ごとの設計と実装状況の概要
- `__Other/FEATURE_ANALYSIS.md` — Phase B の元になった機能調査
- `C:\Users\machi\Desktop\IdServer` — 2026-09-09 に調査した他実装。SimpleIdServer（Apache 2.0）、Authlete の C# リファレンス実装（Apache 2.0）、
  Thinktecture AuthorizationServer（BSD 系、2016 年で開発終了）、damienbod の Blazor BFF テンプレート（MIT）。
  上記の MUST 違反・小項目・設計の受け皿はここから抽出した。コードを流用する場合は帰属表示が必要
