# 実装 TODO

`SPEC.md` の実装チェックリスト兼、本プロジェクトの唯一のバックログです。
完了済みは `[x]`、未着手は `[ ]` で管理します。

*最終更新: 2026-09-05*

---

## マイルストーン計画

2026-09-05 に決定した進め方です。ブラウザリダイレクト（方式 A）は API-only の作業を終えてから着手します。

| M | 内容 | 状態 |
|---|------|------|
| M1 | トークンライフサイクル（Phase 4 前半）: `/connect/revoke`・`/connect/introspect`・JTI 失効リスト・SEC-04 ファミリー失効・スキーママイグレーション機構・鍵ローテーション・クリーンアップジョブ・TestClient `revoke` / `introspect` | ✅ 完了（2026-09-05） |
| M2 | API-only 候補の一部（Phase B から選択）: Device Authorization Grant、Resource Indicators + ES256、DPoP、Dynamic Client Registration、監査ログ / レート制限、鍵の事前公開（2 段階ローテーション） | 🔲 次 |
| M3 | ブラウザリダイレクト（方式 A）と、それを前提とする項目: 同意画面、`/connect/logout` とセッション管理、`prompt`、外部 IdP、Front-Channel Logout | 🔲 M2 の後 |

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

- [ ] `/connect/authorize` を標準のブラウザリダイレクト方式（`SPEC.md` §6.3 方式 A）で実装する
      現在は方式 B（API 専用・資格情報直送）のみ。方式 B は信頼モデルが ROPC 相当のため、
      同意画面・`prompt` パラメーター・外部 IdP 連携が成立しません
- [ ] トークン有効期限が当初仕様と異なる（`SPEC.md` SEC-07）。
      リフレッシュトークンは仕様 30 日に対し実装 1 日（86400 秒）、
      認可コードは仕様 10 分に対し実装 2 分（120 秒）。仕様と実装のどちらに寄せるか要判断。
      方式 3 ではアクセストークンの有効期限（現在 3600 秒）が失効の反映遅延そのものになるため、短縮も含めて判断する
- [ ] HTTPS 構成が未対応（`SPEC.md` SEC-01）。現在は AuthServer / ResourceServer とも HTTP。
      ResourceServer の `RequireHttpsMetadata` は既定 `true` に変更済み（Development のみ `false`）
- [ ] レート制限が未実装（`SPEC.md` SEC-09）。Token / Authorize エンドポイントのブルートフォース対策
- [ ] CORS 設定が未実装（`SPEC.md` SEC-10）

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
- [x] TestClient: Authorization Code Flow 実装（方式 B のためローカル HTTP リスナーは不要）
- [x] TestClient: トークンリフレッシュ実装
- [x] 結合テスト: Authorization Code Flow 全体フロー
- [x] 結合テスト: PKCE 不一致で拒否確認（`invalid_grant`）
- [x] 結合テスト: 認可コード再利用で拒否確認（`invalid_grant`）
- [ ] `/connect/authorize` の GET（ブラウザリダイレクト）実装 ※方式 A
- [ ] `/account/login` Blazor ページ実装 ※方式 A
- [x] `state` の検証（サーバーは保存・返却、TestClient が送信値との一致を検証。方式 A では redirect 先で同様に検証する）

## Phase 3: OIDC 準拠

ID Token と UserInfo は Phase 2 の実装に伴い先行して対応済みです。

- [x] ID Token 生成（`nonce`）
- [x] Authorization Code Flow レスポンスに `id_token` 追加
- [x] `/connect/userinfo` 実装 (`Endpoints/UserInfoEndpoint.cs`)
- [x] スコープに基づくクレーム返却制御（`openid`, `profile`, `email`）
- [x] Discovery メタデータに `authorization_endpoint` / `userinfo_endpoint` を追加
- [x] TestClient: UserInfo 取得実装 (`userinfo` コマンド)
- [x] 結合テスト: UserInfo レスポンス検証
- [x] ID Token に `at_hash`, `auth_time`, `amr` を追加（`email_verified` も boolean 化、有効期限は `IdTokenLifetimeSeconds` に分離）
- [x] Discovery メタデータ拡張（`claims_supported`, `subject_types_supported`, `request_uri_parameter_supported`）
- [ ] Discovery に `response_modes_supported` を追加 ※方式 A 実装後（方式 B に該当する標準値がない）
- [ ] Dapper による同意情報データアクセス実装
- [ ] `/account/consent` Blazor ページ実装 ※方式 A が前提
- [ ] 同意済みスコープの DB 保存・参照
- [ ] 同意済みの場合は同意画面スキップ
- [x] TestClient: ID Token のデコード・表示（`token` コマンドがペイロードのクレームを一覧表示）
- [x] 結合テスト: ID Token クレーム検証（各クレームの JSON 型、`at_hash` の独立計算との一致を確認）
- [ ] 結合テスト: 同意フロー動作確認

## Phase 4: 運用機能

前半（トークンライフサイクル）は M1 で実装済み。ログアウト・セッション関連は方式 A（M3）が前提です。
2026-09-05 に AuthServer / ResourceServer を実起動して全項目を実機検証しました。

- [x] Dapper による失効トークンデータアクセス実装 (`Services/RevokedTokenService.cs`)
- [x] スキーママイグレーション機構（`schema_migrations`、v1 `consumed_at` / v2 `source_code_hash`）
- [x] `/connect/revoke` 実装 (`Endpoints/RevocationEndpoint.cs`)
- [x] 失効リスト管理（JTI ベース、DB 永続化）
- [x] `/connect/introspect` 実装 (`Endpoints/IntrospectionEndpoint.cs`)
- [x] 認可コード再使用時のファミリー失効（SEC-04）と、ローテーション後の RT リプレイ検知
- [x] クライアント認証の共通化 (`Endpoints/ClientAuthentication.cs`) と AT 検証の共通化 (`TokenService.ValidateAccessTokenAsync`、`typ=at+jwt` 必須)
- [x] 鍵ローテーション機能（新鍵生成・旧鍵猶予期間・DB 管理。管理画面 `/signing-keys` と `SigningKeyRotationDays` による自動）
- [x] JWKS キャッシュ制御ヘッダー（`Cache-Control`、`JwksCacheMaxAgeSeconds`）
- [x] 期限切れ認可コード・リフレッシュトークンのクリーンアップジョブ (`Services/MaintenanceService.cs`)
- [x] 期限切れ失効トークンのクリーンアップジョブ（猶予期間切れの鍵の退役も同じジョブ）
- [x] TestClient: トークン失効実装（`revoke --token-type all|access|refresh`）
- [x] TestClient: イントロスペクション実装（`introspect --token-type access|refresh`）
- [x] 結合テスト: 失効後は AuthServer（UserInfo / Introspection）が拒否し、ResourceServer は有効期限まで受理する（方式 3 の想定どおり）
- [x] 結合テスト: イントロスペクション応答確認（AT / RT / 失効済み / 不正 / ID Token は inactive）
- [x] 結合テスト: 鍵ローテーション後のトークン検証確認（旧鍵のトークンは猶予期間中受理。新鍵のトークンは JwtBearer の既定動作で最初の 1 要求のみ 401、JWKS 再取得後は受理）
- [ ] 鍵の事前公開（2 段階ローテーション: 新鍵を JWKS に先行公開し、`JwksCacheMaxAgeSeconds` 経過後に署名を切り替えて直後の 401 をなくす） ※M2 候補
- [ ] `/connect/logout` 実装 ※M3（方式 A）
- [ ] セッション管理（Cookie ベース） ※M3
- [ ] Blazor ログアウト確認画面 ※M3
- [ ] TestClient: ログアウト実装 ※M3

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

## Phase B: spec 範囲外の機能強化候補

`__Other/FEATURE_ANALYSIS.md` の調査結果をもとにした、`SPEC.md` に含まれない機能の候補です。
M2 ではこの中から一部を選んで実装します（方式 A が前提のものは M3 以降）。優先度は以下の 3 軸で付けています。

| 軸 | 内容 |
|----|------|
| 学習価値 | RFC / OIDC 仕様の理解が深まるか。標準化された仕様か |
| 現実的需要 | 実際の認証システムで広く使われているか |
| 実装コスト | 現在のコードベースへの追加が現実的か |

> `prompt` パラメーター・同意画面・外部 IdP 連携・Front-Channel Logout は、
> いずれもブラウザリダイレクトとセッションが前提です。`SPEC.md` §6.3 の方式 A
> （「仕様と実装の乖離」に計上）を先に実装しないと着手できません。

### B-1. 最優先（学習価値・需要ともに高い）

- [ ] ★★★ **JWT Replay 検出** — RFC 7519 §4.1.7。`jti` ベースのキャッシュでリプレイ攻撃を防ぐ。Phase 4 の失効リスト（`revoked_tokens`）に相乗りできる。コスト: 低
- [ ] ★★★ **`prompt` パラメーター対応**（`none` / `login` / `consent` / `select_account`）— OIDC Core §3.1.2.1。SSO の核心。`prompt=none` で既存セッション検出、`prompt=login` で強制再認証。コスト: 中 ※方式 A 前提
- [ ] ★★★ **Pairwise Subject Types** — OIDC Core §8。クライアントごとに異なる `sub` を返すプライバシー保護。コスト: 中
- [ ] ★★☆ **PAR（Pushed Authorization Request）** — RFC 9126。認可リクエストを事前にサーバーへ送付し `request_uri` で参照。コスト: 中
- [ ] ★★☆ **複数署名アルゴリズム対応（ES256 等）** — RFC 7518。現在 RS256 固定。コスト: 中

### B-2. 高優先（実際のシステムで頻出）

- [ ] ★★☆ **Front-Channel Logout** — OIDC Front-Channel Logout 1.0。各 RP へ iframe でセッション終了を通知。コスト: 中 ※方式 A 前提
- [ ] ★★☆ **Back-Channel Logout** — OIDC Back-Channel Logout 1.0。Logout Token (JWT) をサーバー間で送付。コスト: 中
- [ ] ★★☆ **`nonce` の厳密検証** — OIDC Core §3.1.2.1。ID Token リプレイ対策（`state` の検証は Phase 2 に計上済み）。コスト: 低
- [ ] ★★☆ **外部 IdP 連携（ソーシャルログイン）** — Google / GitHub 等を外部 IdP として受け入れる Federation。コスト: 高 ※方式 A 前提
- [ ] ★★☆ **監査ログ** — ログイン・トークン発行・失敗履歴の永続化。コスト: 低（テーブル追加）
- [ ] ★☆☆ **TOTP / MFA** — RFC 6238 / RFC 4226。パスワード + TOTP の 2 要素認証。コスト: 中
- [ ] ★☆☆ **メール確認** — OIDC Core §5.1。`email_verified` クレームと連動。コスト: 中

### B-3. 中優先（学習価値は高いが実装コストが大きい）

- [ ] ★★☆ **Request Object / JAR** — RFC 9101。認可リクエストを JWT 化して署名・暗号化。コスト: 高
- [ ] ★★☆ **DPoP** — RFC 9449。Bearer トークン盗難対策（所有証明）。コスト: 高
- [ ] ★★☆ **Resource Indicators** — RFC 8707。複数リソースサーバー環境での `aud` 制限。コスト: 中
- [ ] ★☆☆ **CIBA** — OpenID CIBA 1.0。スマートフォン承認フロー。コスト: 高
- [ ] ★☆☆ **ユーザーグループ / ロール管理** — グループ単位のクレーム付与・アクセス制御。コスト: 中
- [ ] ★☆☆ **カスタムクレーム管理 UI** — 管理者が任意クレームを定義・付与。コスト: 中
- [ ] ★☆☆ **SCIM 2.0** — RFC 7642〜7644。ユーザープロビジョニング標準。コスト: 高

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

### 着手順

冒頭の「マイルストーン計画」を参照してください。M2 の候補は上記 B-1〜B-3 のうち方式 A を前提としないもの
（Device Authorization Grant は Phase 5、Resource Indicators / ES256 / DPoP / DCR / 監査ログ / レート制限）から選びます。

---

## 参考

- `SPEC.md` — 実装仕様書。Phase ごとの設計と実装状況の概要
- `__Other/FEATURE_ANALYSIS.md` — Phase B の元になった機能調査
