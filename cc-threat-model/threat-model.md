# Threat model — Temporal server (github.com/cx-benchmark/temporal)

Reviewed whole at bf81a4c. Paths are repo-relative. "Default authorizer" = `authorization.authorizer: default` + `claimMapper: default`; "noop mode" = both empty, which is the code default.

## system

**What it is.** The Temporal server (Go module `go.temporal.io/server`): a durable-execution platform that persists and schedules Workflows/Activities whose code runs in SDK workers outside this repo (README.md; "originated as a fork of Uber's Cadence"). Tenancy unit is the **namespace**.

**One binary, several services** (cmd/server/main.go → `temporal.NewServer`; `--service` default = temporal/server.go `DefaultServices` = frontend, history, matching, worker; `internal-frontend` only when requested):
- **frontend** (service/frontend): gRPC server registering WorkflowService, AdminService, OperatorService, grpc health and gRPC reflection (service.go `Start`). HTTP server on `rpc.httpPort` (off when 0, fx.go `httpEnabled`) carrying a grpc-gateway for WorkflowService+OperatorService (http_api_server.go), Nexus HTTP routes (nexus_operation_http_handler.go, nexus_completion_http_handler.go) and OpenAPI docs (openapi_http_handler.go).
- **internal-frontend**: same module, served with internode TLS options and a claim mapper that grants every caller System Admin (temporal/fx.go `genericFrontendServiceProvider`; common/authorization/claim_mapper.go `internalClaimMapper`). Server-side SDK clients target it when `publicClient.hostPort` is empty and internal-frontend is configured (common/resource/fx.go).
- **history** (service/history, chasm/ framework, chasm/lib/{activity,callback,nexusoperation,scheduler,workflow,namespacereplication}): mutable state, event histories, timer/transfer/outbound queues (callbacks, Nexus calls), replication. Serves HistoryService plus CHASM library services (service/history/service.go:87-89 `chasmRegistry.RegisterServices`).
- **matching** (service/matching): task queues, poll dispatch, worker versioning (MatchingService, service/matching/service.go:70).
- **worker** (service/worker): system workflows (batcher, scheduler, worker deployments, migration, DLQ, delete-namespace, scanners, archival) run through SDK clients against the frontend, per-namespace on task queue `temporal-sys-per-ns-tq` (common/primitives/task_queues.go; service/worker/fx.go). Its own gRPC server serves only health + reflection (service/worker/service.go:283-286).
- **Persistence**: Cassandra (gocql), MySQL / PostgreSQL / SQLite plugins (common/persistence/sql/sqlplugin/*, imported in cmd/server/main.go); visibility on SQL or Elasticsearch (common/persistence/visibility/store/{sql,elasticsearch}); archival providers filestore, s3store, gcloud (common/archiver).
- **Membership**: ringpop over TChannel on `membershipPort` (common/membership/ringpop/factory.go).
- **Shipped CLIs**: temporal-cassandra-tool, temporal-sql-tool, temporal-elasticsearch-tool (tools/{cassandra,sql,elasticsearch}, schema from schema/embed.go) and tdbg (tools/tdbg, an AdminService client).
- **Embedding API**: package temporal (server_option.go: `WithAuthorizer`, `WithClaimMapper`, `WithAudienceGetter`, `WithTLSConfigProvider`, `WithTokenProvider`, custom frontend interceptors) and temporaltest (README: "helpers for writing end to end tests against a real Temporal server").

**Principals the code trusts.**
- Operator: static config YAML, optionally rendered as Go text/template + sprig with env access (common/config/loader.go `processConfigFile`, enabled by a `# enable-template` comment in the first 1 KiB); dynamic config file (`dynamicConfigClient.filepath`); CLI flags/env (cmd/server/main.go); SQL `passwordCommand`, which the server executes (common/config/persistence.go `ResolvePassword`).
- Internode peers: anything that reaches history/matching/worker/internal-frontend; those servers have no authorization interceptor (service/fx.go `getUnaryInterceptors`, service/worker/fx.go `ServerProvider`).
- Datastores (DB, Elasticsearch), archival stores, JWKS key sources, remote clusters registered via `AddOrUpdateRemoteCluster`.
- Frontend caller identity = `Claims` produced by the ClaimMapper (common/authorization/interceptor.go).

**Build, ship, deploy (own files).**
- .goreleaser.yml: builds temporal-server (cmd/server, tag `disable_grpc_modules`), the three schema tools and tdbg; `CGO_ENABLED=0`; linux/darwin/windows × amd64/arm64; archives include `./config/*`; sha256 checksums. .github/workflows/release.yml runs `goreleaser release` on a GitHub "released" event (`contents: write`).
- Docker: docker/targets/server.Dockerfile (alpine `ALPINE_TAG` 3.23.4 from docker/docker-bake.hcl, not digest-pinned per its comment; user `temporal` uid 1000; CMD docker/scripts/sh/entrypoint.sh → `exec temporal-server start` with no config flags → embedded template common/config/config_template_embedded.yaml via `config.WithEmbedded`). admin-tools.Dockerfile bundles the CLIs and schema and idles.
- build-and-publish.yml pushes images to Docker Hub (`IMAGE_REPO` default `temporaliotest`) on main, cloud/*, release/* with `DOCKERHUB_TOKEN`; promote-*-image.yml (workflow_dispatch) promote tags to the temporalio registry.
- No production deployment manifests (Helm/K8s) are in the repo; develop/docker-compose and config/development*.yaml are dev setups.

## adversaries

**A1 — Unauthenticated network client of the frontend.**
- Code default is open: `GetAuthorizerFromConfig` returns `noopAuthorizer` (allows all) when `authorizer` is "" (common/authorization/authorizer.go). `GetClaimMapperFromConfig` returns `noopClaimMapper` (`System: RoleAdmin`, `AuthInfoRequired` false) when `claimMapper` is "" (claim_mapper.go).
- cmd/server/main.go only logs a warning when the noop authorizer is used without `--allow-no-auth`.
- Embedded/docker template: authorizer and claimMapper come from `TEMPORAL_AUTH_AUTHORIZER` / `TEMPORAL_AUTH_CLAIM_MAPPER` (default ""); frontend/internode TLS certs default ""; `requireClientAuth` "false"; `bindOnIP` default 127.0.0.1, but entrypoint.sh sets `BIND_ON_IP` to the container's resolved IP.
- In noop mode every frontend entry point below, AdminService included, is anonymous.

Frontend gRPC (`rpc.grpcPort`, 7233 in the shipped templates). Role column assumes the default authorizer (common/authorization/default_authorizer.go `Authorize`, roles from common/api/metadata.go, enforced by `Interceptor.Intercept` / `InterceptStream` registered in service/frontend/fx.go `GrpcServerOptionsProvider`):

| Entry point | Access under default authorizer | Check |
|---|---|---|
| grpc.health.v1.Health/Check | anonymous always | default_authorizer.go `IsHealthCheckAPI`; rate-limit exempt (fx.go `RateLimitInterceptorProvider`) |
| WorkflowService/GetSystemInfo | anonymous always | frontend_api.go `healthCheckAPI` |
| gRPC reflection (stream) | denied (method not in metadata → ScopeUnknown → deny); anonymous in noop mode | interceptor.go `InterceptStream`, metadata.go `GetMethodMetadata` |
| Any stream RPC | `CallTarget.Namespace` is "" → needs a System role; check skipped entirely when `system.disableStreamingAuthorizer`=true (default false) | interceptor.go `InterceptStream` |
| WorkflowService, 123 methods | namespace-scoped: 50 Reader, 70 Writer, 3 Admin (Register/Update/DeprecateNamespace) on the request's namespace, or the same role at System; cluster-scoped ListNamespaces, GetSearchAttributes, GetClusterInfo: System Reader | metadata.go `workflowServiceMetadata` |
| OperatorService | ListSearchAttributes: namespace Reader; Add/RemoveSearchAttributes, DeleteNamespace: namespace Admin; remote clusters and Nexus endpoint CRUD/List: System Admin | metadata.go `operatorServiceMetadata` |
| AdminService, 49 methods (incl. StreamWorkflowReplicationMessages, ImportWorkflowExecution, DeleteWorkflowExecution, DLQ, shard and task ops) | System Admin | metadata.go: AdminService prefix → ScopeCluster/AccessAdmin |

No `MaxRecvMsgSize` is set on any server (grep finds none), so grpc-go's default receive limit applies (library, out of view).

Frontend HTTP (`rpc.httpPort`, 7243 in the shipped templates):

| Route | Access | Check |
|---|---|---|
| GET /swagger.json, GET /openapi.yaml | anonymous (static spec) | openapi_http_handler.go: only `rateLimitInterceptor.Allow` |
| grpc-gateway routes for WorkflowService + OperatorService (paths from go.temporal.io/api annotations, out of view) | same as gRPC | http_api_server.go `inlineClientConn` runs the full frontend unary chain; `allowedHostsMiddleware` (`frontend.httpAllowedHosts`, default matches anything) wraps only the gateway mux |
| /namespaces/{ns}/task-queues/{tq}/nexus-services/… | Writer on {ns} (NexusService/DispatchByNamespaceAndTaskQueue) | nexus_operation_http_handler.go `parseTLSAndAuthInfo` + nexus_handler.go `interceptRequest` → `auth.Authorize` |
| /nexus/endpoints/{id}/services/… | Writer on the endpoint's target namespace; only worker-target endpoints accepted | `nexusContextFromEndpoint` + `interceptRequest` |
| /namespaces/{ns}/nexus/callback and /nexus/callback | Writer on the namespace named inside the `Temporal-Callback-Token` header (NexusService/CompleteNexusOperation); URL {ns} must match it | nexus_completion_http_handler.go `CompleteOperation`, `requestContext.interceptRequest` |

Gateway header forwarding: `Authorization-Extras`, `X-Forwarded-For`, client-name/version headers and `rpc.httpAdditionalForwardedHeaders` (trailing `*` = prefix), then grpc-gateway's `DefaultHeaderMatcher` (out of view) (http_api_server.go `incomingHeaderMatcher`). TLS state is copied into the gRPC peer so mTLS subjects reach the claim mapper (`serveHTTP`).

Nexus and callback routes are registered directly on the gorilla mux (fx.go `RegisterNexus*HTTPHandler`). They do not run the gRPC interceptor chain: each calls `GetAuthInfo`/`GetClaims`/`Authorize` itself, its audience getter returns "" (TODO in code), and the Host allow-list does not apply.

**A2 — Authenticated tenant** (JWT via common/authorization/default_jwt_claim_mapper.go: permissions claim (default "permissions") of `<namespace>:<role>`, or `permissionsRegex`; namespace `temporal-system` grants System roles). Reaches its own namespaces' APIs per role. Cross-namespace surfaces, as the code stands:
- Authorization namespace = `req.GetNamespace()` (interceptor.go). When it is empty and the request has a `task_token`, `NamespaceValidateIntercept` (runs **before** auth) fills it from the token's namespace_id (common/rpc/interceptor/namespace_validator.go `setNamespaceIfNotPresent`). The token-vs-request namespace check runs after auth in `StateValidationIntercept` and only while `frontend.enableTokenNamespaceEnforcement` is true (the default). Requests that name a namespace only by ID (e.g. DescribeNamespace, DeleteNamespace) authorize against namespace "", i.e. need a System role.
- Task tokens are plain protobuf with no signature or MAC (common/tasktoken/serializer.go).
- History page tokens are client-held, unsigned `tokenspb.HistoryContinuation` carrying RunId and BranchToken (service/history/api/token.go `DeserializeHistoryToken`). GetWorkflowExecutionHistory rejects a RunId mismatch. Outside the long-poll branch it checks the BranchToken with `ValidateBranchTokenForExecution`, gated by `history.enablePaginationTokenBranchValidation` (default true; shadow mode default false) (getworkflowexecutionhistory/api.go:235-262).
- Cross-namespace workflow commands are rejected by history unless `system.enableCrossNamespaceCommands` is set (default false; service/history/api/command_attr_validator.go:597). When it is set, the frontend authorizes target namespaces only for RespondWorkflowTaskCompleted's SignalExternal / StartChild / RequestCancelExternal commands (interceptor.go `authorizeTargetNamespaces`).
- Nexus callback tokens are JSON {v, base64(protobuf NexusOperationCompletion)}, neither signed nor encrypted (common/nexus/callback_token.go). They name the target namespace, workflow and run (or a CHASM ComponentRef).
- Completion callbacks attached in `prepareStartWorkflowRequest` and `prepareUpdateWorkflowRequest` (service/frontend/workflow_handler.go:700, :5616) are checked by common/callbacks/validator.go. `temporal://system` and `temporal://internal` always pass. The same-namespace check on the embedded token (`validateInternalCallback`) runs only for `temporal://internal`. Stored callback headers become request headers (chasm/lib/callback/invocable_outbound.go:79). `temporal://system` deliveries are routed by the namespace in that token header to a frontend HTTP client (chasm/lib/callback/request.go `routeSystemCallbackRequest`).
- Visibility List/Count: the store ANDs a namespace filter onto the parsed query (SQL: visibility/store/sql/visibility_store.go `buildQueryParams`; ES: elasticsearch/visibility_store.go:774 TermQuery on NamespaceID).
- Reserved task queues:
  - `tqid` rejects the `/_sys/` prefix for root partitions (common/tqid/task_queue_validator.go:144).
  - `CheckInternalPerNsTaskQueueAllowed` blocks scheduling onto `temporal-sys-per-ns-*` from a non-internal parent (task_queue_validator.go:84).
  - Poll-side restrictions on those queues: not verified.
- Roles are a bitmask compared numerically (`hasRole >= required`, default_authorizer.go; roles.go). A "worker" permission alone (RoleWorker=1) satisfies no API. `RegisterNamespace` is namespace-scoped Admin, so a holder of `<name>:admin` can register `<name>`; the namespace validator skips the registry lookup for it.
- A namespace Admin sets archival URIs (namespace_handler.go `validateHistoryArchivalURI`). filestore accepts any non-empty local directory path (common/archiver/filestore/util.go `validateDirPath`) and writes with the configured modes (embedded template `fileMode: "0666"`, `dirMode: "0766"`). ListArchivedWorkflowExecutions queries go through the archivers' sqlparser-based `queryParser.Parse` (common/archiver/{filestore,s3store,gcloud}/query_parser.go).

**A3 — Malicious worker / SDK client inside its namespace** (Writer). Supplies workflow commands, payloads, failures, query answers, Nexus task responses and heartbeats. History validates commands (service/history/api/command_attr_validator.go). Size limits: `limit.blobSize.error` 2 MiB per namespace (common/dynamicconfig/constants.go), HTTP gateway body 4 MiB, Nexus/callback body 2 MiB (common/rpc/grpc.go; enforced with `http.MaxBytesReader`). `limit.maxIDLength` is 1000. Nexus request headers matching `frontend.nexusRequestHeadersBlacklist` are stripped before reaching the handler worker (nexus_handler.go, the last step of `interceptRequest`).

**A4 — External HTTP peers.**
- Inbound: callers of the Nexus/callback routes (A1 or A2 depending on the authorizer).
- Outbound callback URLs: allow-list `callback.allowedAddresses` (chasm/lib/callback/config.go), default no rules, so only the two system URLs pass. Rules match `host:port` patterns and require https unless `AllowInsecure` (common/callbacks/address.go). The dialer has no IP filtering (common/http_transport.go `NewHTTPTransport`).
- Outbound Nexus calls to external endpoints created by a System Admin through OperatorService.
- JWKS fetch via `http.Get` or `file://` (default_token_key_provider.go `openURI`).
- Version check to Temporal's service: `frontend.enableServerVersionCheck` defaults to on unless `TEMPORAL_VERSION_CHECK_DISABLED` is set. It sends server version, OS/arch, DB name, cluster ID and SDK info (service/frontend/version_checker.go).
- Responses from all of these are parsed by the server.

**A5 — Peer on the internal network.** No authorization on these ports; only TLS when configured (common/rpc/rpc.go `GetInternodeGRPCServerOptions`, which requires client certs only if `global.tls.internode.server.requireClientAuth`; template default "false"):

| Entry point | Access | Check |
|---|---|---|
| history gRPC: HistoryService (78 methods) + CHASM ActivityService (10), SchedulerService (9), NexusOperationService (6), NamespaceReplicationService (1); reflection | anonymous at app layer | service/fx.go `GrpcServerOptionsProvider` + history/fx.go `HistoryAdditionalInterceptorsProvider` (health/CHASM only) |
| matching gRPC: MatchingService (43 methods); reflection | anonymous at app layer | same |
| worker gRPC (health, reflection) | anonymous | service/worker/fx.go |
| internal-frontend gRPC/HTTP (when enabled) | every caller gets System Admin | `internalClaimMapper` |
| ringpop `membershipPort` | plaintext TChannel unless `system.enableRingpopTLS` (default false) | ringpop/factory.go `getTChannel` |
| pprof HTTP (`global.pprof.port`: 0 = off in embedded template, 7936 in config/development*.yaml) | anonymous; binds "localhost" when host is empty | common/pprof/pprof.go |
| Prometheus/OTel metrics listener (when configured) | out of view | common/metrics (not read) |

**A6 — Malicious or compromised remote cluster.**
- Calls the frontend AdminService replication APIs (GetReplicationMessages, StreamWorkflowReplicationMessages, GetNamespaceReplicationMessages, …) and needs System Admin under the default authorizer.
- Its replication tasks are applied by history (service/history/replication: out of view).
- Outbound connections to remote clusters use `global.tls.remoteClusters` and an embedder `TokenProvider`. `remoteClusterAuth.require` without a provider fails boot (temporal/fx.go:270), and a provider without remote-cluster TLS also fails boot (:277).

**A7 — Local unprivileged user on a server host.** Can reach pprof on localhost when enabled and listeners bound to 127.0.0.1. Can read or write filestore archives (0666/0766 defaults) and SQLite files if their permissions allow. JWKS `file://` paths are read by the server.

**A8 — Embedders / plugin authors** (custom Authorizer, ClaimMapper, interceptors, persistence or archiver factories passed through `temporal.ServerOption`) are outside the system: their code is trusted. For the library API, inputs an embedding application passes on from its own users are ordinary API requests that cross the same interceptors.

**Entry points left out individually**: the 123 WorkflowService, 12 OperatorService and 49 AdminService methods (service/frontend/{workflow,operator,admin}_handler.go, registered in service/frontend/service.go `Start`), 78 HistoryService and 43 MatchingService methods (service/history/service.go:87, service/matching/service.go:70) and 26 CHASM library methods (chasm/lib/*/library.go `RegisterServices`): about 330 RPCs, summarized by group above.

## assets

1. **Namespace-isolated workflow data**: histories, payloads, memos, search attributes, visibility rows, schedules, Nexus operation state. Isolation is enforced at:
   - frontend `authorization.Interceptor` (namespace from the request or task token);
   - `NamespaceValidatorInterceptor.checkNamespaceMatch`;
   - store-side namespace filters (SQL `buildQueryParams`, ES TermQuery);
   - history cross-namespace command check (command_attr_validator.go:597);
   - `validateInternalCallback`;
   - history page-token branch validation.
   Handlers past the interceptors trust the namespace they are given (not verified per handler).
2. **Control-plane capabilities**: AdminService (raw history import/export, DLQ purge/merge, shard close, task removal, remote cluster registration, replication streams); OperatorService (search attributes, namespace deletion, Nexus endpoint registry); namespace Admin (namespace config, archival URIs).
3. **Credentials and keys**: DB/ES user and password from config or env-rendered templates, or from `passwordCommand` output; TLS keys from `certFile/keyFile` or inline `certData/keyData` (common/rpc/encryption/local_store_*); JWKS public keys (default_token_key_provider.go); S3 via the AWS default credential chain (common/archiver/s3store `awsconfig.LoadDefaultConfig`); remote-cluster bearer tokens from the embedder `TokenProvider` (common/rpc/rpc.go `dialRemoteFrontendGRPCConnection`); bearer tokens kept on the request context (`AuthHeader`, interceptor.go `EnhanceContext`). CI secrets (Docker Hub, GitHub App keys, Anthropic key) live in GitHub Actions secrets.
4. **Outbound request capability** (callbacks, Nexus endpoints, JWKS, remote clusters, version check): see A4.
5. **Availability**: per-host / per-namespace RPS and concurrency limiters (service/frontend/fx.go `RateLimitersProvider`, `NamespaceRateLimitersProvider`, `NamespaceCountLimitInterceptorProvider`), persistence QPS limits, blob/history size limits.
6. **Integrity of shipped artifacts**: release binaries and checksums (goreleaser) and Docker images (build-and-publish.yml).

**Trust boundaries.**
- B1 client → frontend gRPC/HTTP: interceptor order (fx.go): mask errors → service error → routing key → **NamespaceValidateIntercept** → namespace log → metrics → **authorization** → handover → redirection → … → **StateValidationIntercept** → count/rate limits → custom interceptors → retry. `headers.StripPrincipal` removes inbound `temporal-principal-*` in both unary and stream paths (interceptor.go). The principal header is re-set when `frontend.enablePrincipalHeader` (default true). Exceptions: Nexus/callback/OpenAPI HTTP routes (own checks, see A1).
- B2 frontend/worker → history/matching, history ↔ matching: internode TLS only; internal requests carry caller info headers, not authorization.
- B3 internal-frontend: authenticated only by internode TLS, then System Admin.
- B4 cluster ↔ cluster: AdminService under the frontend authorizer inbound; `global.tls.remoteClusters` + `TokenProvider` outbound (temporal/fx.go:270-279).
- B5 server → SQL: visibility WHERE clauses are built as SQL text. User string values are escaped with a replacer (`'`→`''`, backslash and control characters; visibility/store/sql/query_converter.go `buildValueExpr`) and emitted unquoted-escaped through `UnsafeSQLString` (store/query/util.go); only page-token fields and LIMIT are bind parameters (sqlplugin/mysql/query_converter.go `BuildSelectStmt`). SQLite FTS embeds tokens in a MATCH string (sqlplugin/sqlite/query_converter.go `buildFtsQueryString`). Query grammar via github.com/temporalio/sqlparser (store/query/converter.go). ES uses typed olivere/elastic builders.
- B6 server → external HTTP: callback allow-list (validator at request time); outbound transport common/http_transport.go.
- B7 operator → server: config/template files, dynamic config, `passwordCommand`, TLS files, `nexusoperation.callback.endpoint.template` (text/template, chasm/lib/nexusoperation/config.go).

## out-of-scope
What follows reports the repositories' own statements and exempts nothing from the audit.


No SECURITY.md or other security policy exists in the repository. What its own files concede or require of deployers:
- No-auth is the default and only warned about: cmd/server/main.go logs "Not using any authorizer and flag `--allow-no-auth` not detected. Future versions will require using the flag `--allow-no-auth` if you do not want to set an authorizer." claim_mapper.go: "No-op claim mapper that gives system level admin permission to everybody". The deployer must set `global.authorization.authorizer`/`claimMapper` (or embed custom ones) and JWKS `keySourceURIs`.
- common/api/metadata.go: the Access field "is completely advisory. Any authorizer implementation may implement whatever logic it chooses, including ignoring this field."
- TLS is opt-in: all template TLS fields default empty and `requireClientAuth` "false" (common/config/config_template_embedded.yaml, config/docker.yaml, docker/config_template.yaml). Internode mTLS, frontend TLS and `system.enableRingpopTLS` are the deployer's job.
- docs/architecture/nexus.md: "Wildcard patterns (*) and insecure (HTTP) callbacks are intended for development only. For production, restrict allowed hosts and set AllowInsecure to false whenever HTTPS/TLS is supported."
- frontend.httpAllowedHosts (constants.go): "By default any Host header is allowed."
- common/nexus/callback_token.go: "More fields and encryption support will come later." (tokens are unprotected today).
- nexus_operation_http_handler.go: "For security reasons, at the moment only worker target endpoints are considered valid" for inbound dispatch by endpoint.
- `system.forceSearchAttributesCacheRefreshOnRead`: "should not be turned on in production"; `TEMPORAL_TEST_DATA_ENCODING` (serialization/codec.go): "should only be used for testing; and never set it in production".
- docs/development/testing.md: testhooks are only active with `-tags=test_dep`. Confirmed by build tags in common/testing/{testhooks,grpcfaultstest,httpfaultstest} and chasm/lib/tests/fx.go (`//go:build test_dep`); release builds do not set it (.goreleaser.yml).
- config/jwt/README.md and config/development-jwt.yaml are "for test and development purposes"; CONTRIBUTING.md runs the server with `--allow-no-auth`.
- docker/config_template.yaml: "TODO: Remove this file after temporalio/docker-builds repository is archived".
- tools/{cassandra,sql,elasticsearch}/README.md carry "For production" setup notes (replication and TLS), not security policy.

## production

One line per top-level area:
- **cmd/server**: production; the released `temporal-server` entry point (.goreleaser.yml).
- **cmd/tools/{cassandra,sql,elasticsearch,tdbg}**: production; released CLIs (.goreleaser.yml, admin-tools image). The other cmd/tools/* (codegen, gen*, protogen, protoc-gen-go-chasm, getproto, test-runner, ci-notify, flakereport, check-dependencies, optimize-test-sharding, parallelize, fairsim, test) are build/CI tooling.
- **service/**: production (frontend, history, matching, worker).
- **common/**: production shared code. Exceptions: common/testing/* are test helpers whose server-side hooks compile to no-ops without `test_dep`.
- **chasm/**: production framework and libraries (frontend and history fx modules). chasm/lib/tests and chasm/chasmtest are test-only (`test_dep` / test helpers).
- **client/**: production internode RPC clients.
- **api/**: production; generated Go from proto/internal (internal service APIs, persistence and token protos), compiled in.
- **proto/**: build input for api/ (buf).
- **temporal/**: production server assembly and public embedding API.
- **temporaltest/**: published library, but for users' tests (README).
- **nexusworkflowref/**: production (imported by service/frontend/nexus_completion_http_handler.go).
- **schema/**: production; DB/ES schemas embedded in the tools (schema/embed.go), SQLite schema embedded in the server (schema/sqlite/setup.go), copied into the admin-tools image.
- **config/**: shipped in release archives (`files: ./config/*`); development configs plus docker.yaml and dynamicconfig samples. common/config/config_template_embedded.yaml is the config the Docker image actually uses.
- **docker/**: production packaging (Dockerfiles, bake file, entrypoint).
- **tools/**: tdbg, sql, cassandra, elasticsearch and common/schema back the released CLIs. ci-notify, flakereport, testrunner, fairsim, optimize-test-sharding, parallelize and tests are CI/dev tooling.
- **tests/**: functional/integration tests.
- **develop/**: dev docker-compose, Grafana/Prometheus, CI helper scripts.
- **docs/**: documentation.
- **.github/**: CI. Note claude-review-teams.yml runs on `pull_request_target` with secrets, gated by org-membership/write checks, and checks PR head out into pr-head/. build-and-publish/release/promote workflows hold publishing credentials.
- **.claude/, .cursor/, .vscode/, AGENTS.md, CONTRIBUTING.md, Makefile**: developer tooling and docs. The Makefile builds the same binaries with `CGO_ENABLED=0` and `-tags disable_grpc_modules`, and adds `TEMPORAL_DEBUG` for `temporal-server-debug`.

## facts

- **Security policy**: none (no SECURITY.md anywhere in the tree). .github/.golangci.yml enables errcheck, depguard, forbidigo and others, not gosec. govulncheck runs on PRs (.github/workflows/govulncheck.yml).
- **Template engines**: no HTML templating (no `html/template` import). `text/template` (no escaping) is used for operator config with sprig (common/config/loader.go), for the Nexus callback URL template from dynamic config (chasm/lib/nexusoperation/config.go; executed in task_handler_*.go and service/history/hsm/nexusoperations/executors.go), and for CLI output (cmd/server/main.go).
- **Serialization**:
  - RPC: protobuf/gRPC. HTTP gateway: protojson (service/frontend/protojson_marshaler.go).
  - Persistence blobs: Proto3 by default, JSON decoding always accepted (common/persistence/serialization/codec.go, serializer.go).
  - Task tokens: raw protobuf (common/tasktoken). History page tokens: raw protobuf (service/history/api/token.go). Nexus callback tokens: JSON + base64 protobuf (common/nexus/callback_token.go). None is signed.
  - Config: YAML via gopkg.in/yaml.v3 (common/config/loader.go); dynamic config YAML (common/dynamicconfig `LoadYamlFile`).
  - Page tokens: JSON (sqlplugin `DeserializeVisibilityPageToken`, sql/common.go `deserializePageTokenJson`, history_store.go) and `encoding/gob` into concrete types (common/persistence/sql/common.go `gobDeserialize`, used by task_queues.go and cluster_metadata.go).
  - JWKS: JSON via go-jose (default_token_key_provider.go).
  - Other parsers reached by clients: the visibility/archival query language (github.com/temporalio/sqlparser); JWTs (golang-jwt/jwt v4); Nexus HTTP (nexus-rpc/sdk-go v0.7.0, common/nexus/nexusrpc); Nexus links (common/nexus/link_converter.go); callback URLs (net/url).
- **Authentication**: no sessions or cookies. Each request is authenticated by:
  - a bearer JWT in metadata/header `authorization` (name configurable via `authHeaderName`), plus `authorization-extras`;
  - and/or the verified mTLS client cert subject (interceptor.go `GetAuthInfo`, `PeerCert`).
  The default JWT mapper:
  - accepts RS256/ES256 only (`SupportedMethods`; HMAC refused) and needs a `kid`;
  - validates registered claims with golang-jwt v4 `claims.Valid()` (library behaviour out of view);
  - checks audience only when `authorization.audience` is non-empty;
  - refreshes JWKS every `refreshInterval` (templates: 1m);
  - ignores the TLS subject: with a client cert and no token it returns claims with no roles (`GetClaims`).
  With the JWT mapper and no token and no client cert, claims are nil. The default authorizer then denies everything except health/GetSystemInfo.
- **Defaults that change exposure** (code or shipped templates):
  - authorizer/claimMapper "" → allow-all, System Admin (authorizer.go, claim_mapper.go);
  - TLS off, `requireClientAuth` false;
  - Docker binds the container IP (entrypoint.sh);
  - HTTP API on 7243 (templates);
  - `frontend.httpAllowedHosts` match-all;
  - `system.enableRingpopTLS` false;
  - `system.enableCrossNamespaceCommands` false;
  - `frontend.enableTokenNamespaceEnforcement` true;
  - `history.enablePaginationTokenBranchValidation` true;
  - `system.disableStreamingAuthorizer` false;
  - `frontend.exposeAuthorizerErrors` false;
  - `frontend.maskInternalErrorDetails` true;
  - `frontend.enablePrincipalHeader` true;
  - `callback.allowedAddresses` empty;
  - `frontend.nexusRequestHeadersBlacklist` strips internal headers;
  - `admin.enableListHistoryTasks` true;
  - `frontend.enableServerVersionCheck` on;
  - pprof off (port 0) in the embedded template and 7936 in development configs;
  - gRPC reflection registered on every service;
  - archival filestore modes 0666/0766 in templates.
  Dynamic config keys and defaults: common/dynamicconfig/constants.go and chasm/lib/*/config.go.
- **Build/hardening**: Go `go 1.27.0` (go.mod). Release builds use `CGO_ENABLED=0` and `-tags disable_grpc_modules`; no `-trimpath` or ldflags are set in .goreleaser.yml. `temporal_minimal` / `temporal_with_*` tags compile out Elasticsearch or GCS (docs/development/build-tags.md). `TEMPORAL_DEBUG` multiplies timeouts ×100 (common/debug). `test_dep` enables test hooks and fault injection. The image runs non-root (uid 1000) on alpine. GitHub Actions are SHA-pinned in the workflows read, except `anthropics/claude-code-action@v1` and `temporalio/public-actions/...@main`.
- **Where things are defined**:
  - Public API protos/HTTP annotations: go.temporal.io/api module (out of view). Internal protos: proto/internal → api/.
  - gRPC registration: service/*/service.go. HTTP routes: service/frontend/http_api_server.go, nexus_*_http_handler.go `RegisterRoutes`, openapi_http_handler.go. Nexus route shapes: common/nexus/routes.go.
  - Method scope/access: common/api/metadata.go. Authorizer: common/authorization. Interceptor chains: service/frontend/fx.go and service/fx.go.
  - Rate-limit priorities: service/frontend/configs/quotas.go. DB schemas: schema/. Config structs: common/config/config.go.
- **Languages**: Go throughout. About 3,124 .go files and 1.12M lines: ≈512k in _test.go, ≈112k generated .pb.go, ≈426k other. Also SQL/CQL schemas (113 .sql, 19 .cql), shell (27 files), YAML config/CI and Markdown docs.


<!-- written at these commits:
bf81a4c20009db89dc952592c9cfe770bafe66ee https://github.com/cx-benchmark/temporal
-->
