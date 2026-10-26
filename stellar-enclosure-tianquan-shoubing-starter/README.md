# Tianquan-Shoubing SQL identity authority

Servlet 与 Gateway 的正式资源服务器链使用同一套签名验证、SQL 当前状态查询和同步审计回执合同。`IdentityAuthorityClientResolver` 是既有端口的适配边界：IdP 数据库 owner 提供本地实现，其他服务使用固定 AUTH-07 地址和有限的 SERVICE 凭据绑定。目标不能来自 JWT、Header 或请求体。

每次受保护请求执行本地 JWT 校验，再按已验证 issuer 查询 `IdentitySecurityStateRequest(ACCESS_VALIDATION)`。返回的 issuer、subject、client、resource、authorization、securityVersion 和授权期限必须与证明一致。负向状态立即拒绝；超时、错误响应、缺少状态均不可使用旧结果继续。

审计 `append`/`appendStrict` 均要求 `IdentityAuditReceipt`：事件 ID、核心合同 fingerprint、发送 issuer/client、目标 Resource、STORED 和确认时间必须匹配。正式实现不写 Redis Stream、receipt bucket、磁盘 spool，也没有本地重放任务。审计引用是包含域前缀的 SHA-256，不依赖本地 HMAC 文件；令牌原文只进入状态请求体，不进入审计、日志或回执。

## 普通资源服务器配置

以下为字段说明示例，需由受控初始化流程预先建立相应 Client、Resource 与 Scope 授权。此文件不创建注册，也不证明运行环境已就绪。

```yaml
egon:
  cola:
    platform:
      tianquan:
        shoubing:
          enabled: true
          register-filter: false
          resource-uri: https://api.example/orders
          trusted-issuers:
            tenant-a:
              issuer: https://idp.example/tenants/1001
              jwks-uri: https://idp.example/tenants/1001/.well-known/jwks.json
              realm-key: tenant:1001
              realm-type: TENANT
              tenant-id: "1001"
              status: ACTIVE
              trust-version: 1
          usage-observation:
            enabled: true
            receiver: APPLICATION
            fallback-issuer: https://idp.example/tenants/1001
          service-client:
            app-id: orders
            registration-id: identity-tenant-a
            credential-versions:
              identity-tenant-a: 1
          authority:
            base-uri: https://identity-internal.example
            timeout: 2s
            bindings:
              tenant-a:
                issuer: https://idp.example/tenants/1001
                registration-id: identity-tenant-a
                source-resource: https://api.example/orders
                audience: https://api.example/identity
                context: TENANT
                tenant-id: "1001"
                scopes:
                  - tianquan-shoubing:security-state:resolve
                  - tianquan-shoubing:audit:append
```

`identity-tenant-a` 必须对应 Spring OAuth2 Client 的 Client Credentials 注册；issuer 与租户上下文必须精确一致。每个 ACTIVE issuer 都必须有本服务 `resource-uri` 的 authority binding；一个 `(issuer, source-resource)` 只能配置一次。`source-resource` 默认等于本服务 `resource-uri`。Gateway 为不同上游 Resource 分别配置绑定，使用归属该 Resource 的受控 SERVICE 注册；IdP 仍从数据库验证实际发送 Client 的源 Resource，不信任此配置来扩大权限。PLATFORM binding 使用 `context: PLATFORM` 并省略 tenant-id。Refresh context 调用额外要求 `tianquan-shoubing:refresh-context:resolve`；普通访问验证不会自动申请此 Scope。

提供名为 `defaultValidator` 的现有 Validator 和唯一或 Primary 的 MeterRegistry。`idpSecurityAuditReady` 验证可信 issuer 路由是否完整，不把静态装配成功当成远端数据库健康证明；每次调用仍必须收到已持久化回执。IdP 本地 owner 通过 `IdentityAuthorityClientResolver` Bean 替换 HTTP resolver，在本地数据库终止状态/审计调用，不递归请求自己。`forResource(verifiedIssuer, expectedResource)` 的本地默认实现仍经过 owner 的精确目标检查，不能查询其他 owner 的资源。

HTTP authority 请求与 SERVICE Token 获取均使用有限超时、禁止重定向；authority 响应上限 64 KiB，请求上限 32 KiB。401 最多使 SERVICE 凭据失效并重试一次，其他错误不重试。事件 ID 在重试间不变，接收方按同一 SQL 合同去重。

旧 `audit.spool-directory`、`audit.hmac-key-file`、`audit.stream`、Redis 状态键和撤销配置、legacy issuer cutover 配置会触发明确迁移错误。已有磁盘文件不会被自动清理。

## Reactive 与 Gateway

`ReactiveIdentityAuthorityClient` 把阻塞 owner/HTTP 调用放到调用方提供的有界 Scheduler；空响应产生错误，不以空 Publisher 代替失败。GatewayAdapter 的 JWT/SQL/审计整段验证仍放在 bounded-elastic worker，不能直接在 Netty event loop 调用同步客户端。

GatewayAdapter 只从服务端生成的 `GatewayAuthContext.attributes` 选择固定目标：

```yaml
egon.cola.platform.tianquan.shoubing.yuheng:
  enabled: true
  route-resources:
    orders:
      biz-code: commerce
      app-code: orders
      environment: prod
      resource-uri: https://api.example/orders
    mcp:
      resource-uri: https://api.example/mcp
```

三元组必须完整匹配；直接 Resource URI 必须出现在该有限列表中；两种属性同时存在时必须指向同一个目标。未知或冲突路由拒绝。配置只选择 expectedResource，不包含启停、撤销、权限或安全版本状态；这些仍由 SQL authority 按请求判断。Gateway 的旧独立 Redis、issuer/JWK 和投影键配置不再生效。每个该列表中的 Resource 还必须在 `authority.bindings` 中有相应 `(issuer, source-resource)` 的 SERVICE 绑定；缺失时拒绝该请求，不能使用本 Gateway 的身份替代上游身份。

## 验证边界

Starter 单元/框架测试覆盖真实本地 JWT 签名验证、AUTH-07 mock transport、响应约束、逐请求 SQL port 调用、同步回执与 401/403/503、无业务执行和 Reactor 调度。Gateway 测试覆盖未知路由、目标冲突、当前撤销、审计失败和非事件循环调度。测试替身不等于真实 PostgreSQL 并发/事务证明；外部注册、运行进程与真实数据库验收需另行显式执行。
