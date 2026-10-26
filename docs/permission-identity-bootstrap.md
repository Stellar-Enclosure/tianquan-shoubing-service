# Permission identity bootstrap (B0-I)

`bootstrap-permission-identities` is an explicit one-shot command in the IdP executable. It provisions only the finite OAuth clients, resource servers and client-resource grants listed in its private command file. It reuses `OAuthClientService`, `ResourceServerService`, the native repositories and the shared SQL transaction/Outbox. Ordinary startup never runs this command. `IdpDevelopmentClientBootstrap` no longer implements a Spring startup lifecycle.

## Prerequisites

The operator must prepare the intended database/schema, ACTIVE platform and tenant realms, signing keys and enabled realm security generations first. The existing isolated preparation workflow is documented by `IsolatedOAuthProvisioningIT`; its identity/tenant/realm preparation precedes this command. B0-I does not create realms, human administrators, memberships or signing keys, does not apply DDL and does not rotate existing credentials. PostgreSQL identity, stateless OAuth schema and Outbox metadata are checked before any owner mutation. A fresh operation rejects pre-existing client IDs, resource IDs, resource URIs and source tuples.

Use an assigned Snowflake `idMachineId` that does not overlap a running process. The command uses a minimal non-web context: no normal application scan, RPC provider, scheduler, Outbox dispatcher, identity migration runner or Redis connection. The generated Outbox messages are consumed later by the normal owner application.

## Protected inputs

Create an operator-owned directory with mode `0700`; all command, connection, password, encryption-key, pending-journal and receipt files must be regular owner-owned `0600` files. Final symlinks and non-normalized or relative paths are rejected. Do not place credentials in command arguments, environment variables, logs or the JSON command itself. Connection and encryption-key files refer to the existing prepared state.

A connection file uses this shape (all values below are illustrative):

```json
{
  "jdbcUrl": "jdbc:postgresql://127.0.0.1:5432/prepared_identity",
  "databaseName": "prepared_identity",
  "databaseOid": "12345",
  "databaseOwner": "identity_owner",
  "username": "identity_owner",
  "passwordFile": "/private/operator/database-password",
  "publicOrigin": "https://idp.example.com",
  "platformStoragePartitionId": 1,
  "idMachineId": 711,
  "platformManagementTenantId": 1001,
  "keyId": "existing-kek",
  "keyFile": "/private/operator/existing-kek"
}
```

`databaseOid` is the observed PostgreSQL OID encoded as a decimal string. Every borrowed physical connection must match the database name, OID, owner and current SQL user. The JDBC URL accepts one PostgreSQL host and database with no embedded credentials or query parameters. The command adds finite connection/socket timeouts. The existing encryption-key file contains exactly 32 bytes.

A minimal client command uses this shape:

```json
{
  "schemaVersion": 1,
  "operationId": "a2b98a9a-b2e4-46ee-b7e9-395913dc2538",
  "connectionFile": "/private/operator/connection.json",
  "credentialDirectory": "/private/operator/credentials",
  "actorSub": "existing-operator-subject",
  "clients": [{
    "issuer": "https://idp.example.com/platform",
    "definition": {
      "appId": "permission-ci", "clientId": "permission-ci", "clientName": "Permission CI",
      "clientType": "CONFIDENTIAL", "purpose": "SERVICE",
      "accessTokenTtlSeconds": 300, "refreshTokenTtlSeconds": 0,
      "redirectUris": [], "resourceUris": [], "allowedScopes": [],
      "browserBound": false, "postLogoutRedirectUris": []
    }
  }],
  "resources": [],
  "grants": []
}
```

The maximum command contains 16 clients, 16 resources and 32 explicit grants. Each resource entry contains `definition` (the existing `CreateResourceServerDTO` fields) and an explicit `enable` boolean. Its management client must be a platform client in the same command. Each grant contains `issuer`, `clientId`, `resourceServerId`, `grantType`, `tenantId` and `allowedScopes`; both its client and resource must occur in the command. Native validation enforces the SERVICE context and finite scope rules. Grants use the resource version just returned by its native owner, not a caller-supplied guess.

Optional USER clients are created after the resources. Their `resourceUris` must list only enabled resources in this command; native client creation records their exact USER delegation grants. Do not also list `USER_DELEGATION` under `grants`. The CLI does not create a human USER identity or bypass interactive authentication.

## Execute and recover

```sh
java -jar stellar-enclosure-tianquan-shoubing-admin/target/stellar-enclosure-tianquan-shoubing-admin-exec.jar \
  bootstrap-permission-identities \
  --command-file /private/operator/command.json \
  --receipt-file /private/operator/receipt.json
```

The command creates a private pending journal before provisioning. For each confidential client it journals the operation-owned filename and SHA-256 before writing the one-time plaintext to a new `0600` credential file. A collision never overwrites a file. The native SQL changes, native Outbox messages and immutable `IDENTITY_PERMISSION_BOOTSTRAP_COMMITTED` audit receipt commit in one transaction. The receipt includes client identities, credential generations and file hashes, but no credential values. This audit receipt has an explicit long retention boundary because subsequent recovery must find the original operation.

After SQL commits, the command publishes the identical receipt to the private output path without overwriting a different file. If the process fails or the commit outcome is unknown, preserve the command, pending journal and credential files and rerun the **same operation**. A matching SQL receipt verifies the same client primary keys, credential generations and file hashes and projects the original receipt without creating or rotating anything. If no SQL receipt exists, all planned native identities must still be absent under the platform realm lock before the command may remove only its matching journal-owned credential files and retry. Partial/foreign state or a changed command digest fails closed. An existing receipt file cannot initialize a different or empty database.

## Validation boundary

The offline tests exercise native-owner orchestration, one transaction, immutable receipt recovery, uncertain-commit preservation, rollback/collision handling, private file ownership, direct JDBC target checks, native ShardingSphere connection metadata and the producer-only context definition graph. No real database migration, identity provisioning, external Outbox delivery or runtime application startup was performed by this implementation task.
