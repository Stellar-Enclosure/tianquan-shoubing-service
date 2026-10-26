# Permission build and controlled delivery

`permission-producers.json` is the finite inventory of independent executable producers in this repository. A FULL manifest and a final artifact digest belong to one executable. The five Yuheng executables are never merged into one deployment artifact.

The `permission-producer` Maven profile compiles declarations, runs the producer coverage tests, aggregates successful modules at `prepare-package`, embeds the FULL manifest, and verifies the final executable at `verify`. The build-only processor and manifest CLI are not application runtime dependencies.

```bash
./mvnw -B -ntp -Ppermission-producer \
  -Dpermission.commit="$(git rev-parse HEAD)" \
  -Dpermission.buildId="<unique build identity>" \
  -DskipITs clean verify
```

For each executable, `target/permissions/manifest-v1.json` is read back from the final JAR. `target/permissions/artifact-evidence.json` records its producer, final JAR SHA-256, manifest/policy/metadata digests, original module inputs and build identity. This proves packaged bytes and completeness; it does not prove deployment or readiness. Local dirty builds remain local evidence.

## Tool and target provisioning

The checked-in toolchain lock currently has `mode: LOCAL_UNCOMMITTED`. This accurately describes the implementation checkout and allows local verification against the same tool source and RC artifact. CI deliberately refuses to turn that into a fictitious fixed commit. Before enabling remote validation/delivery:

1. Commit the reviewed SDK tool implementation, then use a separate clean checkout at that exact full commit. Run `npm ci` there.
2. Retain a successfully built RC contract JAR as an immutable CI artifact or local build artifact. Record its actual SHA-256; do not assume a new Maven Central version exists.
3. Use that pinned tool's `lock --mode PINNED_COMMIT --sdk-commit <actual full commit> --artifact <RC jar> --artifact-sha256 <verified SHA> --output <new lock path>` command, inspect the generated contract resource and dependency-lock digests, then replace and commit this repository's `permission-toolchain.lock.json`.
4. Configure `PERMISSION_CONTRACT_ARTIFACT_URL` as a non-secret HTTPS URL for the exact retained RC JAR. Its downloaded digest must match the committed lock. Do not put credentials or signed query tokens in that URL. A private artifact store may supply the same file through its authenticated runner integration instead of the download step; keep the digest validation.
5. Populate the reviewed `permission-targets.json` with actual provisioned targets. Its initial empty `targets` map authorizes no environment. The S30 format is `schemaVersion: 1`, `targets[name] = {baseUrl, target: {catalogScopeId, tenantId, businessCode, applicationCode, namespaceCode, environment}, producerId, authentication: {issuer, clientId, resource, scopes, clientSecretFileEnv}}`. Use `clientSecretFileEnv: "PERMISSION_CLIENT_SECRET_FILE"`; the secret itself is never stored in this JSON.

The SDK checkout and contract preparation are independent of `STELLAR_USE_SOURCE_BOOTSTRAP`. Disabling Maven source bootstrap does not disable the pinned tool gate. A failed pin/scan/build cannot produce a successful offline-validation job or proceed to delivery.

## GitHub Actions

The ordinary `ci.yml` builds with Java 25, archives each final executable and evidence, and runs an independent Node 24 job through the fixed SDK tool. Pull requests and ordinary pushes only validate offline and receive no candidate-registration credentials.

`permission-delivery.yml` is a separate manual workflow. It requires the current protected branch, `PERMISSION_DELIVERY_ENABLED=true`, and the protected environment `permission-register` or `permission-activate`. Configure these environments with required reviewers. The workflow checks the selected build run's repository, workflow path, success, current branch commit and age (at most 24 hours); it downloads the original artifacts instead of rebuilding. Cancelled, failed, foreign, superseded or expired builds are rejected.

For registration, provide the exact producer and target, reviewed expected producer/active revisions, and a stable operation UUID. The tool performs diff → sync → status. Exit 6 means pending or timeout, not completion. Retain the operation UUID and query its status; do not create a new operation to override an unknown outcome. CAS/ownership failures require a new reviewed plan.

Activation additionally requires `PERMISSION_DEPLOYMENT_WORKFLOW_PATH` to name a separate trusted deployment workflow and a successful run of that workflow at the same commit. That workflow must deploy the exact artifact, verify readiness and obtain the server-issued deployment qualification through the existing controlled API. It then uploads artifact `permission-deployment-evidence` containing `permission-deployment.json` with this structure:

```json
{
  "schemaVersion": 1,
  "status": "READY",
  "producerId": "<exact producer>",
  "artifactDigest": "<SHA-256 of the deployed executable>",
  "commit": "<exact build commit>",
  "buildId": "<exact embedded build identity>",
  "verifiedAt": "<UTC readiness verification time>",
  "expiresAt": "<UTC expiry no more than ten minutes after verification>",
  "selection": {
    "target": {"catalogScopeId":"...","tenantId":"...","businessCode":"...","applicationCode":"...","namespaceCode":"...","environment":"..."},
    "operationId": "<stable UUID>",
    "expectedActiveRevision": "<decimal revision>",
    "producers": [{"producerId":"...","producerVersion":"...","qualificationId":"<existing server-issued ID>"}]
  }
}
```

`selection.producers` must be the complete explicit active set for the target, including the required existing qualifications for other producers. The example is a shape, not executable configuration. The adapter verifies build/producer/digest/readiness freshness, then passes the exact selection to the shared CLI. The server independently enforces qualification ownership, expiration, exact versions, completeness and CAS. This workflow does not create deployment proofs, grant roles, deploy services, or activate after a normal build.

Use a scoped client secret in the protected environment secret `PERMISSION_CLIENT_SECRET`; the workflow writes it to a mode-0600 temporary file for the client and removes it afterwards. Only non-secret status/receipt outputs are archived.

## GitLab CI

The default build also archives final artifacts and runs the independent `permission-offline-validation` job. The exact SDK commit is fetched from `web-sdk` using the configured CI job-token read permission; `PERMISSION_SDK_REPOSITORY_URL` may select a reviewed source mirror. There is no floating-branch fallback.

`permission-register` and `permission-activate` are manual protected-environment jobs, enabled only by `PERMISSION_DELIVERY_ENABLED=true`. Protect those environments and use protected file-type variables for `PERMISSION_CLIENT_SECRET_FILE` and, for activation, `PERMISSION_DEPLOYMENT_EVIDENCE_FILE`. Only the trusted deployment integration/operator may supply the latter from a separate successfully completed deployment pipeline after actual deployment, readiness and qualification; never accept it from an application/browser or ordinary build artifact. It uses the same JSON contract above. The proof must additionally contain `gitlab: {projectId, pipelineId, jobId}` with positive decimal-string IDs. Configure the protected `PERMISSION_DEPLOYMENT_JOB_NAME` to the exact separate trusted deployment job name and `PERMISSION_GITLAB_READ_TOKEN_FILE` to an owner-only file containing a read-only `read_api` project token. Activation reads only the current project through the runner's HTTPS `CI_API_V4_URL`: it verifies the job and its separate completed pipeline are successful at the current protected branch commit, checks the exact job name and completion time, and downloads that job's actual `permission-deployment.json` artifact. The archived proof must equal the supplied proof. Local JSON assertions alone cannot establish deployment provenance. Credentials stay in an HTTP header on the GitLab API origin; artifact CDN redirects never receive that header. Missing provenance or read credentials fails closed. The adapter also rejects a superseded branch SHA or a pipeline older than 24 hours. Configure `PERMISSION_PRODUCER_ID`, `PERMISSION_TARGET`, the expected revision variables and `PERMISSION_OPERATION_ID` for the intended operation. The complete target and finite service grant are provisioned by B0; ordinary CI cannot create them or grant administrator roles.

The scripts and workflow structure are validated locally. Remote runner permissions, branch/environment protection, hosted RC artifacts, real service credentials, PostgreSQL, deployment readiness, registration and activation require the separately authorized environment acceptance run. They are not established by a source change.

Workflow syntax follows the upstream [artifact download action](https://github.com/actions/download-artifact), [GitHub script action](https://github.com/actions/github-script), and [GitLab CI reference](https://docs.gitlab.com/ci/yaml/), [Jobs API](https://docs.gitlab.com/api/jobs/), [Pipelines API](https://docs.gitlab.com/api/pipelines/), and [Job Artifacts API](https://docs.gitlab.com/api/job_artifacts/).
