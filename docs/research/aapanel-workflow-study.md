# aaPanel workflow study for AxionPanel

Research date: 2026-11-06. Language: English, following the AxionPanel documentation convention.

## 1. Scope and confidence

This is a documentation-based workflow study covering the official documentation index[1], quick-start/deployment journey, core native resources, selected plug-in workflows, catalog boundaries and selected integration/tutorial pages. It does not cover every third-party plug-in or every screen in the separate Sub aaPanel[41] or aaCloud[61] product areas. The retrieved pages and citation ledger are preserved in the local research workspace.

This is not an installation test, source-code audit, performance comparison, or security certification. The source manifest accompanies the report.

Labels used below:

- **Documented:** behavior described by the retrieved official aaPanel pages.
- **Analysis / AxionPanel proposal:** our interpretation or recommendation, not a claim about aaPanel internals and not an approved scope change.
- **Gap:** information the cited documentation does not establish; it must not be treated as a working guarantee.

No aaPanel installer was executed. No AxionPanel feature implementation, release, production deployment, firewall change, or service takeover is part of this study.

## 2. Main operational journey

The documented onboarding sequence is: prepare a Linux server → connect over SSH → install the panel as root → save the generated HTTPS address, security entrance and login details → log in → initialize LNMP or LAMP → deploy a website. Installation and workload-stack initialization are presented as separate steps.[45]

The deployment guide then connects domain resolution, the chosen environment, WordPress installation, aliases and SSL. It explicitly identifies proxy/forced-HTTPS interactions as a possible source of redirect loops.[44]

**Analysis:** aaPanel's useful reference is the connected operational journey, not just its menu inventory:

```text
Server and panel access
  ├─ Software installation and service health
  ├─ Domains / DNS / certificates
  └─ Workload creation
       ├─ Files + document root + runtime
       ├─ Database + application credentials
       ├─ Network exposure + reverse proxy + TLS
       └─ Ongoing operations
            ├─ Metrics / logs / security / alerts
            ├─ Scheduled backup / retention / restore
            └─ Change / stop / migrate / delete
```

Every arrow above should become an explicit dependency and failure boundary in AxionPanel rather than a hidden side effect.

## 3. Feature workflows

### 3.1 Home, operational status, and installation tasks

**Documented workflow:** log in → inspect CPU, memory, disk, network, workload counts and security findings → follow a resource link into its management page. Software tiles link to installed-software controls. A message box exposes installation/update tasks, execution output and historical messages; update, repair, panel restart and OS restart are distinct controls.[9]

**AxionPanel proposal:** distinguish observed host state, panel-recorded desired state, and active job state. A successful job alone is not proof that the workload remains healthy. Dangerous global actions should not share an undifferentiated confirmation with ordinary navigation.

### 3.2 App Store and native software lifecycle

**Documented workflow:** browse/search/filter the official catalog → install → inspect progress and logs → open software settings → manage status, configuration and versions → update or uninstall. The catalog also accepts third-party/imported plug-ins; categories include Deployment, Professional, Plug-ins and Tools.[4]

The deployment pages expose Nginx/Apache service and configuration controls; PHP version-specific extensions, php.ini, FPM profile, upload/timeout limits, disabled functions, session backend, logs and slow logs; MySQL/MariaDB configuration and logs; Redis persistence; and additional infrastructure services. Old PM2 Manager and Docker Manager plug-ins are marked unmaintained in favor of the native Node.js Project and Docker menus.[6]

Failure text points operators to installation logs at /tmp/panelExec.log or /tmp/panelShell.pl; the same descriptions do not establish transactional installation, durable job semantics, configuration rollback, package provenance, or safe adoption of a pre-existing service. Third-party uploads remain user-supplied plug-ins, not vetted distribution[4][21].

**AxionPanel proposal:** use detected capabilities and an explicit ownership/adoption plan before installation or configuration changes. Preserve the existing curated-template scope; studying an open plug-in store does not approve one for AxionPanel.

### 3.3 PHP and static websites

**Documented creation workflow:** Website → PHP Project → Add site → provide domain/port, description, document root, PHP version and category → optionally create FTP and a MySQL database → optionally request SSL. More PHP versions are installed separately through App Store. The form does not automatically add the www hostname.[2]

**Documented maintenance workflow:** list sites → open a site's configuration → manage domains/subdirectory bindings, site root versus running directory, authentication/access restrictions, traffic controls, rewrite rules, index files, SSL, PHP version, Composer, redirects, reverse proxy, hotlink protection, and access/error logs. Per-site and batch actions cover enable/disable, backup, expiration, PHP version and deletion. The document says deleted site directories enter the Files recycle bin; it does not say database deletion is automatic[2].

**Documented alternative creation paths:** one-click application deploy; Git creation using an SSH key, repository and branch; batch creation; and a deprecated WordPress creation path that points users to WP Toolkit.[2]

**Important distinction:** the page labels open_basedir as “Anti-XSS”; this is aaPanel's UI terminology, not a security guarantee adopted by this report. Apache rewrite uses .htaccess; Nginx requires its own rewrite configuration when switching servers.[2]

**AxionPanel proposal:** separate the site resource from its document root, runtime, database, certificate and deployment history. An optional database must remain visible as an independently owned resource. Do not infer atomic cleanup or database deletion from “Delete site.” Static sites should not require installation of PHP or a database.

### 3.4 Nginx/Apache coexistence and server switching

**Documented workflow:** enable Multi-WebServer Hosting → aaPanel automatically installs Nginx, Apache and OpenLiteSpeed and handles port conflicts → choose a server architecture per site. The page describes single-server modes and Nginx-fronted Apache/OpenLiteSpeed modes. It warns about configuration backup, generated comment markers and verifying the site after switching.[43]

**AxionPanel proposal:** borrow the explicit per-site routing model, not the automatic installation of all three servers. AxionPanel's existing plan includes Nginx and Apache, not OpenLiteSpeed. Server adoption, frontend/backend ports, public listeners, rewrite compatibility, validation and rollback should be presented before applying a switch.

### 3.5 Node.js, Python, Go, and reverse-proxy projects

The Node.js workflow separates default and PM2 projects, runtime version management, project directory, start command/script and process user. Python adds interpreter installation and virtual-environment/dependency preparation. Go project management accepts a binary/startup context and logs. Python and Go guides use a separate proxy project for access through ports 80/443.[19][40][37]

**Documented proxy workflow:** create a proxy project/domain and target → configure whole-site or directory routes, upstream host, timeouts, header/configuration changes, replacements, caching, compression, IP lists, authentication, WebSocket, logging and SSL. The page states that the proxy module currently supports Nginx; the example proxies a domain to an already-running container on 127.0.0.1[39].

**AxionPanel proposal:** model an application process separately from its public route. Process health, build success, proxy reachability and TLS readiness are different states. Use isolated application/build identities; do not translate a UI command field into unrestricted root-agent execution.

### 3.6 Git and one-click application deployment

The PHP Git creation flow shows repository-key registration, repository/branch selection and cloning into a new site. The one-click flow selects an application/version and domain. The Docker catalog supplies a separate application-template workflow.[2][7]

**Gap:** the PHP creation page does not establish isolated builds, signed webhook verification, immutable release directories, atomic switching, health-gated deployment, or migration-aware rollback.

**AxionPanel proposal:** retain the existing stronger Git-deploy contract: authenticated triggers, isolated builds, immutable releases, explicit health checks and bounded rollback. Template installation should show exactly which services, images, ports, volumes, credentials and backup resources it will create.

### 3.7 Docker and Compose

**Documented workflow:** install/select an application template or create a container/Compose deployment → choose image/version, name, host ports, storage and resource constraints → deploy → inspect status, logs, terminal and resource use → stop/restart/rebuild or remove. The module separately exposes cloud/local images, Compose, networks, volumes, registries and settings.[7]

The one-click application form distinguishes localhost-only exposure from public host binding. Its application-management view provides persistent-data backup, upload, restore, download and deletion; the document warns to back up before rebuild or uninstall. Deletion of a volume or cleanup of unused volumes is documented as unrecoverable, so backup is a precondition rather than optional[7].

Container removal, application removal, volume deletion, image cleanup and Compose deletion must be separate destructive operations; cleared unused containers, unrecoverable volume deletion, and non-restorable template/network cleanup are documented. A one-click app's backup covers persistent container data and is not a claim of application-level consistency or cross-host restore compatibility. A container being “running” does not prove application readiness, and Compose is a single-host stack unless a separate orchestration product is explicitly introduced[7].

### 3.8 Databases: MySQL/MariaDB

**Documented workflow:** install/connect a database service → create a database and user with character set, target server, source-access permission and optional forced SSL → give application credentials to the workload → manage password, permissions, backup/import and diagnostic tools. Remote DB registration, “Sync all” and “Get DB from server” are separate operations with opposite synchronization directions.[18]

The page notes that database passwords cannot be synchronized when discovering databases from the server. Backup restore/import can overwrite the existing database, and the documentation tells the operator to back up first. phpMyAdmin has separate access, port, SSL and PHP-version settings.[18]

**AxionPanel proposal:** distinguish register/discover/adopt/create. Database deletion and metadata removal must not be synonymous. Credentials should not be displayed by default, logged or copied into job output. External access should be a deliberate change with network implications, not an automatic side effect of remote registration.

### 3.9 Additional database engines

- PostgreSQL: local/remote database registration and creation, users/passwords, synchronization/discovery, backup/import/restore and deletion; restores/imports can overwrite data.[20]
- MongoDB: a similar lifecycle plus an explicit security-authentication switch.[16]
- Redis: local/remote connection, DB selection, key/value/TTL editing, backup/restore and clear-database operations.[22]
- SQL Server: the page describes remote Microsoft SQL Server management, not local engine installation, with database creation, discovery/synchronization, password change and deletion.[23]

**AxionPanel scope check:** the current native database plan remains MariaDB/MySQL-first. Studying other engines does not automatically add native managers for them. A container application using another engine is not the same feature as native engine administration.

### 3.10 Files, editor, permissions, and recycle bin

**Documented workflow:** navigate/select a directory → upload, remote-download or create files/directories/symlinks → copy/move/rename/archive/extract → edit with history → inspect/modify ownership and permissions → delete to recycle bin → recover or permanently delete. The module also documents favorites, sharing, content search and opening a terminal in the current directory.[8]

The database recycle-bin option is separate and MySQL-specific; the docs say it must be enabled manually. File protection depends on an anti-tamper plug-in rather than being identical to ordinary filesystem permissions.[8]

**AxionPanel proposal:** define managed-root/path boundaries, symlink traversal rules, archive validation, upload limits, editor concurrency and recoverability. Soft deletion requires storage/retention policy and must not be marketed as a substitute for an independent backup.

### 3.11 FTP

**Documented workflow:** install/manage PureFTPd → create a scoped FTP account with document root → configure service/network access → upload using a client → change path/password, enable/disable account and inspect logs → delete account. Path migration can copy files while leaving old data. The documented quota feature is XFS-specific.[11]

**AxionPanel scope check:** FTP remains later scope. SFTP over SSH and FTP/PureFTPd are different capabilities; this study does not silently equate or add them.

### 3.12 Cron, task scheduling, and script library

**Documented workflow:** select a task type → set schedule and relevant target/user → save → inspect enabled state, last execution and logs → execute manually/edit/disable/delete. Types include shell scripts, website/database/directory backup, log cutting, time synchronization, URL requests and a “Free RAM” task that restarts services.[5]

A second task-scheduling workflow runs a script and uses output matching to trigger another script; a script library supplies reusable commands. Its example checks Nginx status and triggers a start action when output includes a stopped indication.[5]

**AxionPanel proposal:** distinguish an OS cron resource from an asynchronous panel job and an event-triggered automation. Record timezone, overlap behavior, timeout, execution identity and last successful result. Do not adopt periodic service restarts as a general memory-management policy.

### 3.13 Backup destinations, schedules, and restore

**Documented scheduled workflow:** install/configure a destination plug-in when using remote storage → create a site/database/directory backup task in Cron → choose schedule, target, retention, exclusions, local-copy behavior and failure notification → run/test → inspect task logs. Cron's database-backup section specifically names MySQL; this is narrower than the database-manager pages' individual backup controls.[5]

The S3 tutorial connects storage credentials and a bucket to the plug-in, then selects AWS S3 in Cron; the R2 tutorial adds the compatible endpoint before creating and testing a backup task.[31][50]

**Documented restore workflow:** choose an individual workload backup or Settings → Backup Restore → inspect supported data/details → restore and monitor logs → verify the result. The broader restore page warns about space, overwriting same-named data and taking a server snapshot first.[18][25]

**Gap:** these pages do not establish encryption at rest, independent recovery-key custody, application-consistent snapshots, cross-resource consistency, corruption detection, object-lock support, or proven recovery-time objectives.

**AxionPanel proposal:** keep these guarantees explicit and tested rather than inferred from a “Backup successful” message. Use scoped least-privilege storage credentials, never an account root key as the default tutorial path. A restore needs its own preflight, ownership and overwrite plan.

### 3.14 Migration and recovery

**Documented workflow:** Settings → Migrate → back up source data → supply target access → install aaPanel/required components and restore on the target → inspect restore details and verify integrity. The guide recommends a fresh target and warns about overwriting existing installations. It notes that PHP extensions need manual reinstallation. Other Panel Migrate currently describes cPanel migration, with only WordPress sites going into WP Toolkit.[25]

**AxionPanel proposal:** distinguish workload backup/restore, metadata recovery and whole-server migration. Provider snapshots and full-OS restore are not implied by panel-level backups. Migration must disclose unsupported configuration and external dependencies.

### 3.15 Monitor, logs, and terminal

**Documented monitor workflow:** enable monitoring and retention → choose time range and metric/device → inspect load, CPU, memory, disk/network I/O and top processes → clear recorded monitoring data if desired.[17]

**Documented logs workflow:** select panel operations/runtime/cron logs, website access/error logs, OS audit, SSH login success/failure, FTP logs or MySQL error/slow logs → filter/refresh → follow the relevant diagnostic or security action.[13]

**Documented terminal workflow:** open the default local connection or register a remote SSH server using account/authentication details → execute interactive commands or saved commands. The page warns that stopping the panel from that terminal interrupts the connection.[26]

**AxionPanel proposal:** use bounded/redacted log streams and explicit retention; distinguish tamper-resistant audit records from editable operational logs. Treat terminal sessions as privileged interactive access, with fresh authorization, scoped target selection and session cleanup. A terminal is not permission to add generic exec to the typed agent API.

### 3.16 Firewall, SSH, and host hardening

**Documented firewall workflow:** add/edit/import/export port or IP rules, directions, protocols and sources; manage forwarding and region rules. SSH controls include service, password/key/root login settings, port, root credential operations and login logs. Brute-force protection separates panel-username lockout from SSH/IP-based blocking.[24]

System hardening and anti-intrusion add policy switches, protected users/paths/services/cron, process allowlists and logs. The docs explicitly warn that certain protections can prevent login, command execution, software installation, user changes or cron changes.[24]

**AxionPanel proposal:** require a lockout-safe SSH/firewall change flow with syntax validation, a timed confirm-or-revert window and an out-of-band recovery path. Do not assume local firewall success means a provider security group permits access. Broad root-password controls and kernel protections need separate threat-model decisions.

### 3.17 Panel settings, MFA, notifications, and API

**Documented access workflow:** configure panel TLS, entrance, session timeout, password policy, optional BasicAuth/TOTP, domain restriction and authorized IPs. Several restrictions have documented root/SSH recovery commands. Binding a panel domain blocks direct IP access; this is different from simply resolving a domain to the panel's IP.[25]

**Documented alert workflow:** configure and test a channel → define an alert task/condition → set interval, daily/total limits and delivery window → enable → inspect records. Channels include email, Dingding, WeCom, Feishu/Lark, Discord, webhook and Telegram; conditions include resource thresholds, login/security/service events and certificate/domain expiration.[25]

**Documented API workflow:** enable API in Settings → allow the client IP → obtain an API secret → construct signed requests. The page says the browser uses the same interface and that the published API documentation is unfinished.[42]

**AxionPanel proposal:** preserve the existing native-panel HTTPS independence. Do not copy the documented API authentication algorithm as a new AxionPanel design. Scoped tokens, expiry, revocation and audits require a separate public-API contract. Notification secrets belong in secure configuration, not Telegram chat or plaintext job logs.

### 3.18 Domains, DNS, and certificate inventory

**Documented workflow:** connect a DNS provider → list/manage domains and records → create/edit resolution entries → request/import a certificate → deploy/manage/renew it. The domain module also offers a self-hosted DNS installation path.[12]

The self-hosted tutorial requires a domain/static public IP, DNS service setup, registrar glue and nameserver changes, network access and verification queries. This is substantially different from managing a provider's DNS API.[55]

Website certificate issuance supports file validation or DNS validation; wildcard use is documented with DNS validation. The PHP page warns that manual TXT entry does not provide automatic renewal. Purchased certificates have a separate purchase, validation and deployment workflow.[2][46]

**AxionPanel scope check:** website TLS belongs to the current MVP, while DNS hosting/provider management remains later scope. DNS-01 automation should never be assumed merely because an SSL form exists. DNS credentials need provider/zone scope and explicit renewal ownership.

### 3.19 WordPress Toolkit

Documented creation paths include create, batch create, batch from backup, import, and create from backup; the restore sources named are aaPanel, Manual, Plesk and cPanel. Site management covers version/plugin/theme/admin access, cache, SSL, backup, vulnerability scanning, cloning and copying data to another site, with the target backed up first. The cache control is documented for Nginx only[34].

Remote management has its own add/connect and remote-site operations rather than being the same as local hosting. The deployment guide states that using WP Toolkit requires signing into an aaPanel account.[35][44]

**AxionPanel proposal:** treat WordPress as a workload integration built on reliable site/database/deploy/backup primitives. A one-click login, plugin update or database copy is a separate privileged application operation. Clone and restore must address credentials, URLs and application/database consistency.

### 3.20 WAF, application security, and anti-tamper

**Documented WAF workflow:** configure global/per-site protection → enable appropriate proxy/CDN handling → inspect interceptions and rule hits → add narrowly scoped allow/block rules → investigate false positives → review reports and operation logs. Controls cover IP/URL/UA lists, regions, custom request rules and CC protection. Restoring the default configuration deletes all user-added WAF configuration, and isolated Trojan files may include legitimate files that require whitelisting[33].

The Professional catalog separately describes PHP code security, Nginx/Apache WAF, anti-intrusion, system hardening, file monitoring and anti-tamper products. Enterprise anti-tamper uses protected directories, suffix rules and user/group/process/path exclusions, with global and per-directory settings; the tutorial says it cannot be combined with the other anti-tamper product and has kernel-compatibility constraints.[47][51]

**Gap:** catalog statements about attack protection or effectiveness are vendor claims, not independently verified results. In particular, this study does not establish volumetric DDoS protection or multi-tenant isolation from those descriptions.

**AxionPanel proposal:** keep host firewall, authentication throttling, WAF, malware scanning and tenant isolation separate. A security toggle must reveal its scope, compatibility and likely operational impact.

### 3.21 Nodes, file transfer, synchronization, and load balancing

**Documented Node workflow:** add a remote node using Panel API or SSH → test the connection → categorize and monitor it → enter its management context. File transfer is documented only for nodes added through the API, not for SSH-added nodes. Deletion removes the node from the management list, not the remote server, and 'restart service' is documented as restarting the remote operating system rather than one workload[38].

Files Sync is a separate send/receive-task system with filters, real-time/scheduled use, and local backup scenarios; mirror mode propagates source deletions to the receiver, and receiver content may be overwritten. Load balancing is another separate plug-in exposing website/TCP balancing, node status/logs and monitoring/alarms; the short tutorial alone does not describe a distributed scheduler.[28][29][47]

Platform Ops separately adds servers, task orchestration, triggers and a script library to run scripts according to results.[54]

**AxionPanel proposal:** keep inventory/enrollment, file transfer, replication, deployment, load balancing and automation as separate resources. Managed hosts do not imply automatic application failover, replicated databases, control-plane HA or a distributed scheduler. Retain the planned revocable mTLS enrollment rather than requiring every remote machine to expose a full panel. Where mirroring is used, deletion on the source propagates to the receiver, and receiver content may be overwritten[28].

### 3.22 Accounts, packages, tenant UI, and WHMCS

Account creation can provision a website and mail domain where the names do not already exist, while the account and package remain separate resources. The account overview exposes user-scoped workload counts, quota usage, traffic and disk; storage and package rules constrain what the sub-user can create. Deleting the account can remove the associated user data rather than only the login entry[3][41].

WHMCS integration requires aaPanel API access and a trusted client IP, a connection module/server configuration, product configuration and order provisioning; the guide includes a connection test and one-click user access.[60]

**AxionPanel scope check:** this is later commercial/multi-user scope, not merely adding a second login. Packages and quotas require enforcement, ownership isolation, lifecycle/suspension semantics and a separate billing-provisioning trust boundary. Menu visibility alone is not proof of authorization isolation.

### 3.23 Mail server and mail marketing

Mail domain setup distinguishes automatic and manual DNS-record paths, checks server-IP consistency and quota/mailbox limits. Marketing tasks and automation require subscriber groups and templates; delivery can depend on outbound mail ports or an SMTP relay when the provider restricts mail ports. Deletion of a domain can remove mail users and their data, while the documented backup cycle operates at the mail storage directory rather than a single mailbox[15][14].

**AxionPanel scope check:** mail remains later scope. Mail hosting must distinguish domain validation, delivery/authentication DNS, mailbox storage, abuse controls, queues/retries and reputation; a green service status alone cannot establish deliverability.

### 3.24 AI, ChatOps, mobile, and aaCloud

**Documented AI workflow:** choose a model and converse with the assistant; diagnostic tools cover logs, DNS, SSL, services, performance, websites, databases and firewall. Operators can manage tools, import skill packs, configure custom model endpoints, inspect quota/usage, and connect Telegram/Discord with identifier allowlists and a high-risk-actions option.[59]

**Documented mobile workflow:** enable panel API → install the panel-side mobile component → scan a QR code in the app → confirm adding the server. The Apple path additionally describes a bound domain and trusted matching panel certificate.[56]

aaCloud's retrieved overview describes multi-server management, aaPanel integration/one-click access, cloud API instance provisioning and manual SSH integration. It is a separate product overview, not evidence that Node Manager provides all those functions.[61]

**AxionPanel scope check:** no AI, mobile app, cloud provisioning or ChatOps expansion is approved by this study. If later added, tool invocation needs the same authorization, job and confirmation gates as the UI; a messaging allowlist is not sufficient authorization for arbitrary privileged execution.

## 4. Official extension catalog coverage

The following groups were reviewed through the official catalog descriptions; depth varies. A catalog entry is not a fully specified end-to-end workflow.[4][6][21]

- **Native infrastructure:** Nginx, Apache, PHP, MySQL/MariaDB, Redis, phpMyAdmin, PureFTPd, MongoDB, Memcached, Elasticsearch, OpenLiteSpeed and RabbitMQ.[6]
- **Developer/application extensions:** Node version manager, Python/Java managers, Supervisor, FFmpeg, WebHook and one-click deployment/migration.[21][27]
- **Storage/network extensions:** FTP Storage, Google Drive, AWS S3, Google Cloud Storage, DNS/DDNS/Cloud DNS, IP tools, frp and NFS shares/mounts.[21][27][47]
- **Security/operations:** Fail2ban, ClamAV, system firewall/boot items, process/service/user/session management, performance tests, Linux tools, disk analysis, log cleanup and abnormal notifications.[21][27][30]
- **Website insights:** statistics-v2, website analytics, website speed, file monitor, WAF and PHP code security. The Professional page describes the analytics product separately from server-log statistics; these should not be merged into one measurement model.[47]
- **Deprecated routes:** PM2 Manager → native Node projects; Docker Manager → native Docker menu; old WordPress deploy → WP Toolkit; old statistics → statistics-v2; Sync Tool → Files Sync.[6][2][47]

## 5. What AxionPanel should borrow, adapt, or not copy

This section is analysis, not a statement that aaPanel lacks the proposed safeguards.

### Borrow the workflow

1. Start with host capability/software readiness, not a blank create form.
2. Offer connected site/runtime/database/TLS provisioning while showing each created resource.
3. Keep a per-resource operational view: status, configuration, logs, backup and destructive actions.
4. Make asynchronous progress and error output visible.
5. Link scheduled backups to their restore entry points and expose retention.
6. Provide recovery instructions for access restrictions that can lock out the administrator.

### Adapt to AxionPanel's existing contracts

- Unprivileged control plane plus closed typed agent operations; no generic root command proxy.
- Per-site identities, explicit resource ownership, per-host policy/capability checks.
- Native panel HTTPS independent of Nginx/PHP/database services.
- Explicit Nginx/Apache coexistence, no automatic installation of out-of-scope web servers.
- Isolated builds, authenticated webhooks and immutable Git releases.
- Local/S3 encrypted backups with recovery-key custody, consistency disclosure and tested restore.
- Revocable mTLS host enrollment rather than full-panel credentials as the host-management primitive.
- Scoped destructive confirmations, lockout-safe firewall/SSH operations and audit coverage.

### Do not copy mechanically

- Installation commands that disable TLS certificate verification; the retrieved quick-start example contains such flags.[45]
- Broad credential examples: the S3 tutorial describes an account root key and the DNS tutorial includes global/all-zone options. Those are observations about the tutorials, not recommendations for AxionPanel.[31][48]
- Security advice that globally removes existing controls as an automatic fix. The commercial-certificate and self-hosted-DNS tutorials include CAA-removal and DNSSEC-disable instructions respectively; their applicability requires separate validation, not blind reuse.[46][55]
- “Free RAM” scheduled service restarts as a generic optimization policy.[5]
- Vendor effectiveness percentages, GDPR claims or DDoS claims as verified facts.[47]
- Deprecated plug-ins as the basis for new implementation.[6][47]

## 6. Dependency-first implementation recommendation

This is a proposed engineering order, not a release announcement and not a reduction of the agreed MVP.

1. **Mutation foundation:** durable jobs, host/resource locks, scoped policy, redacted progress, audit and failure/retry handling.
2. **Software/service adapters:** discover versus adopt versus install, owned configuration, validation, reload/health verification, rollback boundaries.
3. **One complete website vertical slice:** static/PHP site, Nginx or Apache profile, per-site identity/root/runtime, optional MariaDB database, TLS, logs, backup and safe deletion.
4. **Operational resources:** file manager, cron, service controls, terminal, log viewer, firewall/SSH with recovery safeguards.
5. **Docker/Compose and deployment:** resource ownership, localhost/public routing, persistent volumes, isolated builds, template plans and deployment rollback.
6. **Multi-node and gateway resources:** enrollment/revocation, host-scoped capabilities, explicit target selection and backend health/routing.
7. **Recovery completion:** scheduled encrypted backups, retention, integrity and restore drills for every managed resource type; finish these alongside each vertical slice, not only at the end.

Mail, authoritative DNS, FTP, multi-tenant hosting/billing, public plug-in marketplace, AI and mobile integrations remain separate scope discussions. Learning their aaPanel workflows does not automatically approve them for the MVP.

## 7. Acceptance checklist for each AxionPanel feature

Before calling a feature complete, specify and exercise:

- Entry point, actor, target host and required capability.
- Required inputs, secret handling and validation.
- Resource ownership and linked dependencies.
- Planned changes, public listeners and permission effects.
- Job states, progress, cancellation limits, timeout and retry/idempotency.
- Success verification against observed host/workload state.
- Failure cleanup and rollback limits, including irreversible data migrations.
- Logs, audit events, redaction and retention.
- Backup scope/consistency, restore procedure and overwrite confirmation.
- Stop, detach, uninstall and delete-data distinctions.
- Administrator lockout/recovery path where applicable.
- Tests on a disposable supported system, including reboot and partial failure when relevant.

## 8. Remaining verification boundaries

This study is sufficient to map the documented workflow surface and design questions, not to claim implementation parity. Direct testing on a disposable aaPanel installation would still be needed to verify actual installation side effects, generated configuration, authorization isolation, network exposure, backup contents/restore behavior, failure recovery, plug-in compatibility and UI behavior across versions. Some tutorials rely heavily on screenshots, and text extraction cannot establish every field or default shown only in images.

No stable price, license entitlement, compatibility matrix or security-performance claim is inferred from catalog placement. Documentation may change after the research date.

## Sources

[1] https://www.aapanel.com/docs
[2] https://www.aapanel.com/docs/Function/php.html
[3] https://www.aapanel.com/docs/Function/Account.html
[4] https://www.aapanel.com/docs/Function/AppStore.html
[5] https://www.aapanel.com/docs/Function/Cron.html
[6] https://www.aapanel.com/docs/Function/Deployment.html
[7] https://www.aapanel.com/docs/Function/Docker.html
[8] https://www.aapanel.com/docs/Function/Files.html
[9] https://www.aapanel.com/docs/Function/Home.html
[11] https://www.aapanel.com/docs/Function/Ftp.html
[12] https://www.aapanel.com/docs/Function/Domains.html
[13] https://www.aapanel.com/docs/Function/Logs.html
[14] https://www.aapanel.com/docs/Function/MailServer-basics.html
[15] https://www.aapanel.com/docs/Function/MailServer.html
[16] https://www.aapanel.com/docs/Function/MongoDB.html
[17] https://www.aapanel.com/docs/Function/Monitor.html
[18] https://aapanel.com/docs/Function/MySQL.html
[19] https://www.aapanel.com/docs/Function/Node.html
[20] https://aapanel.com/docs/Function/PgSQL.html
[21] https://www.aapanel.com/docs/Function/Plug-ins.html
[22] https://www.aapanel.com/docs/Function/Redis.html
[23] https://www.aapanel.com/docs/Function/SQLServer.html
[24] https://www.aapanel.com/docs/Function/Security.html
[25] https://www.aapanel.com/docs/Function/Settings.html
[26] https://www.aapanel.com/docs/Function/Terminal.html
[27] https://www.aapanel.com/docs/Function/Tools.html
[28] https://www.aapanel.com/docs/Function/Tutorial/files_sync.html
[29] https://www.aapanel.com/docs/Function/Tutorial/Load_balance.html
[30] https://www.aapanel.com/docs/Function/Tutorial/Task_Manager.html
[31] https://www.aapanel.com/docs/Function/Tutorial/amazon-s3-storage.html
[33] https://www.aapanel.com/docs/Function/WAF.html
[34] https://www.aapanel.com/docs/Function/WPToolkit-Local.html
[35] https://www.aapanel.com/docs/Function/WPToolkit-Remote.html
[37] https://www.aapanel.com/docs/Function/go.html
[38] https://www.aapanel.com/docs/Function/panel-node.html
[39] https://aapanel.com/docs/Function/proxy.html
[40] https://www.aapanel.com/docs/Function/python.html
[41] https://www.aapanel.com/docs/SubaaPanel/Overview.html
[42] https://www.aapanel.com/docs/api/api-list.html
[43] https://www.aapanel.com/docs/faq/multi-webserver_hosting.html
[44] https://www.aapanel.com/docs/guide/deploywebsite.html
[45] https://www.aapanel.com/docs/guide/quickstart.html
[46] https://www.aapanel.com/docs/Function/BusinessCertificate.html
[47] https://www.aapanel.com/docs/Function/Professional.html
[48] https://www.aapanel.com/docs/Function/Tutorial/DNS_API_Tutorial.html
[50] https://www.aapanel.com/docs/Function/Tutorial/How_to_Backup_Data_to_Cloudflare_R2_Object_Storage_using_Aws_S3.html
[51] https://www.aapanel.com/docs/Function/Tutorial/How_to_use_Tamper-proof_for_Enterprise.html
[54] https://www.aapanel.com/docs/Function/Tutorial/Platform_Ops.html
[55] https://www.aapanel.com/docs/Function/Tutorial/build_dns_server.html
[56] https://www.aapanel.com/docs/Function/Tutorial/how_to_use_aapanel_mobile.html
[59] https://www.aapanel.com/docs/Function/ai.html
[60] https://www.aapanel.com/docs/Function/whms/whms.html
[61] https://www.aapanel.com/docs/aacloud/en/overview.html
