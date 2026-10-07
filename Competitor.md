Below is a capability map based on PortSwigger’s current documentation as of September 2026\. It is broader than just the familiar Proxy/Repeater/Intruder trio: the current product includes automated scanning, browser-powered crawling, AI/agentic workflows, DAST, extensions, collaboration, API integrations, and extensive project/configuration tooling.  PortSwigger+1

 ## Burp Suite capability map

 ### 1\. Core interception / traffic engine

 - HTTP/HTTPS interception proxy
- Request/response interception
- Modify requests before forwarding
- Modify responses
- TLS interception
- Certificate generation/trust handling
- Proxy listeners
- Upstream proxies
- Proxy chaining
- Scope-aware interception
- HTTP history
- WebSocket traffic
- HTTP/2
- Browser traffic capture
- Raw HTTP message editor
- Message annotations/notes
- Search/filter captured traffic
- Send messages between tools
- Request/response logging
- Traffic inspection and transformation

 The Proxy is fundamentally the central traffic-processing layer, with captured traffic feeding the other tools.  PortSwigger+1

 ### 2\. Embedded browser

 - Preconfigured Chromium-based browser
- Automatically routed through proxy
- HTTPS certificate handling
- JavaScript execution
- Modern SPA support
- Dynamic request generation
- DOM interaction
- Authentication/login workflows
- Browser-powered crawling
- Browser-powered auditing
- Session-aware navigation

 Browser-powered scanning is particularly important for modern JavaScript-heavy applications.  PortSwigger+1

 ### 3\. Target / Site Map

 - Automatic application discovery
- Hierarchical site map
- URLs/endpoints
- Parameters
- HTTP methods
- Status codes
- Content types
- Request/response relationships
- Scope management
- Include/exclude scope rules
- Sitemap filtering
- Crawl paths
- API definition import
- Discovered issues
- Target-specific testing
- Context menus to send targets to other tools

 ### 4\. Repeater

 - Manually edit HTTP requests
- Resend requests repeatedly
- Multiple request tabs
- Tab groups
- Request history
- Response rendering
- Raw/pretty views
- Request/response inspection
- WebSocket message editing/replay
- Sequential request execution
- Notes
- Send to Scanner
- Send to Intruder
- Send to Comparer
- Send to other tools
- AI-assisted analysis
- Custom actions

 Current Repeater supports HTTP and WebSocket workflows and can execute sequences of requests.  PortSwigger

 ### 5\. Intruder / fuzzing engine

 - Payload insertion positions
- Multiple payload positions
- Sniper
- Battering ram
- Pitchfork
- Cluster bomb
- Simple lists
- Predefined payload lists
- Custom wordlists
- Generated payloads
- Number payloads
- Character substitution
- Dates
- Case modification
- Regex payloads
- Copy-other-payload
- Extension-generated payloads
- Collaborator payloads
- Payload encoding
- Payload processing rules
- Prefix/suffix
- URL encoding
- Base64
- Hashing
- Payload transformations
- Grep matching
- Grep extraction
- Status-code analysis
- Response-length analysis
- Response similarity
- Attack throttling/resource pools
- Concurrent requests
- Attack configuration persistence
- Results filtering
- Results sorting
- Send results to other tools
- Stop/pause attacks

 Burp currently documents four core Intruder attack types and extensive payload-generation/processing functionality.  PortSwigger+2

 ### 6\. Scanner / DAST

 This is one of the largest areas.

 #### Crawling

 - Traditional crawling
- Browser-powered crawling
- JavaScript execution
- SPA discovery
- Link discovery
- Form discovery
- Form submission
- Authentication
- State-aware crawling
- Crawl depth
- Crawl limits
- Scope controls
- Resource handling
- API discovery
- OpenAPI
- SOAP/WSDL
- Postman collections
- GraphQL
- Dynamic content discovery

 #### Auditing

 - Passive scanning
- Active scanning
- JavaScript analysis
- DOM vulnerability analysis
- Insertion-point testing
- Parameter testing
- Cookie testing
- JSON testing
- XML testing
- Multipart testing
- URL testing
- Parameter-name testing
- Out-of-band checks
- Time-based checks
- Custom scan checks
- BChecks
- Scan configuration
- Custom audit settings
- Custom crawl settings
- Scan presets
- Scan scheduling
- Scan task management
- Parallel crawl/audit
- Issue deduplication
- Evidence collection
- Reproduction evidence

 Burp Scanner explicitly uses passive checks, active checks, JavaScript analysis, insertion points, and specialized checks such as Collaborator-based detection.  PortSwigger+2

 ### 7\. Authentication / state management

 - Cookie/session tracking
- Authentication handling
- Recorded login sequences
- Automated login
- Complex authentication flows
- SSO workflows
- Session handling rules
- Macros
- Session-handling actions
- Session-handling rules
- Authentication configuration
- Per-scan login configuration
- Browser-based login
- State-aware scanning

 Recorded browser login sequences are particularly important for authenticated modern applications.  PortSwigger

 ### 8\. Collaborator / OOB interaction system

 - Generate unique OOB payloads
- DNS interactions
- HTTP interactions
- External callback detection
- Interaction polling
- Interaction correlation
- Repeater integration
- Intruder integration
- Scanner integration
- Automated OOB vulnerability checks
- Private Collaborator infrastructure

 The underlying concept is detecting vulnerabilities where successful exploitation produces an external interaction rather than an obvious HTTP response.  PortSwigger

 ### 9\. Sequencer

 - Capture security tokens
- Session-token analysis
- CSRF-token analysis
- Password-reset-token analysis
- Large token samples
- Randomness testing
- Statistical analysis
- Token quality assessment
- Entropy analysis/reporting

  PortSwigger  ### 10\. Decoder / encoding utilities

 - URL encode/decode
- Base64
- HTML encoding
- Hex
- Various text/data transformations
- Automatic decoding
- Nested encoding/decoding
- Hashing
- Transform pipelines
- Copy transformed value
- Integration with other tools

 ### 11\. Comparer

 - Compare requests
- Compare responses
- Text diff
- Word-level comparison
- Byte-level comparison
- Identify response differences
- Compare Intruder results
- Compare authentication responses
- Compare application behavior

  PortSwigger  ### 12\. Logger

 - Central HTTP traffic log
- Requests
- Responses
- Tool origin
- Filtering
- Searching
- Traffic analysis
- Logging configuration
- Project-level logging

 Current logging can include traffic from Proxy, Scanner, Repeater, Intruder, Sequencer, Extender and other components.  PortSwigger

 ### 13\. Inspector

 - HTTP headers
- Parameters
- Cookies
- Request body
- Response body
- URL components
- WebSocket messages
- Structured message analysis
- Editing
- Decoding
- Context-sensitive inspection

 ### 14\. DOM Invader

 - DOM XSS testing
- Client-side source/sink analysis
- DOM instrumentation
- Taint-style analysis
- Browser integration
- XSS detection workflows

 ### 15\. Clickbandit

 - Clickjacking testing
- Generate clickjacking demonstrations
- Test UI framing behavior
- Visual attack generation

 ### 16\. Infiltrator

 - Detect potentially unsafe API usage
- Instrumentation
- Detect whether attacker-controlled input reaches sensitive APIs
- Runtime testing

 ### 17\. Organizer

 - Save interesting requests/responses
- Investigation workspace
- Notes
- Status
- Tags/organization
- Revisit traffic later
- Cross-tool workflow

 ### 18\. Dashboard / task management

 - Scan tasks
- Live tasks
- Background tasks
- Event log
- Issue summary
- Task progress
- Task cancellation
- Task pause/resume
- Resource allocation
- Central project monitoring

 ### 19\. Issues / vulnerability management

 - Vulnerability findings
- Severity
- Confidence
- Evidence
- Request/response evidence
- Issue details
- Remediation information
- Reproduction information
- Issue filtering
- Issue sorting
- Issue status
- False-positive handling
- Issue editing
- Issue deletion
- Issue export
- Issue tracking integrations

 ### 20\. AI

 Current Burp has two distinct AI concepts:

 **Burp AI**

 - Explain selected traffic/code
- Analyze requests/responses
- Investigate issues
- Repeater assistance
- False-positive analysis
- Broken-access-control analysis
- Security-testing assistance
- AI-assisted recorded logins

 **Burp AT**

 - Agentic security testing
- Natural-language testing goals
- Planning
- Tool selection
- Autonomous/semi-autonomous execution
- Human approval gates
- Configurable tool permissions
- Scope enforcement
- Scan management
- Request/response analysis
- Issue management
- Fuzzing
- Collaborator
- Scripting
- Dataset access

  PortSwigger+2  ### 21\. Extensibility

 - Extension/plugin system
- Custom UI tabs
- Custom context-menu actions
- Request/response modification
- Additional HTTP requests
- Custom Scanner checks
- Custom Intruder payload generators
- External-tool integration
- Access to internal application data
- Custom columns
- Custom filters
- Custom actions
- Embedded scripts/Bambdas
- Custom scan checks
- Community extension marketplace
- API/SDK

 PortSwigger currently recommends its Montoya API for Java/Kotlin extensions, while also maintaining legacy mechanisms.  PortSwigger+2

 ### 22\. API/security-testing formats

 Your competitor should treat these as first-class citizens:

 - REST
- OpenAPI
- GraphQL
- SOAP/WSDL
- Postman Collections
- JSON
- XML
- Multipart
- WebSockets
- HTTP/1.1
- HTTP/2
- Browser-generated traffic
- JavaScript-generated traffic

 Burp Scanner currently explicitly supports OpenAPI, SOAP WSDL, Postman Collections and qualifying GraphQL APIs.  PortSwigger

 ### 23\. Project/configuration system

 - Projects
- Project files
- Temporary projects
- Persistent projects
- Global settings
- Project settings
- Tool-specific settings
- Named configurations
- Scan configurations
- Login configurations
- Scope configuration
- Proxy configuration
- TLS configuration
- Resource pools
- Logging configuration
- UI configuration
- Keyboard shortcuts
- Import/export configuration

 ### 24\. Search / productivity UX

 - Global search
- Command palette
- Keyboard shortcuts
- Context menus
- Filtering
- Sorting
- Column customization
- Tab management
- Tab groups
- Search across HTTP history
- Search across project data
- Quick "send to" workflows
- Custom actions

 ### 25\. Enterprise / DAST

 The cloud/enterprise side adds another product surface:

 - Centralized users
- Roles
- Permissions
- Sites
- Scan scheduling
- Recurring scans
- CI/CD integration
- API
- GraphQL API
- MCP integration
- Issue tracking
- Jira
- GitLab
- Trello
- Slack
- Splunk
- Email reporting
- Compliance reports
- Scan result exports
- Organization-level settings
- AI-enhanced scanning
- AI-generated login sequences

  PortSwigger+1
---

 # Copy/paste prompt for your development agent

 I would give your agent something like this. It deliberately frames the product as a **Burp-class authorized application-security platform**, rather than asking it to blindly clone implementation details.

 # Master Engineering Prompt: Build a Burp-Class Web Application Security Testing Platform

 You are the principal architect and engineering agent for a new professional web/API application-security testing platform.

 The goal is to build a serious, production-grade competitor in the same broad product category as Burp Suite Professional/DAST.

 Do NOT merely build an HTTP proxy. Build an integrated security-testing platform where interception, crawling, scanning, manual testing, fuzzing, browser automation, vulnerability analysis, automation, extensibility, and reporting operate as one coherent system.

 The product must be designed for authorized security testing, penetration testing, application-security engineering, QA/security validation, and development environments.

 ## 1\. Core product principles

 The platform must be:

 - Fast.
- Reliable.
- Extensible.
- Scriptable.
- API-first internally.
- Excellent for manual penetration testers.
- Excellent for automated security testing.
- Excellent for modern JavaScript applications.
- Excellent for REST, GraphQL, SOAP, WebSockets, and OpenAPI.
- Capable of authenticated/stateful testing.
- Capable of large-scale fuzzing.
- Capable of enterprise DAST.
- AI-ready but never AI-dependent.
- Safe-by-default.
- Explicitly scope-aware.
- Auditable.
- Deterministic where possible.
- Cross-platform.
- Capable of running both locally and in distributed/cloud environments.

 Do not sacrifice the manual tester experience for automation.

 ## 2\. Product architecture

 Design the system around independent but interoperable engines:

 1. Traffic engine
2. HTTP/HTTPS proxy
3. HTTP message model
4. HTTP/2 engine
5. WebSocket engine
6. Browser automation engine
7. Site-map engine
8. Crawl engine
9. Authentication/state engine
10. Passive analysis engine
11. Active scanner engine
12. Fuzzing engine
13. Payload engine
14. Out-of-band interaction engine
15. Vulnerability/issue engine
16. Project/data store
17. Search/indexing engine
18. Reporting engine
19. Extension/plugin runtime
20. Script/Bambda-like runtime
21. API server
22. CLI
23. CI/CD integration layer
24. AI assistant
25. Agentic security-testing layer
26. Enterprise/cloud orchestration layer

 Every engine should expose clean internal APIs.

 ## 3\. Traffic interception

 Implement a professional interception proxy supporting:

 - HTTP
- HTTPS
- HTTP/1.1
- HTTP/2
- WebSockets
- Request interception
- Response interception
- Request editing
- Response editing
- TLS interception
- Proxy listeners
- Upstream proxy support
- Proxy chaining
- Scope-aware interception
- HTTP history
- Search/filtering
- Traffic logging
- Request/response annotations
- Send-to-tool workflows

 The traffic engine must be reusable by every other subsystem.

 A request captured by Proxy should be transferable to Repeater, Intruder/Fuzzer, Scanner, Comparer, Decoder, Organizer, scripting, extensions, and issue workflows without unnecessary serialization or data loss.

 ## 4\. HTTP message model

 Create a canonical structured HTTP message representation.

 It must understand:

 - Method
- URL
- Scheme
- Host
- Port
- Path
- Query parameters
- Headers
- Cookies
- Body
- JSON
- XML
- Multipart
- Form parameters
- Binary bodies
- WebSocket messages
- HTTP/2 metadata

 Support both:

 - Raw representation
- Structured representation

 Never force users to choose between raw HTTP power and structured editing.

 ## 5\. Embedded browser

 Provide an integrated Chromium-class browser.

 It must:

 - Automatically proxy traffic.
- Support modern JavaScript.
- Support SPAs.
- Execute client-side code.
- Capture dynamically generated requests.
- Support login workflows.
- Support browser automation.
- Feed discovered traffic into the site map.
- Support browser-powered crawling.
- Support browser-powered auditing.
- Support screenshots where appropriate.
- Expose browser events to the scanner.

 The browser must be treated as a first-class security-testing component, not merely a convenience browser.

 ## 6\. Target and site map

 Build a dynamic application graph/site map.

 Represent:

 - Hosts
- Origins
- URLs
- Endpoints
- Parameters
- Forms
- API endpoints
- WebSockets
- Technologies
- Authentication boundaries
- Crawl relationships
- Issues
- Requests
- Responses

 Provide:

 - Scope inclusion/exclusion
- Filters
- Search
- Tags
- Notes
- Endpoint metadata
- Crawl paths
- Manual additions
- API-definition imports

 The site map should become the shared knowledge base for scanning and manual testing.

 ## 7\. Repeater

 Implement a high-performance manual request laboratory.

 Required:

 - Multiple tabs
- Tab groups
- Request history
- Response history
- Raw editing
- Structured editing
- Syntax highlighting
- Pretty/raw views
- Request comparison
- Response comparison
- WebSocket support
- Request sequences
- Notes
- Send-to-other-tool actions
- Scanner integration
- Fuzzer integration
- AI assistance
- Custom actions

 Every modification should be undoable/history-aware where practical.

 ## 8\. Fuzzing / Intruder

 Implement a generalized fuzzing engine.

 Support:

 - Payload positions
- Multiple payload positions
- Single-position iteration
- Same payload in multiple positions
- Parallel payload streams
- Cartesian-product payload combinations
- Wordlists
- Generated payloads
- Custom generators
- Payload transformations
- Encoding
- Decoding
- Prefix/suffix
- Regex transformations
- Hashing
- Base64
- URL encoding
- Custom scripting
- OOB payloads
- Response matching
- Response-length analysis
- Status-code analysis
- Similarity analysis
- Grep extraction
- Grep matching
- Concurrency control
- Rate limiting
- Pause/resume
- Cancellation
- Results streaming
- Result filtering
- Result sorting
- Export
- Send-to-tool workflows

 Design the engine so additional payload generators and result analyzers can be installed as plugins.

 ## 9\. Scanner

 Build a professional DAST engine with two major phases:

 ### Crawl

 Support:

 - Traditional crawling
- Browser-powered crawling
- JavaScript applications
- Dynamic navigation
- Forms
- Links
- API discovery
- Authentication
- State management
- Session handling
- Crawl depth
- Crawl limits
- Scope controls
- OpenAPI
- GraphQL
- SOAP/WSDL
- Postman Collections
- Dynamically discovered APIs

 ### Audit

 Support:

 - Passive checks
- Active checks
- Insertion-point testing
- Parameter testing
- Cookie testing
- JSON testing
- XML testing
- Multipart testing
- URL testing
- Parameter-name testing
- JavaScript/DOM analysis
- OOB checks
- Time-based checks
- Stateful checks

 The scanner must support custom scan checks.

 Every finding should contain:

 - Title
- Severity
- Confidence
- Description
- Affected endpoint
- Evidence
- Request
- Response
- Insertion point
- Reproduction information
- Remediation guidance
- References
- Scan metadata
- Timestamp
- Fingerprint/deduplication identity

 ## 10\. Scanner architecture

 Do NOT hard-code the scanner into one monolithic engine.

 Create:

 - Crawl scheduler
- Audit scheduler
- Check registry
- Insertion-point engine
- Payload engine
- Evidence engine
- Confidence engine
- Issue correlation engine
- Deduplication engine
- Browser integration
- OOB integration
- Authentication integration
- Scan configuration engine

 Each vulnerability check should be independently testable.

 Support custom checks through a stable SDK.

 ## 11\. Authentication and state

 Authentication is a first-class requirement.

 Support:

 - Cookies
- Tokens
- Headers
- Sessions
- CSRF tokens
- Dynamic values
- Login sequences
- Recorded browser login flows
- SSO
- Multi-step authentication
- Session refresh
- Session invalidation
- Macros
- State-dependent scanning

 The system must understand that modern applications are state machines rather than collections of independent URLs.

 ## 12\. API security

 Provide first-class API testing.

 Support:

 - OpenAPI
- Swagger
- REST
- GraphQL
- SOAP
- WSDL
- Postman Collections
- JSON APIs
- WebSockets

 Allow users to:

 - Import API definitions
- Discover APIs from traffic
- Map endpoints
- Generate test cases
- Scan parameters
- Test authentication
- Test authorization boundaries
- Compare responses
- Fuzz API parameters
- Export findings

 ## 13\. Out-of-band engine

 Create a generic OOB interaction platform.

 Architecture:

 CLIENT → UNIQUE PAYLOAD → TARGET → EXTERNAL INTERACTION → CALLBACK SERVICE → CORRELATION ENGINE → FINDING

 Support:

 - Unique interaction identifiers
- DNS interactions
- HTTP callbacks
- Interaction polling
- Correlation
- Expiration
- Project isolation
- Scanner integration
- Fuzzer integration
- Manual testing integration

 Design it so additional protocols can be added later.

 ## 14\. Token/randomness analyzer

 Create a dedicated token-analysis module.

 Support:

 - Session tokens
- CSRF tokens
- Password-reset tokens
- Custom token extraction
- Large sample analysis
- Statistical analysis
- Entropy analysis
- Randomness tests
- Visualization
- Exportable results

 ## 15\. Diff/comparison engine

 Build a reusable comparison engine for:

 - Requests
- Responses
- Headers
- Bodies
- JSON
- XML
- Text
- Binary data

 Support multiple comparison modes:

 - Byte
- Character
- Word
- Line
- Structural JSON/XML
- Semantic similarity

 Expose the engine to Repeater, Fuzzer, Scanner and reporting.

 ## 16\. Decoder/transform engine

 Build a reusable transformation pipeline supporting:

 - URL encoding
- URL decoding
- Base64
- Hex
- HTML encoding
- HTML decoding
- Unicode transformations
- Hashing
- Compression where appropriate
- Custom transformations

 Allow chains such as:

 INPUT → URL decode → Base64 decode → transform → encode

 Expose this engine to manual testing, fuzzing and extensions.

 ## 17\. DOM/client-side security

 Provide client-side analysis capabilities.

 Support:

 - DOM XSS analysis
- Source/sink tracking
- JavaScript analysis
- Runtime instrumentation
- Browser-based testing
- Client-side request discovery
- Dynamic sink detection

 Keep this subsystem independent so it can evolve into a broader client-side security analyzer.

 ## 18\. Issue management

 Create a central vulnerability database.

 Issues must support:

 - Severity
- Confidence
- Status
- Tags
- Assignee
- Comments
- Evidence
- Screenshots
- Request/response
- Reproduction
- Remediation
- References
- Duplicate relationships
- False-positive state
- Verification state
- History/audit trail

 Allow issues to originate from:

 - Scanner
- Manual testing
- Extensions
- Scripts
- AI
- External integrations

 ## 19\. Project system

 Projects should contain:

 - Target scope
- Site map
- HTTP history
- Scanner tasks
- Scan configurations
- Authentication configurations
- Issues
- Repeater sessions
- Fuzzer sessions
- Organizer entries
- Notes
- Logs
- Extensions
- Scripts
- Credentials/configuration references

 Support:

 - Temporary projects
- Persistent projects
- Import/export
- Project backups
- Versioned configuration
- Encryption for sensitive project data

 ## 20\. Search

 Build global search across:

 - URLs
- Requests
- Responses
- Headers
- Bodies
- Issues
- Site map
- Notes
- Project metadata

 Support:

 - Regex
- Case sensitivity
- Scope filtering
- Tool filtering
- Time filtering
- Status-code filtering
- Content-type filtering

 Search must remain fast on millions of HTTP messages.

 ## 21\. Logging/event system

 Create an internal event bus.

 Events should cover:

 - Request sent
- Response received
- Scan started
- Scan progress
- Scan completed
- Issue discovered
- Issue updated
- Fuzzer started
- Fuzzer result
- Browser event
- Extension event
- OOB interaction
- Authentication change
- Configuration change

 The event system should power:

 - UI
- Logging
- Audit trail
- Automation
- Plugins
- Agentic workflows

 ## 22\. Extension platform

 Extensibility is a strategic requirement.

 Provide an SDK capable of:

 - HTTP interception
- Request modification
- Response modification
- Custom tabs
- Custom panels
- Custom context-menu actions
- Custom scanner checks
- Custom fuzzing payload generators
- Custom analyzers
- Custom exporters
- Custom integrations
- Access to project data
- Access to site-map data
- Access to issue data
- External tool invocation

 Provide SDKs with stable versioning and compatibility guarantees.

 Create an extension marketplace architecture.

 ## 23\. Embedded scripting

 Provide lightweight scripting for quick customization.

 Use cases:

 - Match/replace logic
- Custom columns
- Filters
- HTTP transformations
- Extraction
- Data analysis
- Custom actions
- Scanner helpers
- Fuzzing helpers

 Scripts should have explicit permissions and resource limits.

 ## 24\. AI assistant

 AI should augment, not replace, deterministic security tooling.

 Provide AI features such as:

 - Explain HTTP traffic
- Explain vulnerability findings
- Analyze unusual responses
- Suggest investigation steps
- Summarize endpoints
- Analyze JavaScript
- Explain scanner evidence
- Help configure scans
- Generate test ideas
- Analyze false positives
- Assist with authorization testing
- Help construct request transformations
- Summarize scan results

 AI must always show:

 - What data it received
- What action it proposes
- What tools it will use
- What requests it intends to send
- Whether approval is required

 Sensitive data handling must be explicit and configurable.

 ## 25\. Agentic security tester

 Build an optional autonomous security-testing agent.

 The agent should have tools such as:

 - Inspect scope
- Inspect site map
- Search HTTP history
- Inspect requests
- Inspect responses
- Send/replay requests
- Run fuzzing
- Run scans
- Inspect issues
- Compare messages
- Decode data
- Run scripts
- Generate OOB payloads
- Poll OOB interactions
- Manage scan configuration
- Create investigation notes

 Implement autonomy levels:

 1. Read-only
2. Suggest
3. Ask-before-action
4. Approved automation
5. Fully autonomous within explicit scope

 The agent MUST enforce scope.

 It must never silently expand the authorized target.

 Every external request should be attributable to an agent action.

 Provide a complete action history.

 ## 26\. Safety architecture

 Build authorization boundaries into the product.

 Required:

 - Explicit target scope
- Include/exclude rules
- Scope validation before requests
- Destructive-action warnings
- Rate limiting
- Request budgets
- Scan budgets
- Authentication-secret protection
- Credential redaction
- Audit logs
- Kill switch
- Pause/resume
- Approval gates
- Safe defaults

 Never assume that because a URL is technically reachable it is authorized for testing.

 ## 27\. Enterprise DAST

 Build a server-side/cloud architecture supporting:

 - Organizations
- Users
- Teams
- Roles
- Permissions
- Sites
- Scan configurations
- Scheduled scans
- Recurring scans
- Scan history
- Findings
- Issue lifecycle
- API
- CLI
- CI/CD
- Webhooks
- Notifications
- Ticketing integrations
- Reporting
- Compliance reports
- Distributed scanning
- Worker pools

 Design the system to support horizontal scaling.

 ## 28\. CI/CD

 Provide:

 - CLI
- REST API
- Webhooks
- Pipeline integration
- Scan policies
- Thresholds
- Build gates
- SARIF export
- JSON export
- XML export
- HTML reports
- Machine-readable findings
- Baseline comparison
- New-vulnerability detection

 Integrate cleanly with common CI/CD systems without requiring the GUI.

 ## 29\. Reporting

 Provide:

 - Executive reports
- Technical reports
- Vulnerability reports
- Endpoint reports
- Scan reports
- Compliance-oriented reports
- Evidence attachments
- Reproduction steps
- Remediation recommendations
- Historical comparisons

 Allow custom report templates.

 ## 30\. Performance requirements

 The architecture must support:

 - Millions of HTTP messages
- Large site maps
- Large wordlists
- High-concurrency fuzzing
- Parallel scanning
- Multiple browser sessions
- Long-running scans
- Large response bodies
- Large projects

 Use streaming wherever possible.

 Do not load entire datasets into memory unnecessarily.

 Build indexing and pagination into the architecture from day one.

 ## 31\. UX requirements

 The UI should feel like a professional security workstation.

 Prioritize:

 - Keyboard-first workflows
- Fast navigation
- Context menus
- Send-to-tool actions
- Search everywhere
- Filtering everywhere
- Resizable panes
- Multiple tabs
- Tab groups
- Persistent workspaces
- Dark/light themes
- Clear severity visualization
- Minimal modal dialogs
- Non-blocking background tasks
- Progress indicators
- Command palette

 A tester should be able to move:

 Proxy → Repeater → Fuzzer → Scanner → Issue → Repeater

 with almost no friction.

 ## 32\. Internal data model

 Define reusable objects for:

 - HttpRequest
- HttpResponse
- HttpExchange
- Endpoint
- Parameter
- Cookie
- WebSocketMessage
- SiteNode
- CrawlAction
- ScanTask
- ScanConfiguration
- ScanCheck
- Payload
- PayloadGenerator
- FuzzJob
- FuzzResult
- Finding
- Issue
- Evidence
- AuthenticationSession
- LoginSequence
- OobInteraction
- Project
- Extension
- Script
- AgentTask
- AgentAction

 Avoid duplicated representations of HTTP messages across subsystems.

 ## 33\. Testing strategy

 Every subsystem requires:

 - Unit tests
- Integration tests
- Regression tests
- Performance tests
- Fuzz tests
- Failure/recovery tests

 Build a dedicated intentionally vulnerable test environment.

 Test against:

 - Traditional web apps
- SPAs
- REST APIs
- GraphQL
- WebSockets
- OAuth/OIDC flows
- SSO
- Multi-step workflows
- CSRF-protected applications
- Dynamic tokens
- Large responses
- Slow applications
- Unstable applications

 Do not use real third-party systems as test targets.

 ## 34\. Compatibility strategy

 Do not copy proprietary source code, implementation details, trademarks, UI assets, or protected content.

 Instead, compete at the capability/category level.

 Use independent architecture and implementation.

 Where interoperability is useful, create documented APIs and import/export formats.

 ## 35\. Development methodology

 Work in vertical slices.

 Do not build disconnected mock screens.

 Each milestone must produce a working end-to-end workflow.

 Recommended sequence:

 ### Phase 1

 - HTTP message model
- Proxy
- HTTP history
- Scope
- Repeater

 ### Phase 2

 - Site map
- Search
- Comparer
- Decoder
- Organizer

 ### Phase 3

 - Fuzzing engine
- Payload engine
- Result analysis

 ### Phase 4

 - Browser
- Browser traffic integration
- Crawl engine
- Authentication/state

 ### Phase 5

 - Scanner framework
- Passive checks
- Active checks
- Issue engine

 ### Phase 6

 - API scanning
- GraphQL
- OpenAPI
- WebSockets
- JavaScript/DOM analysis

 ### Phase 7

 - OOB infrastructure
- Advanced scanner checks
- Custom scan-check SDK

 ### Phase 8

 - Extension SDK
- Scripting
- Marketplace architecture

 ### Phase 9

 - AI assistant
- Agentic tester
- Approval/autonomy framework

 ### Phase 10

 - Cloud/DAST
- CI/CD
- Enterprise RBAC
- Reporting
- Integrations

 ## 36\. Definition of done

 A feature is NOT complete merely because its UI exists.

 For every feature require:

 - Working backend
- Working UI
- Persistent state where appropriate
- Keyboard support
- Search/filter support where appropriate
- Error handling
- Cancellation
- Progress reporting
- Logging
- Tests
- Documentation
- API exposure where appropriate
- Extension hooks where appropriate
- Security review

 Never create placeholder buttons that imply functionality that does not exist.

 ## 37\. Agent behavior

 As the engineering agent:

 - Inspect the existing codebase before modifying it.
- Preserve working functionality.
- Identify architectural weaknesses before adding large features.
- Prefer reusable engines over duplicated implementations.
- Keep APIs stable.
- Write tests alongside implementation.
- Benchmark performance-sensitive code.
- Maintain migration paths for schema changes.
- Document architectural decisions.
- Surface blockers immediately.
- Never silently remove existing functionality.
- Never claim a feature is implemented without a working test.
- Track incomplete functionality explicitly.
- Build production-quality foundations rather than demo-only features.

 For every major feature, produce:

 1. Architecture
2. Data model
3. API design
4. UI design
5. Implementation
6. Tests
7. Performance considerations
8. Security considerations
9. Documentation
10. Acceptance criteria

 The ultimate goal is a unified security-testing platform where a professional tester can discover an application, intercept traffic, understand its attack surface, manipulate requests, fuzz inputs, crawl authenticated applications, run automated security checks, investigate findings, validate vulnerabilities, automate workflows, extend the platform, and manage results — all without leaving the product.

 ### Recommended strategic priorities

 If you're actually building this, I would **not** start by implementing every Burp feature simultaneously. The architectural core that determines whether the competitor can eventually reach feature parity is:

 **HTTP message model → proxy/traffic engine → site map → Repeater → fuzzing engine → browser/state engine → scanner framework → issue engine → extension SDK.**

 Everything else can build on those primitives. In particular, don't make the scanner a separate product bolted onto a proxy—the current Burp architecture demonstrates how tightly crawling, browser automation, auditing, insertion points, authentication, and the site map need to work together.  PortSwigger+1

 Also treat **extensibility as a first-class product feature**, rather than something added at the end. PortSwigger's current extension model exposes traffic manipulation, custom UI, scanner checks, external integrations, and internal-tool access, which is a major part of the ecosystem effect around a platform like this.  PortSwigger+1

 And for a 2026-era competitor, I'd make **AI/agentic testing an architectural layer rather than a chatbot tab**: the agent needs structured access to scope, traffic, site map, scanner, fuzzing, issues, OOB interactions and configuration, with explicit per-tool autonomy/approval controls. That's broadly how Burp AT is now structured.  PortSwigger+1

 ### Official references

 - PortSwigger — Burp Suite tools
- PortSwigger — Burp Scanner documentation
- PortSwigger — Full documentation contents
- PortSwigger — Extending Burp
- PortSwigger — Burp AI / agentic testing
- PortSwigger — Burp Suite DAST

  - Inspect the existing codebase before modifying it.
- Preserve working functionality.
- Identify architectural weaknesses before adding large features.
- Prefer reusable engines over duplicated implementations.
- Keep APIs stable.
- Write tests alongside implementation.
- Benchmark performance-sensitive code.
- Maintain migration paths for schema changes.
- Document architectural decisions.
- Surface blockers immediately.
- Never silently remove existing functionality.
- Never claim a feature is implemented without a working test.
- Track incomplete functionality explicitly.
- Build production-quality foundations rather than demo-only features.