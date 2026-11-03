package protocol

// The wire contract of /agent/v1, field for field: the JSON names and their order are the server's. Keys,
// signatures, nonces and sealed parts are base64url without padding; SHA-256 values are lowercase hex; bodies are
// UTF-8 JSON. A nullable field is a pointer (nil = null); a list is never sent as null (MarshalJSON below).

// APIBase is the path every route sits under.
const APIBase = "/agent/v1"

// Request and answer headers.
const (
	// HeaderJoinProof carries the join request's proof (JoinProof).
	HeaderJoinProof = "x-nsa-join-proof"
	// HeaderJoinMAC carries the join answer's MAC (JoinMAC).
	HeaderJoinMAC = "x-nsa-join-mac"
	// HeaderAgent carries the agent id.
	HeaderAgent = "x-nsa-agent"
	// HeaderTimestamp carries the request time in unix seconds.
	HeaderTimestamp = "x-nsa-timestamp"
	// HeaderNonce carries 16 random bytes, used once.
	HeaderNonce = "x-nsa-nonce"
	// HeaderSignature carries the agent's signature of the request (SignRequest).
	HeaderSignature = "x-nsa-signature"
	// HeaderServerSignature carries the server's signature of a 2xx answer (VerifyAnswer).
	HeaderServerSignature = "x-nsa-server-signature"
)

// AgentKind is how the agent runs.
type AgentKind string

const (
	KindHost       AgentKind = "host"
	KindDocker     AgentKind = "docker"
	KindKubernetes AgentKind = "kubernetes"
)

// WebServerKind is a web server the agent reads the configuration of.
type WebServerKind string

const (
	WebServerNginx   WebServerKind = "nginx"
	WebServerApache  WebServerKind = "apache"
	WebServerHAProxy WebServerKind = "haproxy"
)

// SiteKind is where a site's certificate lives.
type SiteKind string

const (
	SiteNginx      SiteKind = "nginx"
	SiteApache     SiteKind = "apache"
	SiteHAProxy    SiteKind = "haproxy"
	SiteK8sIngress SiteKind = "k8s_ingress"
	SiteFolder     SiteKind = "folder"
)

// SiteOwner is the tool that manages a site's certificate today.
type SiteOwner string

const (
	OwnerCertbot     SiteOwner = "certbot"
	OwnerCertManager SiteOwner = "cert-manager"
	OwnerOther       SiteOwner = "other"
)

// SiteBlocked is why the agent cannot install on a site.
type SiteBlocked string

const (
	BlockedPathVariable    SiteBlocked = "path_variable"
	BlockedNoHTTPS         SiteBlocked = "no_https"
	BlockedUnreadable      SiteBlocked = "unreadable"
	BlockedOwnedByOther    SiteBlocked = "owned_by_other"
	BlockedSecretNotTLS    SiteBlocked = "secret_not_tls"
	BlockedSecretImmutable SiteBlocked = "secret_immutable"
)

// WorkAction is what a work item asks for.
type WorkAction string

const (
	ActionInstall WorkAction = "install"
	ActionRelease WorkAction = "release"
)

// CertbotAction is what a work item asks of certbot.
type CertbotAction string

const (
	CertbotTakeOver CertbotAction = "take_over"
	CertbotGiveBack CertbotAction = "give_back"
)

// StepName names one step of an install.
type StepName string

const (
	StepChecked         StepName = "checked"
	StepWritten         StepName = "written"
	StepTested          StepName = "tested"
	StepReloaded        StepName = "reloaded"
	StepRestored        StepName = "restored"
	StepCheckedLocally  StepName = "checked_locally"
	StepCertbotDisabled StepName = "certbot_disabled"
	StepCertbotRestored StepName = "certbot_restored"
	StepSecretWritten   StepName = "secret_written"
	StepHookRan         StepName = "hook_ran"
)

// AgentFacts is what the agent says about its machine, at join and in every heartbeat.
type AgentFacts struct {
	OS           string           `json:"os"`
	OSVersion    string           `json:"osVersion"`
	Arch         string           `json:"arch"`
	Hostname     string           `json:"hostname"`
	WebServers   []WebServer      `json:"webServers"`
	Kubernetes   *KubernetesFacts `json:"kubernetes"`
	AgentVersion string           `json:"agentVersion"`
}

// WebServer is one web server found on the machine.
type WebServer struct {
	Kind    WebServerKind `json:"kind"`
	Version string        `json:"version"`
}

// KubernetesFacts describes the cluster of an agent running in Kubernetes.
type KubernetesFacts struct {
	Version           string  `json:"version"`
	IngressController *string `json:"ingressController"`
	// Annotations: the agent reports each Ingress's Autopilot annotations (the Helm value annotations.enabled).
	Annotations bool `json:"annotations"`
}

// CertFacts describes a served certificate (the leaf only).
type CertFacts struct {
	SHA256   string   `json:"sha256"`
	Issuer   string   `json:"issuer"`
	Names    []string `json:"names"`
	Serial   string   `json:"serial"`
	NotAfter string   `json:"notAfter"`
}

// Site is one certificate file (or Kubernetes TLS secret) and the names it serves: sites sharing one file are one
// site with the union of their names. SiteKey = the first 32 hex characters of the SHA-256 of
// "<kind>|<configPath or namespace/ingress>|<certPath or secret name>", so a changed path is a new site.
type Site struct {
	SiteKey     string       `json:"siteKey"`
	Kind        SiteKind     `json:"kind"`
	Names       []string     `json:"names"`
	ConfigPath  *string      `json:"configPath"`
	CertPath    *string      `json:"certPath"`
	KeyPath     *string      `json:"keyPath"`
	ChainPath   *string      `json:"chainPath"`
	Secret      *SecretRef   `json:"secret"`
	Served      *CertFacts   `json:"served"`
	Owner       *SiteOwner   `json:"owner"`
	CertbotName *string      `json:"certbotName"`
	Blocked     *SiteBlocked `json:"blocked"`
	// Autopilot is what the Ingresses of the site's secret annotate (null: none does, or annotations are off).
	Autopilot *SiteAutopilot `json:"autopilot"`
}

// SiteAutopilot is the agent's report of the Autopilot annotations of the Ingresses using a site's secret: only the
// values, the server decides what they mean.
type SiteAutopilot struct {
	// Ingress is the first annotated Ingress by name.
	Ingress string `json:"ingress"`
	// CA and AlertEmail are the raw values (clipped) of the first annotated Ingress that names one.
	CA         *string `json:"ca"`
	AlertEmail *string `json:"alertEmail"`
	// TLSSection is false for a host served without TLS (the secret is made for it).
	TLSSection bool `json:"tlsSection"`
	// Conflict: two annotated Ingresses name different CAs or alert emails.
	Conflict bool `json:"conflict"`
}

// The annotations of an Ingress the agent reports.
const (
	AnnotationEnabled    = "autopilot.nslookup.io/enabled"
	AnnotationCA         = "autopilot.nslookup.io/ca"
	AnnotationAlertEmail = "autopilot.nslookup.io/alert-email"
)

// SecretRef names a Kubernetes TLS secret and the ingress using it.
type SecretRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ingress   string `json:"ingress"`
}

// Inventory is every site the agent found (at most 500).
type Inventory struct {
	Sites []Site `json:"sites"`
}

// InstalledState is what the agent has on disk for one assignment.
type InstalledState struct {
	AssignmentID string  `json:"assignmentId"`
	SHA256OnDisk *string `json:"sha256OnDisk"`
}

// Work is one thing the server asks the agent to do.
type Work struct {
	AssignmentID string         `json:"assignmentId"`
	SiteKey      string         `json:"siteKey"`
	SHA256       string         `json:"sha256"`
	Action       WorkAction     `json:"action"`
	Certbot      *CertbotAction `json:"certbot"`
	// FolderName is for folder certificates only; the agent keeps only [a-z0-9.-], else uses the assignment id.
	FolderName *string `json:"folderName"`
}

// Step is one step of an install and how it went.
type Step struct {
	Name   StepName `json:"name"`
	OK     bool     `json:"ok"`
	Detail *string  `json:"detail"`
}

// JoinRequest is the body of POST /agent/v1/join. The join code is sent only as its id; its secret never travels.
type JoinRequest struct {
	JoinCodeID    string     `json:"joinCodeId"`
	SignPublicKey string     `json:"signPublicKey"`
	SealPublicKey string     `json:"sealPublicKey"`
	Kind          AgentKind  `json:"kind"`
	Name          *string    `json:"name"`
	Facts         AgentFacts `json:"facts"`
}

// JoinResponse is the 201 answer to a join.
type JoinResponse struct {
	AgentID             string `json:"agentId"`
	ServerSignPublicKey string `json:"serverSignPublicKey"`
	PollSeconds         int    `json:"pollSeconds"`
	MinVersion          string `json:"minVersion"`
	LatestVersion       string `json:"latestVersion"`
}

// HeartbeatRequest is the body of POST /agent/v1/heartbeat; Inventory only when it changed or was asked for.
type HeartbeatRequest struct {
	Version       string           `json:"version"`
	Facts         AgentFacts       `json:"facts"`
	InventoryHash string           `json:"inventoryHash"`
	Inventory     *Inventory       `json:"inventory"`
	Installed     []InstalledState `json:"installed"`
}

// HeartbeatResponse is the 200 answer to a heartbeat; Work is empty below MinVersion.
type HeartbeatResponse struct {
	Now           int64  `json:"now"`
	PollSeconds   int    `json:"pollSeconds"`
	WantInventory bool   `json:"wantInventory"`
	MinVersion    string `json:"minVersion"`
	LatestVersion string `json:"latestVersion"`
	// ServerSignPublicKeys are the server's signing keys, 1 or 2 (base64url raw Ed25519): [0] signs its answers now,
	// [1] is the next key during a rollover (ParseServerKeys). nil from a server that lists none.
	ServerSignPublicKeys []string `json:"serverSignPublicKeys,omitempty"`
	Work                 []Work   `json:"work"`
}

// SealedKey is a private key PEM sealed to the agent's X25519 key; Ciphertext = the AES-GCM ciphertext followed by
// the 16-byte tag.
type SealedKey struct {
	EPK        string `json:"epk"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// SealedBundle is the 200 answer of GET /agent/v1/assignments/:assignmentId/bundle, its key still sealed.
type SealedBundle struct {
	AssignmentID string    `json:"assignmentId"`
	SHA256       string    `json:"sha256"`
	CertPEM      string    `json:"certPem"`
	ChainPEM     string    `json:"chainPem"`
	SealedKey    SealedKey `json:"sealedKey"`
}

// Bundle is a SealedBundle opened: what the agent installs.
type Bundle struct {
	AssignmentID, SHA256      string
	CertPEM, ChainPEM, KeyPEM []byte
}

// InstallResult is the body of POST /agent/v1/assignments/:assignmentId/result (answered 204).
type InstallResult struct {
	SHA256        string  `json:"sha256"`
	OK            bool    `json:"ok"`
	Steps         []Step  `json:"steps"`
	Message       *string `json:"message"`
	ServedLocally *bool   `json:"servedLocally"`
	Drift         bool    `json:"drift"`
}

// RemovedBody is the body of the server's signed 403 to a removed agent, byte for byte (IsRemoval).
const RemovedBody = `{"code":"agent_removed"}`

// ErrorBody is the body of a refusal: 410 join_code_invalid, 409 agent_limit_reached, 401 unauthorized or
// clock_skew (with ServerTime), 403 agent_removed, and the like.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// ServerTime is the server's unix time, with clock_skew only.
	ServerTime *int64 `json:"serverTime"`
}

// The server refuses null where the contract has a list, so these send a nil slice as [].

func (f AgentFacts) MarshalJSON() ([]byte, error) {
	type plain AgentFacts
	if f.WebServers == nil {
		f.WebServers = []WebServer{}
	}
	return MarshalBody(plain(f))
}

func (c CertFacts) MarshalJSON() ([]byte, error) {
	type plain CertFacts
	if c.Names == nil {
		c.Names = []string{}
	}
	return MarshalBody(plain(c))
}

func (s Site) MarshalJSON() ([]byte, error) {
	type plain Site
	if s.Names == nil {
		s.Names = []string{}
	}
	return MarshalBody(plain(s))
}

func (i Inventory) MarshalJSON() ([]byte, error) {
	type plain Inventory
	if i.Sites == nil {
		i.Sites = []Site{}
	}
	return MarshalBody(plain(i))
}

func (h HeartbeatRequest) MarshalJSON() ([]byte, error) {
	type plain HeartbeatRequest
	if h.Installed == nil {
		h.Installed = []InstalledState{}
	}
	return MarshalBody(plain(h))
}

func (r InstallResult) MarshalJSON() ([]byte, error) {
	type plain InstallResult
	if r.Steps == nil {
		r.Steps = []Step{}
	}
	return MarshalBody(plain(r))
}
