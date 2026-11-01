package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// vectors mirrors testdata/vectors.json, a byte-for-byte copy of the server's own test vectors: both sides test
// against the same file.
type vectors struct {
	Version int `json:"version"`
	Keys    struct {
		AgentSign  struct{ Seed, PublicKey string }       `json:"agentSign"`
		AgentSeal  struct{ PrivateKey, PublicKey string } `json:"agentSeal"`
		ServerSign struct{ Seed, PublicKey string }       `json:"serverSign"`
		// ServerSignNext is the next server key of a key rollover.
		ServerSignNext struct{ Seed, PublicKey string } `json:"serverSignNext"`
	} `json:"keys"`
	Requests []struct {
		Name          string `json:"name"`
		Method        string `json:"method"`
		PathWithQuery string `json:"pathWithQuery"`
		Timestamp     int64  `json:"timestamp"`
		Nonce         string `json:"nonce"`
		AgentID       string `json:"agentId"`
		Body          string `json:"body"`
		BodySha256    string `json:"bodySha256"`
		Canonical     string `json:"canonical"`
		Signature     string `json:"signature"`
	} `json:"requests"`
	Answers []struct {
		Name string `json:"name"`
		// SignedBy names the key of Keys that signs it.
		SignedBy      string `json:"signedBy"`
		Status        int    `json:"status"`
		AgentID       string `json:"agentId"`
		Method        string `json:"method"`
		PathWithQuery string `json:"pathWithQuery"`
		RequestNonce  string `json:"requestNonce"`
		Body          string `json:"body"`
		BodySha256    string `json:"bodySha256"`
		Canonical     string `json:"canonical"`
		Signature     string `json:"signature"`
	} `json:"answers"`
	JoinCodes struct {
		Valid []struct {
			JoinCode   string `json:"joinCode"`
			JoinCodeID string `json:"joinCodeId"`
			Secret     string `json:"secret"`
		} `json:"valid"`
		Invalid []string `json:"invalid"`
	} `json:"joinCodes"`
	Joins []struct {
		Name            string `json:"name"`
		JoinCode        string `json:"joinCode"`
		JoinCodeID      string `json:"joinCodeId"`
		Secret          string `json:"secret"`
		RequestBody     string `json:"requestBody"`
		ProofMessageHex string `json:"proofMessageHex"`
		Proof           string `json:"proof"`
		ResponseBody    string `json:"responseBody"`
		MACMessageHex   string `json:"macMessageHex"`
		MAC             string `json:"mac"`
	} `json:"joins"`
	Seals []struct {
		Name                string    `json:"name"`
		AssignmentID        string    `json:"assignmentId"`
		SHA256              string    `json:"sha256"`
		Plaintext           string    `json:"plaintext"`
		AAD                 string    `json:"aad"`
		EphemeralPrivateKey string    `json:"ephemeralPrivateKey"`
		SharedSecret        string    `json:"sharedSecret"`
		Salt                string    `json:"salt"`
		BundleKey           string    `json:"bundleKey"`
		Sealed              SealedKey `json:"sealed"`
	} `json:"seals"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func b64(t *testing.T, text string) []byte {
	t.Helper()
	data, err := DecodeB64URL(text)
	if err != nil {
		t.Fatalf("%q: %v", text, err)
	}
	return data
}

func signKey(t *testing.T, seed string) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(b64(t, seed))
}

func sealKey(t *testing.T, raw string) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(b64(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestVectorFileIsVersion4AndComplete(t *testing.T) {
	v := loadVectors(t)
	if v.Version != 4 {
		t.Fatalf("version = %d, want 4 (a new version means the protocol changed: update the agent with it)", v.Version)
	}
	if len(v.Requests) == 0 || len(v.Answers) == 0 || len(v.JoinCodes.Valid) == 0 || len(v.JoinCodes.Invalid) == 0 || len(v.Joins) == 0 || len(v.Seals) == 0 {
		t.Fatal("a section of the vectors is empty")
	}
}

func TestVectorKeys(t *testing.T) {
	v := loadVectors(t)
	for name, k := range map[string]struct{ Seed, PublicKey string }{"agentSign": v.Keys.AgentSign, "serverSign": v.Keys.ServerSign, "serverSignNext": v.Keys.ServerSignNext} {
		pub := signKey(t, k.Seed).Public().(ed25519.PublicKey)
		if got := EncodeB64URL(pub); got != k.PublicKey {
			t.Errorf("%s public key = %s, want %s", name, got, k.PublicKey)
		}
		parsed, err := ParseSignPublicKey(k.PublicKey)
		if err != nil || !bytes.Equal(parsed, pub) {
			t.Errorf("%s: ParseSignPublicKey = %x, %v", name, parsed, err)
		}
	}
	seal := sealKey(t, v.Keys.AgentSeal.PrivateKey)
	if got := EncodeB64URL(seal.PublicKey().Bytes()); got != v.Keys.AgentSeal.PublicKey {
		t.Errorf("agentSeal public key = %s, want %s", got, v.Keys.AgentSeal.PublicKey)
	}
}

func TestVectorRequests(t *testing.T) {
	v := loadVectors(t)
	priv := signKey(t, v.Keys.AgentSign.Seed)
	for _, r := range v.Requests {
		t.Run(r.Name, func(t *testing.T) {
			if got := SHA256Hex([]byte(r.Body)); got != r.BodySha256 {
				t.Errorf("body sha256 = %s, want %s", got, r.BodySha256)
			}
			canonical, err := CanonicalRequest(r.Method, r.PathWithQuery, r.Timestamp, r.Nonce, r.AgentID, []byte(r.Body))
			if err != nil {
				t.Fatal(err)
			}
			if canonical != r.Canonical {
				t.Errorf("canonical = %q, want %q", canonical, r.Canonical)
			}
			if got := SignRequest(priv, canonical); got != r.Signature {
				t.Errorf("signature = %s, want %s", got, r.Signature)
			}
			if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte(r.Canonical), b64(t, r.Signature)) {
				t.Error("the vector's signature does not verify with the agent's public key")
			}
		})
	}
}

func TestVectorAnswers(t *testing.T) {
	v := loadVectors(t)
	agentPub := signKey(t, v.Keys.AgentSign.Seed).Public().(ed25519.PublicKey)
	for _, a := range v.Answers {
		t.Run(a.Name, func(t *testing.T) {
			seeds := map[string]string{"serverSign": v.Keys.ServerSign.Seed, "serverSignNext": v.Keys.ServerSignNext.Seed}
			if seeds[a.SignedBy] == "" {
				t.Fatalf("signed by %q, a key the vectors do not have", a.SignedBy)
			}
			server := signKey(t, seeds[a.SignedBy])
			serverPub := server.Public().(ed25519.PublicKey)
			parts := AnswerParts{Status: a.Status, AgentID: a.AgentID, Method: a.Method, PathWithQuery: a.PathWithQuery, RequestNonce: a.RequestNonce, Body: []byte(a.Body)}
			if got := SHA256Hex([]byte(a.Body)); got != a.BodySha256 {
				t.Errorf("body sha256 = %s, want %s", got, a.BodySha256)
			}
			canonical, err := CanonicalAnswer(parts)
			if err != nil {
				t.Fatal(err)
			}
			if canonical != a.Canonical {
				t.Errorf("canonical = %q, want %q", canonical, a.Canonical)
			}
			signature, err := SignAnswer(server, parts)
			if err != nil {
				t.Fatal(err)
			}
			if signature != a.Signature {
				t.Errorf("signature = %s, want %s", signature, a.Signature)
			}
			if !VerifyAnswer(serverPub, parts, a.Signature) {
				t.Fatal("VerifyAnswer refused the vector's own signature")
			}

			// Every field the signature covers: changing any one of them, or the key, must fail.
			changed := map[string]AnswerParts{}
			p := parts
			p.Status++
			changed["status"] = p
			p = parts
			p.AgentID = "0d6f1e2a-3b4c-4d5e-8f60-718293a4b5c6"
			changed["agent id"] = p
			p = parts
			p.Method = map[string]string{"GET": "POST", "POST": "GET"}[parts.Method]
			changed["method"] = p
			p = parts
			p.PathWithQuery += "?x=1"
			changed["path"] = p
			p = parts
			p.RequestNonce = "AAAAAAAAAAAAAAAAAAAAAA"
			changed["request nonce"] = p
			p = parts
			p.Body = append([]byte(a.Body), ' ')
			changed["body"] = p
			for name, p := range changed {
				if VerifyAnswer(serverPub, p, a.Signature) {
					t.Errorf("verified with a changed %s", name)
				}
			}
			if VerifyAnswer(agentPub, parts, a.Signature) {
				t.Error("verified with another key")
			}
			sigBytes := b64(t, a.Signature)
			for name, sig := range map[string]string{
				"empty":             "",
				"truncated":         a.Signature[:len(a.Signature)-2],
				"padded":            a.Signature + "==",
				"standard alphabet": strings.NewReplacer("-", "+", "_", "/").Replace(a.Signature) + "+",
				"flipped bit":       EncodeB64URL(append([]byte{sigBytes[0] ^ 1}, sigBytes[1:]...)),
			} {
				if VerifyAnswer(serverPub, parts, sig) {
					t.Errorf("verified a %s signature", name)
				}
			}
			if VerifyAnswer(serverPub[:31], parts, a.Signature) {
				t.Error("verified with a 31-byte key")
			}
		})
	}
}

// Every answer verifies with a set of trusted keys holding the key that signed it, and with no set without it.
func TestVectorAnswersVerifyWithATrustedKeySet(t *testing.T) {
	v := loadVectors(t)
	active := signKey(t, v.Keys.ServerSign.Seed).Public().(ed25519.PublicKey)
	next := signKey(t, v.Keys.ServerSignNext.Seed).Public().(ed25519.PublicKey)
	for _, a := range v.Answers {
		parts := AnswerParts{Status: a.Status, AgentID: a.AgentID, Method: a.Method, PathWithQuery: a.PathWithQuery, RequestNonce: a.RequestNonce, Body: []byte(a.Body)}
		signer := map[string]ed25519.PublicKey{"serverSign": active, "serverSignNext": next}[a.SignedBy]
		other := map[string]ed25519.PublicKey{"serverSign": next, "serverSignNext": active}[a.SignedBy]
		if by, ok := VerifyAnswerWithAny([]ed25519.PublicKey{other, signer}, parts, a.Signature); !ok || !bytes.Equal(by, signer) {
			t.Errorf("%s: with both keys: %x, %v", a.Name, by, ok)
		}
		if _, ok := VerifyAnswerWithAny([]ed25519.PublicKey{other}, parts, a.Signature); ok {
			t.Errorf("%s: verified without the key that signed it", a.Name)
		}
		if _, ok := VerifyAnswerWithAny(nil, parts, a.Signature); ok {
			t.Errorf("%s: verified with no key", a.Name)
		}
	}
}

// The heartbeat answers' lists of server keys: read as the agent reads them, the key that signed each answer among them.
func TestVectorServerKeyLists(t *testing.T) {
	v := loadVectors(t)
	keys := map[string]string{"serverSign": v.Keys.ServerSign.PublicKey, "serverSignNext": v.Keys.ServerSignNext.PublicKey}
	lists := 0
	for _, a := range v.Answers {
		var resp HeartbeatResponse
		if a.PathWithQuery != APIBase+"/heartbeat" || a.Status != 200 || json.Unmarshal([]byte(a.Body), &resp) != nil || resp.ServerSignPublicKeys == nil {
			continue
		}
		lists++
		parsed, err := ParseServerKeys(resp.ServerSignPublicKeys)
		if err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
		signer, _ := ParseSignPublicKey(keys[a.SignedBy])
		if !slices.ContainsFunc(parsed, func(k ed25519.PublicKey) bool { return bytes.Equal(k, signer) }) {
			t.Errorf("%s: the list %v does not hold the key that signed it", a.Name, resp.ServerSignPublicKeys)
		}
	}
	if lists != 2 {
		t.Errorf("%d heartbeat answers list server keys, want 2", lists)
	}
}

// A list of server keys is 1 or 2 well formed Ed25519 public keys, none of small order (which would let anyone make a
// signature that verifies).
func TestServerKeyListsTheAgentRefuses(t *testing.T) {
	v := loadVectors(t)
	good := v.Keys.ServerSign.PublicKey
	smallOrder := []string{
		"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // the neutral point
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // order 4
		"7P_______________________________________38", // order 2: p-1
	}
	for name, list := range map[string][]string{
		"none":                {},
		"three":               {good, v.Keys.ServerSignNext.PublicKey, good},
		"not base64url":       {"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ+mRMw"},
		"padded":              {good + "="},
		"31 bytes":            {EncodeB64URL(make([]byte, 31))},
		"empty":               {""},
		"the neutral point":   {smallOrder[0]},
		"order 4":             {good, smallOrder[1]},
		"order 2":             {smallOrder[2]},
		"order 8":             {EncodeB64URL(mustHex(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))},
		"order 8, sign bit":   {EncodeB64URL(mustHex(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"))},
		"non-canonical p + 1": {EncodeB64URL(mustHex(t, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))},
	} {
		if keys, err := ParseServerKeys(list); err == nil {
			t.Errorf("%s: accepted %x", name, keys)
		}
	}
	if keys, err := ParseServerKeys([]string{good}); err != nil || len(keys) != 1 {
		t.Errorf("one key: %v, %v", keys, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The one refusal the agent acts on is signed: a 403 whose body is exactly {"code":"agent_removed"}.
func TestARemovalIsTheExactBody(t *testing.T) {
	v := loadVectors(t)
	found := false
	for _, a := range v.Answers {
		if a.Status == 403 {
			found = true
			if !IsRemoval(a.Status, []byte(a.Body)) {
				t.Errorf("%s: not a removal", a.Name)
			}
		}
	}
	if !found {
		t.Error("no signed 403 among the vectors")
	}
	for _, c := range []struct {
		status int
		body   string
	}{
		{403, `{"code":"agent_removed","message":"x"}`},
		{403, `{"code": "agent_removed"}`},
		{403, `{"code":"forbidden"}`},
		{401, `{"code":"agent_removed"}`},
		{200, `{"code":"agent_removed"}`},
	} {
		if IsRemoval(c.status, []byte(c.body)) {
			t.Errorf("%d %s: a removal", c.status, c.body)
		}
	}
}

func TestVectorJoinCodes(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.JoinCodes.Valid {
		id, secret, ok := SplitJoinCode(c.JoinCode)
		if !ok || id != c.JoinCodeID || secret != c.Secret {
			t.Errorf("SplitJoinCode(%q) = %q, %q, %v; want %q, %q", c.JoinCode, id, secret, ok, c.JoinCodeID, c.Secret)
		}
	}
	for _, code := range v.JoinCodes.Invalid {
		if id, secret, ok := SplitJoinCode(code); ok || id != "" || secret != "" {
			t.Errorf("SplitJoinCode(%q) accepted it: %q, %q", code, id, secret)
		}
	}
}

func TestVectorJoins(t *testing.T) {
	v := loadVectors(t)
	for _, j := range v.Joins {
		t.Run(j.Name, func(t *testing.T) {
			id, secret, ok := SplitJoinCode(j.JoinCode)
			if !ok || id != j.JoinCodeID || secret != j.Secret {
				t.Fatalf("SplitJoinCode = %q, %q, %v", id, secret, ok)
			}
			if got := hex.EncodeToString(append([]byte(JoinRequestLabel), j.RequestBody...)); got != j.ProofMessageHex {
				t.Errorf("proof message = %s, want %s", got, j.ProofMessageHex)
			}
			if got := hex.EncodeToString(append([]byte(JoinAnswerLabel), j.ResponseBody...)); got != j.MACMessageHex {
				t.Errorf("MAC message = %s, want %s", got, j.MACMessageHex)
			}
			if got := JoinProof(secret, []byte(j.RequestBody)); got != j.Proof {
				t.Errorf("proof = %s, want %s", got, j.Proof)
			}
			if got := JoinMAC(secret, []byte(j.ResponseBody)); got != j.MAC {
				t.Errorf("MAC = %s, want %s", got, j.MAC)
			}
			if !JoinMACMatches(secret, []byte(j.ResponseBody), j.MAC) {
				t.Fatal("JoinMACMatches refused the vector's MAC")
			}
			_, otherSecret, _ := SplitJoinCode(v.JoinCodes.Valid[1].JoinCode)
			for name, c := range map[string]struct {
				secret, body, mac string
			}{
				"the request's proof as an answer's MAC (the labels differ)": {secret, j.RequestBody, j.Proof},
				"another code's secret":       {otherSecret, j.ResponseBody, j.MAC},
				"a changed answer":            {secret, j.ResponseBody + " ", j.MAC},
				"an uppercase MAC":            {secret, j.ResponseBody, strings.ToUpper(j.MAC)},
				"a truncated MAC":             {secret, j.ResponseBody, j.MAC[:63]},
				"no MAC":                      {secret, j.ResponseBody, ""},
				"the MAC with a newline":      {secret, j.ResponseBody, j.MAC + "\n"},
				"the MAC of no secret at all": {"", j.ResponseBody, j.MAC},
			} {
				if JoinMACMatches(c.secret, []byte(c.body), c.mac) {
					t.Errorf("JoinMACMatches accepted %s", name)
				}
			}
		})
	}
}

func TestVectorSeals(t *testing.T) {
	v := loadVectors(t)
	agent := sealKey(t, v.Keys.AgentSeal.PrivateKey)
	for _, s := range v.Seals {
		t.Run(s.Name, func(t *testing.T) {
			ephemeral := sealKey(t, s.EphemeralPrivateKey)
			if got := EncodeB64URL(ephemeral.PublicKey().Bytes()); got != s.Sealed.EPK {
				t.Errorf("epk = %s, want %s", got, s.Sealed.EPK)
			}
			epk, err := ecdh.X25519().NewPublicKey(b64(t, s.Sealed.EPK))
			if err != nil {
				t.Fatal(err)
			}
			fromServer, err := ephemeral.ECDH(agent.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			fromAgent, err := agent.ECDH(epk)
			if err != nil {
				t.Fatal(err)
			}
			if EncodeB64URL(fromServer) != s.SharedSecret || EncodeB64URL(fromAgent) != s.SharedSecret {
				t.Errorf("shared secret = %s / %s, want %s", EncodeB64URL(fromServer), EncodeB64URL(fromAgent), s.SharedSecret)
			}
			salt := append(b64(t, s.Sealed.EPK), agent.PublicKey().Bytes()...)
			if got := EncodeB64URL(salt); got != s.Salt {
				t.Errorf("salt = %s, want %s", got, s.Salt)
			}
			key, err := bundleKey(fromAgent, salt)
			if err != nil {
				t.Fatal(err)
			}
			if got := EncodeB64URL(key); got != s.BundleKey {
				t.Errorf("bundle key = %s, want %s", got, s.BundleKey)
			}
			if got := string(sealAAD(s.AssignmentID, s.SHA256)); got != s.AAD {
				t.Errorf("aad = %q, want %q", got, s.AAD)
			}
			// The server's side, with the vector's fixed nonce: the same ciphertext and tag.
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			if got := EncodeB64URL(gcm.Seal(nil, b64(t, s.Sealed.Nonce), []byte(s.Plaintext), []byte(s.AAD))); got != s.Sealed.Ciphertext {
				t.Errorf("ciphertext = %s, want %s", got, s.Sealed.Ciphertext)
			}

			plaintext, err := OpenSealedKey(agent, s.AssignmentID, s.SHA256, s.Sealed)
			if err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != s.Plaintext {
				t.Errorf("opened = %q, want %q", plaintext, s.Plaintext)
			}
		})
	}
}

func TestOpenSealedKeyRefusesAnythingElse(t *testing.T) {
	v := loadVectors(t)
	agent := sealKey(t, v.Keys.AgentSeal.PrivateKey)
	s := v.Seals[0]
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := b64(t, s.Sealed.Ciphertext)
	flipped := append([]byte{}, data...)
	flipped[len(flipped)-1] ^= 1
	lowOrderEPK := make([]byte, 32) // the all-zero point: every shared secret with it is zero
	cases := map[string]struct {
		key                  *ecdh.PrivateKey
		assignmentID, sha256 string
		sealed               SealedKey
	}{
		"another assignment (AAD)": {agent, v.Seals[1].AssignmentID, s.SHA256, s.Sealed},
		"another sha256 (AAD)":     {agent, s.AssignmentID, v.Seals[1].SHA256, s.Sealed},
		"another agent's key":      {other, s.AssignmentID, s.SHA256, s.Sealed},
		"a changed ciphertext":     {agent, s.AssignmentID, s.SHA256, SealedKey{EPK: s.Sealed.EPK, Nonce: s.Sealed.Nonce, Ciphertext: EncodeB64URL(flipped)}},
		"a short ciphertext":       {agent, s.AssignmentID, s.SHA256, SealedKey{EPK: s.Sealed.EPK, Nonce: s.Sealed.Nonce, Ciphertext: EncodeB64URL(data[:15])}},
		"another seal's nonce":     {agent, s.AssignmentID, s.SHA256, SealedKey{EPK: s.Sealed.EPK, Nonce: v.Seals[1].Sealed.Nonce, Ciphertext: s.Sealed.Ciphertext}},
		"a nonce of 11 bytes":      {agent, s.AssignmentID, s.SHA256, SealedKey{EPK: s.Sealed.EPK, Nonce: EncodeB64URL(make([]byte, 11)), Ciphertext: s.Sealed.Ciphertext}},
		"an epk of 31 bytes":       {agent, s.AssignmentID, s.SHA256, SealedKey{EPK: EncodeB64URL(b64(t, s.Sealed.EPK)[:31]), Nonce: s.Sealed.Nonce, Ciphertext: s.Sealed.Ciphertext}},
		"a low-order epk":          {agent, s.AssignmentID, s.SHA256, SealedKey{EPK: EncodeB64URL(lowOrderEPK), Nonce: s.Sealed.Nonce, Ciphertext: s.Sealed.Ciphertext}},
		"a padded epk":             {agent, s.AssignmentID, s.SHA256, SealedKey{EPK: s.Sealed.EPK + "=", Nonce: s.Sealed.Nonce, Ciphertext: s.Sealed.Ciphertext}},
		"no key":                   {nil, s.AssignmentID, s.SHA256, s.Sealed},
	}
	for name, c := range cases {
		if plaintext, err := OpenSealedKey(c.key, c.assignmentID, c.sha256, c.sealed); err == nil {
			t.Errorf("%s: opened %q", name, plaintext)
		}
	}
}

func TestCanonicalStringsRefuseLineBreaks(t *testing.T) {
	for name, call := range map[string]func() error{
		"method":   func() error { _, err := CanonicalRequest("GET\n", "/agent/v1/heartbeat", 1, "n", "a", nil); return err },
		"path":     func() error { _, err := CanonicalRequest("GET", "/agent/v1/x\r\n", 1, "n", "a", nil); return err },
		"nonce":    func() error { _, err := CanonicalRequest("GET", "/agent/v1/x", 1, "n\n", "a", nil); return err },
		"agent id": func() error { _, err := CanonicalRequest("GET", "/agent/v1/x", 1, "n", "a\n", nil); return err },
		"negative timestamp": func() error {
			_, err := CanonicalRequest("GET", "/agent/v1/x", -1, "n", "a", nil)
			return err
		},
		"answer path": func() error {
			_, err := CanonicalAnswer(AnswerParts{Status: 200, AgentID: "a", Method: "GET", PathWithQuery: "/x\n", RequestNonce: "n"})
			return err
		},
		"answer status": func() error {
			_, err := CanonicalAnswer(AnswerParts{Status: 99, AgentID: "a", Method: "GET", PathWithQuery: "/x", RequestNonce: "n"})
			return err
		},
	} {
		if call() == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestDecodeB64URLIsStrict(t *testing.T) {
	for _, text := range []string{"AAAA=", "AA==", "+/AA", "AA\nAA", "AB", " AAAA", "AAAA\r"} {
		if data, err := DecodeB64URL(text); err == nil {
			t.Errorf("DecodeB64URL(%q) = %x, want an error", text, data)
		}
	}
	for text, want := range map[string]string{"": "", "AA": "00", "_-8": "ffef"} {
		data, err := DecodeB64URL(text)
		if err != nil || hex.EncodeToString(data) != want {
			t.Errorf("DecodeB64URL(%q) = %x, %v; want %s", text, data, err, want)
		}
	}
	if _, err := ParseSignPublicKey(EncodeB64URL(make([]byte, 31))); err == nil {
		t.Error("ParseSignPublicKey accepted 31 bytes")
	}
}

// The wire types carry the exact JSON names and order of the contract: every body in the vectors decodes and encodes
// back to the same bytes.
func TestWireTypesRoundTripTheVectorBodies(t *testing.T) {
	v := loadVectors(t)
	check := func(name, body string, into any) {
		t.Helper()
		if err := json.Unmarshal([]byte(body), into); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, err := MarshalBody(into)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(out) != body {
			t.Errorf("%s:\n got %s\nwant %s", name, out, body)
		}
	}
	check("heartbeat request", v.Requests[0].Body, &HeartbeatRequest{})
	check("install result", v.Requests[2].Body, &InstallResult{})
	for _, a := range v.Answers {
		if a.PathWithQuery == APIBase+"/heartbeat" && a.Status == 200 {
			check(a.Name, a.Body, &HeartbeatResponse{})
		}
	}
	check("bundle", v.Answers[1].Body, &SealedBundle{})
	check("join request", v.Joins[0].RequestBody, &JoinRequest{})
	check("join response", v.Joins[0].ResponseBody, &JoinResponse{})
}

// The server refuses null where the contract has a list, so a nil slice goes out as [].
func TestMarshalBodySendsEmptyListsNeverNull(t *testing.T) {
	for name, c := range map[string]struct {
		value any
		want  []string
	}{
		"heartbeat":  {HeartbeatRequest{}, []string{`"installed":[]`, `"webServers":[]`, `"inventory":null`, `"kubernetes":null`}},
		"inventory":  {Inventory{}, []string{`"sites":[]`}},
		"site":       {Site{}, []string{`"names":[]`, `"served":null`, `"secret":null`, `"blocked":null`}},
		"cert facts": {CertFacts{}, []string{`"names":[]`}},
		"result":     {InstallResult{}, []string{`"steps":[]`, `"message":null`, `"servedLocally":null`}},
		"join":       {JoinRequest{}, []string{`"name":null`, `"webServers":[]`}},
	} {
		out, err := MarshalBody(c.value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, w := range c.want {
			if !strings.Contains(string(out), w) {
				t.Errorf("%s: %s lacks %s", name, out, w)
			}
		}
	}
	out, err := MarshalBody(InstallResult{Message: ptr("<a> & “b”")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"message":"<a> & “b”"`) || strings.HasSuffix(string(out), "\n") {
		t.Errorf("MarshalBody escaped HTML or added a newline: %q", out)
	}
}

func ptr[T any](v T) *T { return &v }

func TestClip(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
	}{
		{"  web-1\n", 64, "web-1"},
		{"a\tb\x01c\x7fd\u0085e", 64, "abcde"},
		{"ab\xffcd", 64, "abcd"},
		{"abcdef", 4, "abcd"},
		{"é" + "é" + "é", 2, "éé"},
		// U+1F512 is two UTF-16 units, as the server counts it: it does not fit in the last one.
		{"ab\U0001F512", 3, "ab"},
		{"ab\U0001F512", 4, "ab\U0001F512"},
		{"", 8, ""},
	} {
		if got := Clip(c.in, c.max); got != c.want {
			t.Errorf("Clip(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestIsAssignmentID(t *testing.T) {
	for _, id := range []string{"9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e", "9C1D4E7A-2B3F-4A8C-9D6E-0F1A2B3C4D5E"} {
		if !IsAssignmentID(id) {
			t.Errorf("IsAssignmentID(%q) = false", id)
		}
	}
	for _, id := range []string{"", "not-an-id", "../join", "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5", "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e/../join",
		"9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e?x=1", "9c1d4e7a2b3f4a8c9d6e0f1a2b3c4d5e", "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e\n"} {
		if IsAssignmentID(id) {
			t.Errorf("IsAssignmentID(%q) = true", id)
		}
	}
}
