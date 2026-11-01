// Package protocol is the agent's half of the /agent/v1 protocol: the canonical strings, the Ed25519 request and
// answer signatures, the join code's parts, its proof and MAC, and opening the private key the server sealed to the
// agent. testdata/vectors.json is a copy of the server's test vectors: both sides test against the same file, which
// changes only with the protocol (and then raises its version).
package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	// RequestPrefix starts a request's canonical string.
	RequestPrefix = "NSA1"
	// AnswerPrefix starts an answer's canonical string.
	AnswerPrefix = "NSA1-RESP"
	// JoinRequestLabel precedes the join request body in its proof.
	JoinRequestLabel = "NSA1-JOIN-REQ\n"
	// JoinAnswerLabel precedes the join answer body in its MAC. The two labels keep a request and an answer from ever
	// being mistaken for each other.
	JoinAnswerLabel = "NSA1-JOIN-ANS\n"
	// BundleKeyInfo is the HKDF info of a sealed key.
	BundleKeyInfo = "nslookup-agent bundle key v1"
)

const (
	rawKeyLen = 32
	nonceLen  = 12
	tagLen    = 16
)

var (
	b64urlText = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	// A join code: nsj_<12 base62>_<36 base62>. The id (nsj_<12>) is sent; the secret (the last 36) never travels.
	joinCode = regexp.MustCompile(`^(nsj_[A-Za-z0-9]{12})_([A-Za-z0-9]{36})$`)
	hmacHex  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// The ids the server gives assignments.
	assignmentID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// IsAssignmentID reports whether id is an assignment id as the server gives them (a UUID). Only such an id goes into
// a request path or the agent's memory.
func IsAssignmentID(id string) bool { return assignmentID.MatchString(id) }

// EncodeB64URL is base64url without padding.
func EncodeB64URL(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// DecodeB64URL decodes strict base64url without padding: padding, the standard alphabet, whitespace, an impossible
// length and stray bits are all errors.
func DecodeB64URL(text string) ([]byte, error) {
	if !b64urlText.MatchString(text) {
		return nil, errors.New("not base64url without padding")
	}
	return base64.RawURLEncoding.Strict().DecodeString(text)
}

// SHA256Hex is the lowercase hex SHA-256 of data; an empty body hashes the empty string.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Clip fits a text into a field of the server: control characters (C0, DEL, C1) and surrounding spaces dropped, at
// most max characters kept, counted as the server counts them (UTF-16 units). The server refuses a longer text or one
// with a control character.
func Clip(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "")))
	n := 0
	for i, r := range s {
		if n += utf16.RuneLen(r); n > max {
			return s[:i]
		}
	}
	return s
}

// ParseSignPublicKey reads an Ed25519 public key as the wire carries it: 32 raw bytes in base64url.
func ParseSignPublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := DecodeB64URL(text)
	if err != nil || len(raw) != rawKeyLen {
		return nil, errors.New("a public key must be 32 bytes in base64url")
	}
	return ed25519.PublicKey(raw), nil
}

// MarshalBody encodes a body as it is hashed, signed and sent: JSON without HTML escaping and without a trailing
// newline.
func MarshalBody(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// field refuses a line break, which would make the fields of a canonical string ambiguous.
func field(name, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("the %s of a canonical string holds a line break", name)
	}
	return nil
}

func fields(pairs ...string) error {
	for i := 0; i < len(pairs); i += 2 {
		if err := field(pairs[i], pairs[i+1]); err != nil {
			return err
		}
	}
	return nil
}

// CanonicalRequest is what a request's signature covers:
// "NSA1\n<METHOD>\n<path including query>\n<timestamp>\n<nonce>\n<agentId>\n<sha256 hex of the body>", the path
// exactly as sent (not decoded, not reordered).
func CanonicalRequest(method, pathWithQuery string, timestamp int64, nonce, agentID string, body []byte) (string, error) {
	if timestamp < 0 {
		return "", errors.New("the timestamp of a canonical string must be whole unix seconds")
	}
	if err := fields("method", method, "path", pathWithQuery, "nonce", nonce, "agent id", agentID); err != nil {
		return "", err
	}
	return strings.Join([]string{RequestPrefix, method, pathWithQuery, strconv.FormatInt(timestamp, 10), nonce, agentID, SHA256Hex(body)}, "\n"), nil
}

// SignRequest is the x-nsa-signature of a request: the agent's Ed25519 signature of its canonical string, in
// base64url. priv must be a full Ed25519 private key (64 bytes).
func SignRequest(priv ed25519.PrivateKey, canonical string) string {
	return EncodeB64URL(ed25519.Sign(priv, []byte(canonical)))
}

// AnswerParts is what a signed answer covers: its status and body, and the agent, request line and nonce of the
// request it answers, exactly as that request was signed.
type AnswerParts struct {
	Status        int
	AgentID       string
	Method        string
	PathWithQuery string
	RequestNonce  string
	Body          []byte
}

// CanonicalAnswer is "NSA1-RESP\n<status>\n<agentId>\n<METHOD>\n<path including query>\n<request nonce>\n<sha256
// hex of the body>": naming the agent and the request line, so one agent's signed answer can never be relayed to
// another.
func CanonicalAnswer(a AnswerParts) (string, error) {
	if a.Status < 100 || a.Status > 599 {
		return "", errors.New("the answer status must be an HTTP status code")
	}
	if err := fields("agent id", a.AgentID, "method", a.Method, "path", a.PathWithQuery, "nonce", a.RequestNonce); err != nil {
		return "", err
	}
	return strings.Join([]string{AnswerPrefix, strconv.Itoa(a.Status), a.AgentID, a.Method, a.PathWithQuery, a.RequestNonce, SHA256Hex(a.Body)}, "\n"), nil
}

// SignAnswer is the server's side of VerifyAnswer (tests act as the server with it).
func SignAnswer(priv ed25519.PrivateKey, a AnswerParts) (string, error) {
	canonical, err := CanonicalAnswer(a)
	if err != nil {
		return "", err
	}
	return EncodeB64URL(ed25519.Sign(priv, []byte(canonical))), nil
}

// VerifyAnswer reports whether signature (x-nsa-server-signature) is the server's signature of the answer with the
// server key pub. Anything malformed is false.
func VerifyAnswer(pub ed25519.PublicKey, a AnswerParts, signature string) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	canonical, err := CanonicalAnswer(a)
	if err != nil {
		return false
	}
	sig, err := DecodeB64URL(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(canonical), sig)
}

// VerifyAnswerWithAny is VerifyAnswer with each of the trusted server keys: the key that verified the signature, and
// whether one did.
func VerifyAnswerWithAny(keys []ed25519.PublicKey, a AnswerParts, signature string) (ed25519.PublicKey, bool) {
	for _, k := range keys {
		if VerifyAnswer(k, a, signature) {
			return k, true
		}
	}
	return nil, false
}

// IsRemoval reports whether an answer is the server's removal of the agent: a 403 whose body is exactly RemovedBody.
// The agent acts on it only when its signature verifies; any other 403 is a refusal like the others.
func IsRemoval(status int, body []byte) bool {
	return status == 403 && string(body) == RemovedBody
}

// maxServerKeys: the server signs with one key and names at most one next key.
const maxServerKeys = 2

// smallOrder are the encodings of the Ed25519 points of small order (the sign bit cleared), canonical or not (y = p,
// y = p + 1): a public key among them lets anyone make signatures that verify. The list libsodium checks against.
var smallOrder = [][32]byte{
	{0x00},
	{0x01},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33,
		0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc,
		0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// isSmallOrder reports whether the 32-byte encoding pub is a point of small order.
func isSmallOrder(pub []byte) bool {
	var p [32]byte
	copy(p[:], pub)
	p[31] &= 0x7f
	for _, s := range smallOrder {
		if subtle.ConstantTimeCompare(p[:], s[:]) == 1 {
			return true
		}
	}
	return false
}

// ParseServerKeys reads a heartbeat answer's serverSignPublicKeys: 1 or 2 Ed25519 public keys, each 32 raw bytes in
// base64url and not of small order. Anything else is an error, and the list is not used.
func ParseServerKeys(list []string) ([]ed25519.PublicKey, error) {
	if len(list) < 1 || len(list) > maxServerKeys {
		return nil, fmt.Errorf("the server lists %d signing keys; 1 or %d are expected", len(list), maxServerKeys)
	}
	keys := make([]ed25519.PublicKey, 0, len(list))
	for _, text := range list {
		key, err := ParseSignPublicKey(text)
		if err != nil {
			return nil, err
		}
		if isSmallOrder(key) {
			return nil, errors.New("the server lists a signing key of small order, which would accept anyone's signature")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// SplitJoinCode splits a join code into its id (sent as joinCodeId) and its secret (never sent); ok is false when
// code is not a join code.
func SplitJoinCode(code string) (id, secret string, ok bool) {
	m := joinCode.FindStringSubmatch(code)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

func joinHMAC(secret, label string, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(label))
	mac.Write(body)
	return mac.Sum(nil)
}

// JoinProof is the x-nsa-join-proof of a join request: hex HMAC-SHA256 keyed with the join code's secret over
// JoinRequestLabel followed by the exact request body.
func JoinProof(secret string, requestBody []byte) string {
	return hex.EncodeToString(joinHMAC(secret, JoinRequestLabel, requestBody))
}

// JoinMAC is the x-nsa-join-mac of a join answer: hex HMAC-SHA256 keyed with the join code's secret over
// JoinAnswerLabel followed by the exact answer body.
func JoinMAC(secret string, responseBody []byte) string {
	return hex.EncodeToString(joinHMAC(secret, JoinAnswerLabel, responseBody))
}

// JoinMACMatches reports whether mac (64 lowercase hex) is the join MAC of responseBody, compared in constant time.
func JoinMACMatches(secret string, responseBody []byte, mac string) bool {
	if secret == "" || !hmacHex.MatchString(mac) {
		return false
	}
	got, err := hex.DecodeString(mac)
	return err == nil && hmac.Equal(got, joinHMAC(secret, JoinAnswerLabel, responseBody))
}

func sealAAD(assignmentID, sha256 string) []byte { return []byte(assignmentID + "|" + sha256) }

// bundleKey is HKDF-SHA256(ikm = the X25519 shared secret, salt = epk raw || agent seal public raw, BundleKeyInfo,
// 32 bytes).
func bundleKey(shared, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, salt, BundleKeyInfo, 32)
}

// OpenSealedKey opens the private key PEM the server sealed to the agent's X25519 key for one assignment and
// certificate: X25519 with the ephemeral key, HKDF-SHA256, AES-256-GCM with AAD "<assignmentId>|<sha256>". A wrong
// key, another assignment or certificate, or any changed part is an error.
func OpenSealedKey(priv *ecdh.PrivateKey, assignmentID, sha256 string, s SealedKey) ([]byte, error) {
	if priv == nil || priv.Curve() != ecdh.X25519() {
		return nil, errors.New("opening a sealed key needs the agent's X25519 key")
	}
	epk, errEPK := DecodeB64URL(s.EPK)
	nonce, errNonce := DecodeB64URL(s.Nonce)
	data, errData := DecodeB64URL(s.Ciphertext)
	if errEPK != nil || errNonce != nil || errData != nil || len(epk) != rawKeyLen || len(nonce) != nonceLen || len(data) < tagLen {
		return nil, errors.New("the sealed key is malformed")
	}
	epkKey, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return nil, errors.New("the sealed key is malformed")
	}
	// A low-order point gives an all-zero secret, which anyone could compute: ECDH refuses it.
	shared, err := priv.ECDH(epkKey)
	if err != nil {
		return nil, fmt.Errorf("the sealed key cannot be opened: %w", err)
	}
	key, err := bundleKey(shared, append(epk, priv.PublicKey().Bytes()...))
	clear(shared)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, data, sealAAD(assignmentID, sha256))
	if err != nil {
		return nil, errors.New("the sealed key does not open with this agent's key for this assignment and certificate")
	}
	return plaintext, nil
}
