// Package database — token.go.
//
// Confirmation-token verification for destructive database operations
// (drop_db, drop_user). The control plane mints a short-lived token that
// pins the operation type, the target instance, and the specific resource
// being touched; the agent rejects the operation if the token is missing,
// expired, malformed, or does not match what the agent is being asked to
// do. This is the authoritative defense against a compromised or buggy
// caller issuing a destructive op against the wrong target.
//
// Wire format (shared with cloudnan-core):
//
//	token = base64url(payload_json) + "." + base64url(hmac_sha256(secret, payload_json))
//
// Payload is the opToken JSON object below. The shared secret is read from
// the env var DATABASE_OP_TOKEN_SECRET and must be at least 32 bytes long;
// a missing or short secret causes every destructive op to be rejected
// — fail-closed by design, because relaxing this would mean a freshly
// installed agent with no secret configured could be told to drop databases.
package database

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// opTokenSecretEnv is the env var carrying the raw HMAC secret. The bytes
// are used as-is (no decoding) so the operator may supply any high-entropy
// string of length >= opTokenMinSecretLen.
const (
	opTokenSecretEnv    = "DATABASE_OP_TOKEN_SECRET"
	opTokenMinSecretLen = 32
)

// opToken is the JSON payload signed by the control plane. Field names are
// fixed by the wire contract; do not rename without updating the core.
type opToken struct {
	Op         string `json:"op"`
	InstanceID string `json:"instance_id"`
	Target     string `json:"target"`
	ExpiresAt  int64  `json:"expires_at"`
}

// verifyOpToken validates that token is a well-formed signature over a
// payload whose op/instance_id/target match the expected values and whose
// expires_at is still in the future. Any deviation is reported as an error;
// the caller MUST treat any non-nil error as a hard reject.
func verifyOpToken(token, expectedOp, expectedInstance, expectedTarget string) error {
	if token == "" {
		return errors.New("missing confirmation token")
	}

	secret := []byte(os.Getenv(opTokenSecretEnv))
	if len(secret) < opTokenMinSecretLen {
		return fmt.Errorf("agent has no %s configured (or it is too short); destructive ops are disabled", opTokenSecretEnv)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("malformed token: expected <payload>.<signature>")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("malformed token payload: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("malformed token signature: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(payloadBytes)
	expectedSig := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sigBytes, expectedSig) != 1 {
		return errors.New("token signature mismatch")
	}

	var p opToken
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return fmt.Errorf("token payload unmarshal: %w", err)
	}

	if p.Op != expectedOp {
		return fmt.Errorf("token op %q does not match operation %q", p.Op, expectedOp)
	}
	if p.InstanceID != expectedInstance {
		return fmt.Errorf("token instance_id %q does not match request instance %q", p.InstanceID, expectedInstance)
	}
	if p.Target != expectedTarget {
		return fmt.Errorf("token target %q does not match resource %q", p.Target, expectedTarget)
	}
	if p.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("token expired at %d", p.ExpiresAt)
	}
	return nil
}
