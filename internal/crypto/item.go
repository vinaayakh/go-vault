package crypto

import (
	"encoding/json"
	"fmt"
)

// Item is the plaintext shape of a single vault entry. It exists only inside the
// client's trust zone; it is JSON-serialized and sealed under the vault key
// before it ever leaves memory. Never log or stringify a populated Item.
type Item struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
	TOTPSeed string `json:"totp_seed"`
}

// EncryptItem serializes item to JSON and seals it under the vault key. aad
// (which may be nil) binds the ciphertext to its context, e.g. the item id. The
// transient plaintext buffer is zeroed before returning.
func EncryptItem(vaultKey []byte, item Item, aad []byte) ([]byte, error) {
	// The marshaled JSON (which contains the password/TOTP fields) exists only to
	// be sealed on the next line; it is never persisted, logged, or transmitted
	// in cleartext, and the buffer is zeroed via defer below.
	plaintext, err := json.Marshal(item) //nolint:gosec // G117: marshaled solely to be immediately Sealed under the vault key
	if err != nil {
		return nil, fmt.Errorf("marshal item: %w", err)
	}
	defer Zero(plaintext)

	return Seal(vaultKey, plaintext, aad)
}

// DecryptItem opens a sealed item blob with the vault key and deserializes it.
// The aad must match the value passed to EncryptItem. The transient plaintext
// buffer is zeroed before returning.
func DecryptItem(vaultKey, blob, aad []byte) (Item, error) {
	plaintext, err := Open(vaultKey, blob, aad)
	if err != nil {
		return Item{}, err
	}
	defer Zero(plaintext)

	var item Item
	if err := json.Unmarshal(plaintext, &item); err != nil {
		return Item{}, fmt.Errorf("unmarshal item: %w", err)
	}
	return item, nil
}
