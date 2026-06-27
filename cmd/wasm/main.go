//go:build js

// cmd/wasm/main.go compiles internal/crypto to WebAssembly, exposing the
// zero-knowledge key hierarchy to the browser via global JavaScript functions.
// All functions are prefixed "vc" (vault-crypto) to avoid polluting globals.
//
// Byte arrays cross the JS boundary as standard-padded Base64 strings.
// KDF parameters travel as JSON strings.
// Errors are reported as JS exceptions (Go panics become JS Errors).
//
// Build: GOOS=js GOARCH=wasm go build -o web/public/crypto.wasm ./cmd/wasm
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"syscall/js"

	vc "github.com/vinaayakh/secure-vault/internal/crypto"
)

func main() {
	g := js.Global()
	g.Set("vcDeriveMasterKey", js.FuncOf(jsDeriveMasterKey))
	g.Set("vcDeriveAuthHash", js.FuncOf(jsDeriveAuthHash))
	g.Set("vcStretchMasterKey", js.FuncOf(jsStretchMasterKey))
	g.Set("vcNewVaultKey", js.FuncOf(jsNewVaultKey))
	g.Set("vcWrapVaultKey", js.FuncOf(jsWrapVaultKey))
	g.Set("vcUnwrapVaultKey", js.FuncOf(jsUnwrapVaultKey))
	g.Set("vcSealItem", js.FuncOf(jsSealItem))
	g.Set("vcOpenItem", js.FuncOf(jsOpenItem))
	g.Set("vcGeneratePassword", js.FuncOf(jsGeneratePassword))
	select {} // block so the module stays alive
}

// decodeB64 decodes a standard-padded Base64 string, panicking on failure.
func decodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("invalid base64: " + err.Error())
	}
	return b
}

// parseKDF decodes a JSON-encoded KDFParams object.
func parseKDF(s string) vc.KDFParams {
	var p vc.KDFParams
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		panic("invalid KDF params JSON: " + err.Error())
	}
	return p
}

// jsDeriveMasterKey(password: string, email: string, kdfParamsJSON: string) → string
func jsDeriveMasterKey(_ js.Value, args []js.Value) any {
	password := []byte(args[0].String())
	salt := []byte(vc.NormalizeEmail(args[1].String()))
	params := parseKDF(args[2].String())

	key, err := vc.DeriveMasterKey(password, salt, params)
	vc.Zero(password)
	if err != nil {
		panic(err.Error())
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	vc.Zero(key)
	return encoded
}

// jsDeriveAuthHash(masterKeyB64: string, password: string, kdfParamsJSON: string) → string
func jsDeriveAuthHash(_ js.Value, args []js.Value) any {
	masterKey := decodeB64(args[0].String())
	password := []byte(args[1].String())
	params := parseKDF(args[2].String())

	hash, err := vc.DeriveAuthHash(masterKey, password, params)
	vc.Zero(masterKey)
	vc.Zero(password)
	if err != nil {
		panic(err.Error())
	}
	encoded := base64.StdEncoding.EncodeToString(hash)
	vc.Zero(hash)
	return encoded
}

// jsStretchMasterKey(masterKeyB64: string) → {encKey: string, macKey: string}
func jsStretchMasterKey(_ js.Value, args []js.Value) any {
	masterKey := decodeB64(args[0].String())

	encKey, macKey, err := vc.StretchMasterKey(masterKey)
	vc.Zero(masterKey)
	if err != nil {
		panic(err.Error())
	}

	obj := js.Global().Get("Object").New()
	obj.Set("encKey", base64.StdEncoding.EncodeToString(encKey))
	obj.Set("macKey", base64.StdEncoding.EncodeToString(macKey))
	vc.Zero(encKey)
	vc.Zero(macKey)
	return obj
}

// jsNewVaultKey() → string
func jsNewVaultKey(_ js.Value, _ []js.Value) any {
	key, err := vc.NewVaultKey()
	if err != nil {
		panic(err.Error())
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	vc.Zero(key)
	return encoded
}

// jsWrapVaultKey(vaultKeyB64: string, encKeyB64: string) → string
func jsWrapVaultKey(_ js.Value, args []js.Value) any {
	vaultKey := decodeB64(args[0].String())
	encKey := decodeB64(args[1].String())

	wrapped, err := vc.WrapKey(encKey, vaultKey, nil)
	vc.Zero(vaultKey)
	vc.Zero(encKey)
	if err != nil {
		panic(err.Error())
	}
	return base64.StdEncoding.EncodeToString(wrapped)
}

// jsUnwrapVaultKey(wrappedB64: string, encKeyB64: string) → string
func jsUnwrapVaultKey(_ js.Value, args []js.Value) any {
	wrapped := decodeB64(args[0].String())
	encKey := decodeB64(args[1].String())

	vaultKey, err := vc.UnwrapKey(encKey, wrapped, nil)
	vc.Zero(encKey)
	if err != nil {
		panic(err.Error())
	}
	encoded := base64.StdEncoding.EncodeToString(vaultKey)
	vc.Zero(vaultKey)
	return encoded
}

// jsSealItem(itemJSON: string, vaultKeyB64: string) → string (base64 ciphertext)
func jsSealItem(_ js.Value, args []js.Value) any {
	var item vc.Item
	if err := json.Unmarshal([]byte(args[0].String()), &item); err != nil {
		panic("invalid item JSON: " + err.Error())
	}
	vaultKey := decodeB64(args[1].String())

	ciphertext, err := vc.EncryptItem(vaultKey, &item, nil)
	vc.Zero(vaultKey)
	if err != nil {
		panic(err.Error())
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// jsOpenItem(ciphertextB64: string, vaultKeyB64: string) → string (item JSON)
func jsOpenItem(_ js.Value, args []js.Value) any {
	ciphertext := decodeB64(args[0].String())
	vaultKey := decodeB64(args[1].String())

	item, err := vc.DecryptItem(vaultKey, ciphertext, nil)
	vc.Zero(vaultKey)
	if err != nil {
		panic(err.Error())
	}

	j, err := json.Marshal(item)
	if err != nil {
		panic(err.Error())
	}
	return string(j)
}

const (
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	digitChars  = "0123456789"
	symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

// jsGeneratePassword(length: number, uppercase: bool, lowercase: bool, digits: bool, symbols: bool) → string
func jsGeneratePassword(_ js.Value, args []js.Value) any {
	length := args[0].Int()
	if length <= 0 || length > 128 {
		panic("length must be between 1 and 128")
	}

	var charset []byte
	if args[1].Bool() {
		charset = append(charset, upperChars...)
	}
	if args[2].Bool() {
		charset = append(charset, lowerChars...)
	}
	if args[3].Bool() {
		charset = append(charset, digitChars...)
	}
	if args[4].Bool() {
		charset = append(charset, symbolChars...)
	}
	if len(charset) == 0 {
		panic("no character class selected")
	}

	// Reject bytes >= largest multiple of len(charset) to eliminate modulo bias.
	n := len(charset)
	maxByte := 256 - (256 % n)

	result := make([]byte, 0, length)
	buf := make([]byte, length*4)
	for len(result) < length {
		if _, err := rand.Read(buf); err != nil {
			panic(err.Error())
		}
		for _, b := range buf {
			if int(b) < maxByte {
				result = append(result, charset[int(b)%n])
				if len(result) == length {
					break
				}
			}
		}
	}
	return string(result)
}
