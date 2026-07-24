// Measurement harness for the Arkade Delegation assumptions (A1, A3).
//
// Two subcommands:
//
//	script     Build the delegated-renewal Tapscript (CLTV-gated 3-of-3
//	           CLTVMultisigClosure) and the standard 2-of-2 renewal
//	           script with the pinned ark-lib, and print exact script
//	           and witness byte counts (A1 + the delegate-path wire
//	           delta for A3).
//
//	intentsize Compute the exact RegisterIntentRequest protobuf wire
//	           size from a captured intent row (proof + message), and
//	           decompose the BIP-322 proof transaction's witnesses to
//	           locate the 64-byte authorisation signatures (A3).
//
// The ark-lib dependency is pinned to arkd v0.7.0 (fcb9f21e) via
// go.mod, so the scripts produced here are byte-identical to what that
// release produces.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "script":
		runScript()
	case "intentsize":
		runIntentSize(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: measure script | measure intentsize -proof-file P -message-file M")
	os.Exit(2)
}

// deterministicKey derives a stable secp256k1 key for reproducible
// script bytes; the byte counts are key-independent.
func deterministicKey(b byte) *btcec.PublicKey {
	var scalar [32]byte
	scalar[31] = b
	_, pub := btcec.PrivKeyFromBytes(scalar[:])
	return pub
}

// witnessSize returns the serialized witness byte count for a
// script-path spend: count varint + per-item (varint + bytes).
// Signatures are 64 B each (SIGHASH_DEFAULT), control block is
// 33 + 32*depth.
func witnessSize(numSigs, scriptLen, depth int) int {
	controlBlock := 33 + 32*depth
	size := 1 // item-count varint (all counts here fit one byte)
	for i := 0; i < numSigs; i++ {
		size += 1 + 64
	}
	size += 1 + scriptLen
	size += 1 + controlBlock
	return size
}

func runScript() {
	user := deterministicKey(1)
	delegate := deterministicKey(2)
	asp := deterministicKey(3)

	// Standard Arkade collaborative renewal path: 2-of-2 (user, ASP).
	baseline := &arkscript.MultisigClosure{
		PubKeys: []*btcec.PublicKey{user, asp},
		Type:    arkscript.MultisigTypeChecksig,
	}
	baseScript, err := baseline.Script()
	must(err)

	// Delegated renewal path per assumption A1: CLTV-gated 3-of-3 over
	// (user, delegate, ASP). The locktime value is representative; its
	// scriptnum encoding is 3 B for any height in [65536, 8388607].
	const cltvHeight = 800000
	delegated := &arkscript.CLTVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{
			PubKeys: []*btcec.PublicKey{user, delegate, asp},
			Type:    arkscript.MultisigTypeChecksig,
		},
		Locktime: arklib.AbsoluteLocktime(cltvHeight),
	}
	delScript, err := delegated.Script()
	must(err)

	baseLeaf := txscript.NewBaseTapLeaf(baseScript)
	delLeaf := txscript.NewBaseTapLeaf(delScript)

	fmt.Println("## A1: renewal Tapscript construction (ark-lib @ arkd v0.7.0)")
	fmt.Println()
	fmt.Printf("standard 2-of-2 MultisigClosure script (%d B): %s\n",
		len(baseScript), hex.EncodeToString(baseScript))
	fmt.Printf("  tapleaf hash: %s\n", baseLeaf.TapHash())
	fmt.Printf("delegated CLTVMultisigClosure script (%d B, CLTV height %d): %s\n",
		len(delScript), cltvHeight, hex.EncodeToString(delScript))
	fmt.Printf("  tapleaf hash: %s\n", delLeaf.TapHash())
	fmt.Println()

	fmt.Println("## A3: per-renewal witness weight, script-path spend")
	fmt.Println()
	fmt.Println("| path                  | sigs | script (B) | witness (B, depth=1) | witness (B, depth=2) |")
	fmt.Println("|-----------------------|------|------------|----------------------|----------------------|")
	fmt.Printf("| 2-of-2 (user, ASP)    | 2    | %10d | %20d | %20d |\n",
		len(baseScript), witnessSize(2, len(baseScript), 1), witnessSize(2, len(baseScript), 2))
	fmt.Printf("| CLTV 3-of-3 delegated | 3    | %10d | %20d | %20d |\n",
		len(delScript), witnessSize(3, len(delScript), 1), witnessSize(3, len(delScript), 2))
	d1 := witnessSize(3, len(delScript), 1) - witnessSize(2, len(baseScript), 1)
	fmt.Println()
	fmt.Printf("delegate-path overhead vs 2-of-2: %d B witness = %d WU = %.2f vB per renewed VTXO input\n",
		d1, d1, float64(d1)/4.0)
	fmt.Println("per-renewal authorisation signature (one BIP-340 sig): 64 B")
}

func runIntentSize(args []string) {
	fs := flag.NewFlagSet("intentsize", flag.ExitOnError)
	proofFile := fs.String("proof-file", "", "file holding the intent proof column (base64)")
	messageFile := fs.String("message-file", "", "file holding the intent message column (JSON)")
	must(fs.Parse(args))
	if *proofFile == "" || *messageFile == "" {
		usage()
	}

	proofRaw, err := os.ReadFile(*proofFile)
	must(err)
	messageRaw, err := os.ReadFile(*messageFile)
	must(err)
	proof := string(bytes.TrimSpace(proofRaw))
	message := string(bytes.TrimSpace(messageRaw))

	// Exact protobuf wire size of
	//   RegisterIntentRequest{ intent: Bip322Signature{ signature=1, message=2 } }
	// Every field is length-delimited: 1 tag byte + uvarint(len) + len.
	inner := fieldSize(len(proof)) + fieldSize(len(message))
	outer := 1 + uvarintLen(inner) + inner

	fmt.Println("## A3: RegisterIntent payload (captured from arkd's intent store)")
	fmt.Println()
	fmt.Printf("proof (base64 BIP-322 tx) : %d chars\n", len(proof))
	fmt.Printf("message (JSON)            : %d chars\n", len(message))
	fmt.Printf("RegisterIntentRequest wire size: %d B\n", outer)
	fmt.Println()

	// Decompose the proof: base64 -> consensus tx -> witness items.
	txBytes, err := base64.StdEncoding.DecodeString(proof)
	must(err)
	var tx wire.MsgTx
	must(tx.Deserialize(bytes.NewReader(txBytes)))
	fmt.Printf("decoded proof tx: %d B raw, %d input(s)\n", len(txBytes), len(tx.TxIn))
	sigCount := 0
	for i, in := range tx.TxIn {
		for j, item := range in.Witness {
			kind := "other"
			// 64 B = BIP-340 sig with SIGHASH_DEFAULT; 65 B = explicit
			// sighash byte appended.
			if len(item) == 64 || len(item) == 65 {
				kind = "BIP-340 signature"
				sigCount++
			}
			fmt.Printf("  input %d witness[%d]: %3d B  (%s)\n", i, j, len(item), kind)
		}
	}
	fmt.Printf("signatures in proof: %d (the per-renewal authorisation is one 64 B signature per signer)\n", sigCount)
}

func fieldSize(n int) int {
	return 1 + uvarintLen(n) + n
}

func uvarintLen(n int) int {
	l := 1
	for n >= 0x80 {
		n >>= 7
		l++
	}
	return l
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
