module arkade-delegation-measure

go 1.23.1

// Pinned to the ark-lib shipped with arkd v0.7.0
// (fcb9f21ef69836e8ddadc2d070deb0c5be139336), the commit the paper's
// Arkade comparison cites. The pseudo-version below is the same one
// arkd v0.7.0's own pkg/ark-cli/go.mod requires.
require (
	github.com/arkade-os/arkd/pkg/ark-lib v0.0.0-20250708155328-721172a83dba
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
)

require (
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
