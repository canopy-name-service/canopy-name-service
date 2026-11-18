package cns

import "strings"

/*
Package cns holds the Canopy Name Service wire types (MessageRegisterName/…, NameRecord, NameSet) and
the canonical state-key layout + name rules. It is deliberately self-contained (no canopy or plugin
imports) so it can be imported both by the plugin (which generates CNS state) and by an external
verifier such as the name-solver (which recomputes keys and reconstructs values). The key layout here
MUST stay byte-for-byte identical to what the plugin writes, and to canopy's JoinLenPrefix helper, so
a client can recompute the exact key it expects a proof for.

DATA MODEL (three plugin-owned key prefixes, all outside the core-reserved range 1-15):

  - cnsNamePrefix    {120}  primary record:  name            -> NameRecord{name, owner, address}
  - cnsReversePrefix {121}  reverse index:   address + name  -> NameRecord  (enables prefix scans)
  - cnsSetPrefix     {122}  per-address set: address         -> NameSet{names}  (completeness commit)
*/

var (
	cnsNamePrefix    = []byte{120} // store key prefix for the primary name -> record mapping
	cnsReversePrefix = []byte{121} // store key prefix for the reverse address+name index
	cnsSetPrefix     = []byte{122} // store key prefix for the per-address name-set commitment
)

// cnsSuffix is the required suffix for all CNS names.
const cnsSuffix = ".cnpy"

// cnsMinLabel and cnsMaxLabel bound the label length (the part of the name before the suffix).
const (
	cnsMinLabel = 3
	cnsMaxLabel = 63
)

// NamePrefix / ReversePrefix / SetPrefix expose the raw prefixes so the plugin can declare them in
// ContractConfig.CustomStatePrefixes.
func NamePrefix() []byte    { return cnsNamePrefix }
func ReversePrefix() []byte { return cnsReversePrefix }
func SetPrefix() []byte     { return cnsSetPrefix }

// KeyForCNSName() returns the state key for the primary record of a (normalized) name.
func KeyForCNSName(name string) []byte {
	return JoinLenPrefix(cnsNamePrefix, []byte(name))
}

// KeyForCNSReverse() returns the state key for a single reverse-index entry (address + name).
func KeyForCNSReverse(addr []byte, name string) []byte {
	return JoinLenPrefix(cnsReversePrefix, addr, []byte(name))
}

// KeyForCNSReversePrefix() returns the key prefix used to scan all reverse-index entries for an address.
func KeyForCNSReversePrefix(addr []byte) []byte {
	return JoinLenPrefix(cnsReversePrefix, addr)
}

// KeyForCNSNameSet() returns the state key for the per-address name-set commitment record.
func KeyForCNSNameSet(addr []byte) []byte {
	return JoinLenPrefix(cnsSetPrefix, addr)
}

// NormalizeName() lowercases a name so lookups and storage are case-insensitive.
func NormalizeName(name string) string {
	return strings.ToLower(name)
}

// ValidateName() reports whether a normalized name obeys the CNS format rules:
//   - ends in the ".cnpy" suffix
//   - the label before the suffix is 3-63 chars of [a-z0-9-]
//   - the label does not start or end with '-'
//
// The input MUST already be normalized (lowercase); callers normalize first.
func ValidateName(normalized string) bool {
	// must carry the required suffix
	if !strings.HasSuffix(normalized, cnsSuffix) {
		return false
	}
	// isolate the label before the suffix
	label := normalized[:len(normalized)-len(cnsSuffix)]
	n := len(label)
	// enforce label length bounds
	if n < cnsMinLabel || n > cnsMaxLabel {
		return false
	}
	// label may not start or end with a hyphen
	if label[0] == '-' || label[n-1] == '-' {
		return false
	}
	// only [a-z0-9-] are allowed in the label
	for i := 0; i < n; i++ {
		c := label[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// JoinLenPrefix() appends items separated by a single length byte per segment. It is a self-contained
// copy of the plugin/core helper and MUST produce identical output so recomputed keys match.
func JoinLenPrefix(toAppend ...[]byte) []byte {
	totalLen := 0
	for _, item := range toAppend {
		if item != nil {
			totalLen += 1 + len(item)
		}
	}
	res := make([]byte, 0, totalLen)
	for _, item := range toAppend {
		if item == nil {
			continue
		}
		res = append(res, byte(len(item)))
		res = append(res, item...)
	}
	return res
}
