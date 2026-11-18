package contract

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/canopy-name-service/canopy-name-service/plugin/go/cns"
)

/*
This file exposes the CNS read-only query endpoints on the plugin's own HTTP server. Each response
carries a merkle proof so lookups are trustless: the client recomputes the key itself and verifies
the proof against a state root it authenticates independently.

PROOF TRANSPORT: proofs are fetched directly over the plugin<->FSM socket via the detached, read-only
query path (PluginQueryRequest with prove=true). The FSM generates the membership/non-membership proof
for the exact key against a committed snapshot and returns it alongside the snapshot's state root and
resolved height — all consistent at a single height. No separate HTTP call to the node is needed.

The plugin only GENERATES these proofs; verifying them ("solving the signatures") is the job of the
separate name-solver binary, which recomputes the key and reconstructs the value independently.
*/

// HexBytes marshals/unmarshals JSON as a lowercase hex string (matching canopy's lib.HexBytes),
// so the plugin can both parse the node's proof response and emit client-friendly responses.
type HexBytes []byte

// MarshalJSON() serializes the bytes as a lowercase hex string.
func (h HexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

// UnmarshalJSON() parses a lowercase hex string into bytes.
func (h *HexBytes) UnmarshalJSON(b []byte) error {
	s := new(string)
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	d, err := hex.DecodeString(*s)
	if err != nil {
		return err
	}
	*h = d
	return nil
}

// CNSProofNode is a single sparse-merkle-tree proof node (leaf or sibling), hex-encoded for the
// client-facing JSON response. (The socket wire type is the generated ProofNode; this is its JSON view.)
type CNSProofNode struct {
	Key     HexBytes `json:"key"`
	Value   HexBytes `json:"value"`
	Bitmask int32    `json:"bitmask"`
}

// keyProof holds the proof data for a single key, assembled from the FSM's detached query response.
type keyProof struct {
	Height uint64         // the committed height the snapshot resolved to
	Root   HexBytes       // the state commitment root at that height (what the proof commits to)
	Key    HexBytes       // the exact key that was proven
	Value  HexBytes       // the committed value (empty for a non-membership proof)
	Exists bool           // whether the key currently holds a value (membership vs. non-membership)
	Proof  []CNSProofNode // the merkle proof nodes
}

// ResolveResponse is the client-facing response for /v1/query/cns/resolve.
type ResolveResponse struct {
	// Height: the committed height the answer was read at
	Height uint64 `json:"height"`
	// Name: the normalized name that was resolved
	Name string `json:"name"`
	// Found: whether the name currently exists
	Found bool `json:"found"`
	// Address: the target address the name resolves to (only when Found)
	Address HexBytes `json:"address,omitempty"`
	// Key: the exact state key proven (the client MUST recompute and compare this, never trust it)
	Key HexBytes `json:"key"`
	// Value: the raw committed value (the marshaled NameRecord), empty for a non-membership proof
	Value HexBytes `json:"value"`
	// StateRoot: the state root the proof commits to at Height
	StateRoot HexBytes `json:"stateRoot"`
	// Proof: the merkle membership (Found) or non-membership (!Found) proof
	Proof []CNSProofNode `json:"proof"`
}

// NamesByAddressResponse is the client-facing response for /v1/query/cns/names-by-address.
type NamesByAddressResponse struct {
	// Height: the committed height the answer was read at
	Height uint64 `json:"height"`
	// Address: the queried address
	Address HexBytes `json:"address"`
	// Names: the complete set of names resolving to the address (authoritative, from the committed
	// NameSet). Completeness is provable via the single membership proof below.
	Names []string `json:"names"`
	// Key: the exact NameSet state key proven (client recomputes and compares)
	Key HexBytes `json:"key"`
	// Value: the raw committed NameSet value, empty when the address has no names
	Value HexBytes `json:"value"`
	// StateRoot: the state root the proof commits to at Height
	StateRoot HexBytes `json:"stateRoot"`
	// Proof: the membership proof for the NameSet commitment (or non-membership if empty)
	Proof []CNSProofNode `json:"proof"`
}

// RegisterCNSRoutes() registers the CNS read-only query endpoints on the given mux.
func (p *Plugin) RegisterCNSRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/query/cns/resolve", p.handleResolveName)
	mux.HandleFunc("/v1/query/cns/names-by-address", p.handleNamesByAddress)
}

// handleResolveName serves GET /v1/query/cns/resolve?name=<name>&height=<height>
// It returns the current target address (or a proven not-found) plus the proof data.
func (p *Plugin) handleResolveName(w http.ResponseWriter, r *http.Request) {
	name := cns.NormalizeName(r.URL.Query().Get("name"))
	height := parseHeight(r.URL.Query().Get("height"))
	// reject malformed input before any state access
	if !cns.ValidateName(name) {
		writeJSONError(w, http.StatusBadRequest, "invalid name")
		return
	}
	key := cns.KeyForCNSName(name)
	// fetch the value + membership/non-membership proof from the node for the exact key; the proof
	// route performs the read itself, so value/proof/root/height are all consistent at one height
	proof, err := p.fetchProof(height, key)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	resp := &ResolveResponse{
		Height:    proof.Height,
		Name:      name,
		Found:     proof.Exists,
		Key:       key,
		Value:     proof.Value,
		StateRoot: proof.Root,
		Proof:     proof.Proof,
	}
	// decode the target address from the committed record when present
	if proof.Exists {
		rec := new(cns.NameRecord)
		if uerr := Unmarshal(proof.Value, rec); uerr == nil {
			resp.Address = rec.Address
		}
	}
	writeJSON(w, resp)
}

// handleNamesByAddress serves GET /v1/query/cns/names-by-address?address=<hex>&height=<height>
// It returns the complete set of names resolving to the address plus a completeness proof.
func (p *Plugin) handleNamesByAddress(w http.ResponseWriter, r *http.Request) {
	addr, derr := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("address"), "0x"))
	height := parseHeight(r.URL.Query().Get("height"))
	// reject malformed input before any state access
	if derr != nil || len(addr) != 20 {
		writeJSONError(w, http.StatusBadRequest, "invalid address")
		return
	}
	setKey := cns.KeyForCNSNameSet(addr)
	// the per-address NameSet is a single committed value; its membership proof guarantees the whole
	// result set (a node cannot silently drop a name without breaking the proof)
	proof, err := p.fetchProof(height, setKey)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	resp := &NamesByAddressResponse{
		Height:    proof.Height,
		Address:   addr,
		Names:     []string{},
		Key:       setKey,
		Value:     proof.Value,
		StateRoot: proof.Root,
		Proof:     proof.Proof,
	}
	// the authoritative, proven list comes from the committed NameSet value
	if proof.Exists {
		set := new(cns.NameSet)
		if uerr := Unmarshal(proof.Value, set); uerr == nil && set.Names != nil {
			resp.Names = set.Names
		}
	}
	// (convenience cross-check) also scan the reverse index via the plugin's own detached query
	// path; this is unproven and only used to detect/log inconsistencies between the two stores
	if scanned, serr := p.queryReverseNames(proof.Height, addr); serr == nil {
		sort.Strings(scanned)
		if !equalStringSlices(scanned, resp.Names) {
			// surface via log only; the proven NameSet remains authoritative
			fmt.Printf("CNS: reverse-index scan %v differs from NameSet %v for %x\n", scanned, resp.Names, addr)
		}
	}
	writeJSON(w, resp)
}

// fetchProof asks the FSM for a membership/non-membership proof of a raw state key at a height
// (0 = latest) over the plugin<->FSM socket, using the detached, read-only query path with prove=true.
// The FSM returns the value, proof, state root, and resolved height all consistent at one snapshot.
func (p *Plugin) fetchProof(height uint64, key []byte) (*keyProof, error) {
	// send the detached, proven read for the single key
	response, perr := p.sendDetachedSync(&PluginToFSM_Query{Query: &PluginQueryRequest{
		Height: height,
		Read: &PluginStateReadRequest{
			Keys: []*PluginKeyRead{{QueryId: rand.Uint64(), Key: key, Prove: true}},
		},
	}})
	if perr != nil {
		return nil, fmt.Errorf("%s", perr.Msg)
	}
	// unwrap the detached query response
	wrapper, ok := response.(*FSMToPlugin_Query)
	if !ok {
		return nil, fmt.Errorf("unexpected FSM response type %T", response)
	}
	q := wrapper.Query
	if q == nil {
		return nil, fmt.Errorf("nil query response")
	}
	if q.Error != nil {
		return nil, fmt.Errorf("%s", q.Error.Msg)
	}
	// assemble the proof result; the snapshot's root + resolved height come from the outer response
	out := &keyProof{
		Height: q.Height,
		Root:   q.StateRoot,
		Key:    key,
	}
	// locate the single result for our key and copy out value/exists/proof
	if read := q.GetRead(); read != nil {
		for _, res := range read.Results {
			if len(res.Entries) != 0 {
				out.Value = res.Entries[0].Value
			}
			out.Exists = res.Exists
			for _, n := range res.Proof {
				out.Proof = append(out.Proof, CNSProofNode{Key: n.Key, Value: n.Value, Bitmask: n.Bitmask})
			}
			break
		}
	}
	return out, nil
}

// queryReverseNames scans the reverse index for an address via the detached query path and returns
// the names it finds (unproven; used only as a convenience cross-check).
func (p *Plugin) queryReverseNames(height uint64, addr []byte) ([]string, error) {
	resp, err := p.QueryState(height, &PluginStateReadRequest{
		Ranges: []*PluginRangeRead{{QueryId: rand.Uint64(), Prefix: cns.KeyForCNSReversePrefix(addr)}},
	})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, r := range resp.Results {
		for _, e := range r.Entries {
			rec := new(cns.NameRecord)
			if uerr := Unmarshal(e.Value, rec); uerr == nil && rec.Name != "" {
				names = append(names, rec.Name)
			}
		}
	}
	return names, nil
}

// parseHeight parses a decimal height string, returning 0 (latest) when empty or invalid.
func parseHeight(s string) uint64 {
	if s == "" {
		return 0
	}
	h, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return h
}

// equalStringSlices reports whether two string slices are equal in order and content.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeJSON writes an indented JSON response with a 200 status.
func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	bz, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(bz)
}

// writeJSONError writes a JSON error object with the given status code.
func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	bz, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(bz)
}
