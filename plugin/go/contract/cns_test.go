package contract

import (
	"bytes"
	"strings"
	"testing"

	"github.com/canopy-name-service/canopy-name-service/plugin/go/cns"
)

// fakeState is an in-memory stateBackend used to unit-test the CNS Deliver handlers without a node.
type fakeState struct {
	m map[string][]byte
}

func newFakeState() *fakeState { return &fakeState{m: map[string][]byte{}} }

func (f *fakeState) StateRead(_ *Contract, req *PluginStateReadRequest) (*PluginStateReadResponse, *PluginError) {
	resp := &PluginStateReadResponse{}
	for _, k := range req.Keys {
		var entries []*PluginStateEntry
		if v, ok := f.m[string(k.Key)]; ok {
			entries = []*PluginStateEntry{{Key: k.Key, Value: v}}
		}
		resp.Results = append(resp.Results, &PluginReadResult{QueryId: k.QueryId, Entries: entries})
	}
	for _, r := range req.Ranges {
		var entries []*PluginStateEntry
		for key, v := range f.m {
			if strings.HasPrefix(key, string(r.Prefix)) {
				entries = append(entries, &PluginStateEntry{Key: []byte(key), Value: v})
			}
		}
		resp.Results = append(resp.Results, &PluginReadResult{QueryId: r.QueryId, Entries: entries})
	}
	return resp, nil
}

func (f *fakeState) StateWrite(_ *Contract, req *PluginStateWriteRequest) (*PluginStateWriteResponse, *PluginError) {
	for _, s := range req.Sets {
		f.m[string(s.Key)] = s.Value
	}
	for _, d := range req.Deletes {
		delete(f.m, string(d.Key))
	}
	return &PluginStateWriteResponse{}, nil
}

// newTestContract returns a Contract wired to a fresh in-memory state.
func newTestContract() (*Contract, *fakeState) {
	f := newFakeState()
	return &Contract{Config: Config{ChainId: 1}, plugin: f}, f
}

// addr returns a 20-byte address filled with b.
func addr(b byte) []byte { return bytes.Repeat([]byte{b}, 20) }

// seedAccount pre-funds an account so fee charging can be exercised.
func seedAccount(f *fakeState, a []byte, amount uint64) {
	bz, _ := Marshal(&Account{Amount: amount})
	f.m[string(KeyForAccount(a))] = bz
}

func getRecord(t *testing.T, f *fakeState, key []byte) *cns.NameRecord {
	t.Helper()
	v, ok := f.m[string(key)]
	if !ok {
		return nil
	}
	r := new(cns.NameRecord)
	if err := Unmarshal(v, r); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return r
}

func getSet(t *testing.T, f *fakeState, key []byte) *cns.NameSet {
	t.Helper()
	v, ok := f.m[string(key)]
	if !ok {
		return nil
	}
	s := new(cns.NameSet)
	if err := Unmarshal(v, s); err != nil {
		t.Fatalf("decode set: %v", err)
	}
	return s
}

func mustRegister(t *testing.T, c *Contract, name string, owner, target []byte, fee uint64) {
	t.Helper()
	resp := c.DeliverMessageRegisterName(&cns.MessageRegisterName{Name: name, Owner: owner, Address: target}, fee)
	if resp.Error != nil {
		t.Fatalf("register %q failed: %v", name, resp.Error)
	}
}

func TestCNSRegisterHappyPath(t *testing.T) {
	c, f := newTestContract()
	owner, target := addr(1), addr(2)
	mustRegister(t, c, "alice.cnpy", owner, target, 0)

	rec := getRecord(t, f, cns.KeyForCNSName("alice.cnpy"))
	if rec == nil || rec.Name != "alice.cnpy" || !bytes.Equal(rec.Owner, owner) || !bytes.Equal(rec.Address, target) {
		t.Fatalf("primary record wrong: %+v", rec)
	}
	// reverse index present under the target address
	if getRecord(t, f, cns.KeyForCNSReverse(target, "alice.cnpy")) == nil {
		t.Fatal("reverse index entry missing")
	}
	// set commitment contains the name
	set := getSet(t, f, cns.KeyForCNSNameSet(target))
	if set == nil || len(set.Names) != 1 || set.Names[0] != "alice.cnpy" {
		t.Fatalf("name set wrong: %+v", set)
	}
}

func TestCNSDuplicateRegistration(t *testing.T) {
	c, _ := newTestContract()
	owner, target := addr(1), addr(2)
	mustRegister(t, c, "alice.cnpy", owner, target, 0)
	resp := c.DeliverMessageRegisterName(&cns.MessageRegisterName{Name: "alice.cnpy", Owner: owner, Address: target}, 0)
	if resp.Error == nil || resp.Error.Code != ErrNameExists().Code {
		t.Fatalf("expected ErrNameExists, got %v", resp.Error)
	}
}

func TestCNSUpdateHappyPath(t *testing.T) {
	c, f := newTestContract()
	owner, oldTarget, newTarget := addr(1), addr(2), addr(3)
	mustRegister(t, c, "alice.cnpy", owner, oldTarget, 0)

	resp := c.DeliverMessageUpdateName(&cns.MessageUpdateName{Name: "alice.cnpy", Owner: owner, NewAddress: newTarget}, 0)
	if resp.Error != nil {
		t.Fatalf("update failed: %v", resp.Error)
	}
	// primary now points at the new target
	rec := getRecord(t, f, cns.KeyForCNSName("alice.cnpy"))
	if !bytes.Equal(rec.Address, newTarget) {
		t.Fatalf("primary not updated: %x", rec.Address)
	}
	// reverse index moved: old gone, new present
	if getRecord(t, f, cns.KeyForCNSReverse(oldTarget, "alice.cnpy")) != nil {
		t.Fatal("old reverse index not removed")
	}
	if getRecord(t, f, cns.KeyForCNSReverse(newTarget, "alice.cnpy")) == nil {
		t.Fatal("new reverse index missing")
	}
	// set commitment moved: old deleted (now empty), new has the name
	if getSet(t, f, cns.KeyForCNSNameSet(oldTarget)) != nil {
		t.Fatal("old set not removed when emptied")
	}
	newSet := getSet(t, f, cns.KeyForCNSNameSet(newTarget))
	if newSet == nil || len(newSet.Names) != 1 || newSet.Names[0] != "alice.cnpy" {
		t.Fatalf("new set wrong: %+v", newSet)
	}
}

func TestCNSUpdateNonOwner(t *testing.T) {
	c, _ := newTestContract()
	owner, target := addr(1), addr(2)
	mustRegister(t, c, "alice.cnpy", owner, target, 0)
	resp := c.DeliverMessageUpdateName(&cns.MessageUpdateName{Name: "alice.cnpy", Owner: addr(9), NewAddress: addr(3)}, 0)
	if resp.Error == nil || resp.Error.Code != ErrNotNameOwner().Code {
		t.Fatalf("expected ErrNotNameOwner, got %v", resp.Error)
	}
}

func TestCNSUpdateMissing(t *testing.T) {
	c, _ := newTestContract()
	resp := c.DeliverMessageUpdateName(&cns.MessageUpdateName{Name: "ghost.cnpy", Owner: addr(1), NewAddress: addr(3)}, 0)
	if resp.Error == nil || resp.Error.Code != ErrNameNotFound().Code {
		t.Fatalf("expected ErrNameNotFound, got %v", resp.Error)
	}
}

func TestCNSDeleteHappyPath(t *testing.T) {
	c, f := newTestContract()
	owner, target := addr(1), addr(2)
	mustRegister(t, c, "alice.cnpy", owner, target, 0)
	resp := c.DeliverMessageDeleteName(&cns.MessageDeleteName{Name: "alice.cnpy", Owner: owner}, 0)
	if resp.Error != nil {
		t.Fatalf("delete failed: %v", resp.Error)
	}
	if getRecord(t, f, cns.KeyForCNSName("alice.cnpy")) != nil {
		t.Fatal("primary record not deleted")
	}
	if getRecord(t, f, cns.KeyForCNSReverse(target, "alice.cnpy")) != nil {
		t.Fatal("reverse index not deleted")
	}
	// the address had only this name -> set key removed entirely (no orphans)
	if getSet(t, f, cns.KeyForCNSNameSet(target)) != nil {
		t.Fatal("empty set not removed")
	}
}

func TestCNSDeleteNonOwner(t *testing.T) {
	c, _ := newTestContract()
	owner, target := addr(1), addr(2)
	mustRegister(t, c, "alice.cnpy", owner, target, 0)
	resp := c.DeliverMessageDeleteName(&cns.MessageDeleteName{Name: "alice.cnpy", Owner: addr(9)}, 0)
	if resp.Error == nil || resp.Error.Code != ErrNotNameOwner().Code {
		t.Fatalf("expected ErrNotNameOwner, got %v", resp.Error)
	}
}

func TestCNSDeleteMissing(t *testing.T) {
	c, _ := newTestContract()
	resp := c.DeliverMessageDeleteName(&cns.MessageDeleteName{Name: "ghost.cnpy", Owner: addr(1)}, 0)
	if resp.Error == nil || resp.Error.Code != ErrNameNotFound().Code {
		t.Fatalf("expected ErrNameNotFound, got %v", resp.Error)
	}
}

func TestCNSMultipleNamesPerAddress(t *testing.T) {
	c, f := newTestContract()
	owner, target := addr(1), addr(2)
	// register in non-sorted order to confirm the set is canonicalized
	mustRegister(t, c, "charlie.cnpy", owner, target, 0)
	mustRegister(t, c, "alice.cnpy", owner, target, 0)
	mustRegister(t, c, "bob.cnpy", owner, target, 0)

	set := getSet(t, f, cns.KeyForCNSNameSet(target))
	want := []string{"alice.cnpy", "bob.cnpy", "charlie.cnpy"}
	if set == nil || len(set.Names) != 3 {
		t.Fatalf("expected 3 names, got %+v", set)
	}
	for i := range want {
		if set.Names[i] != want[i] {
			t.Fatalf("set not sorted canonical: %+v", set.Names)
		}
	}
	// delete the middle one -> remaining two, set still present
	if resp := c.DeliverMessageDeleteName(&cns.MessageDeleteName{Name: "bob.cnpy", Owner: owner}, 0); resp.Error != nil {
		t.Fatalf("delete bob failed: %v", resp.Error)
	}
	set = getSet(t, f, cns.KeyForCNSNameSet(target))
	if set == nil || len(set.Names) != 2 || set.Names[0] != "alice.cnpy" || set.Names[1] != "charlie.cnpy" {
		t.Fatalf("set after delete wrong: %+v", set)
	}
	// reverse entry for bob is gone, others remain
	if getRecord(t, f, cns.KeyForCNSReverse(target, "bob.cnpy")) != nil {
		t.Fatal("bob reverse entry not removed")
	}
	if getRecord(t, f, cns.KeyForCNSReverse(target, "alice.cnpy")) == nil {
		t.Fatal("alice reverse entry missing")
	}
}

func TestCNSReverseIndexMoveOnUpdate(t *testing.T) {
	c, f := newTestContract()
	owner, oldT, newT := addr(1), addr(2), addr(3)
	// oldT also owns another name so its set should survive the move
	mustRegister(t, c, "keep.cnpy", owner, oldT, 0)
	mustRegister(t, c, "move.cnpy", owner, oldT, 0)

	if resp := c.DeliverMessageUpdateName(&cns.MessageUpdateName{Name: "move.cnpy", Owner: owner, NewAddress: newT}, 0); resp.Error != nil {
		t.Fatalf("update failed: %v", resp.Error)
	}
	// old address no longer lists 'move', still lists 'keep'
	oldSet := getSet(t, f, cns.KeyForCNSNameSet(oldT))
	if oldSet == nil || len(oldSet.Names) != 1 || oldSet.Names[0] != "keep.cnpy" {
		t.Fatalf("old set wrong after move: %+v", oldSet)
	}
	// new address lists 'move'
	newSet := getSet(t, f, cns.KeyForCNSNameSet(newT))
	if newSet == nil || len(newSet.Names) != 1 || newSet.Names[0] != "move.cnpy" {
		t.Fatalf("new set wrong after move: %+v", newSet)
	}
}

func TestCNSCaseNormalization(t *testing.T) {
	c, f := newTestContract()
	owner, target := addr(1), addr(2)
	// register with mixed case; it should normalize to lowercase
	mustRegister(t, c, "Alice.CNPY", owner, target, 0)
	// stored under the normalized key
	if getRecord(t, f, cns.KeyForCNSName("alice.cnpy")) == nil {
		t.Fatal("record not stored under normalized key")
	}
	// mixed-case re-registration collides with the existing normalized name
	resp := c.DeliverMessageRegisterName(&cns.MessageRegisterName{Name: "ALICE.cnpy", Owner: owner, Address: target}, 0)
	if resp.Error == nil || resp.Error.Code != ErrNameExists().Code {
		t.Fatalf("expected ErrNameExists on case-insensitive duplicate, got %v", resp.Error)
	}
}

func TestCNSInvalidNameFormats(t *testing.T) {
	bad := []string{
		"",                                // empty
		"foo",                             // no suffix
		"foo.com",                         // wrong suffix
		"ab.cnpy",                         // label too short (2)
		"-abc.cnpy",                       // leading hyphen
		"abc-.cnpy",                       // trailing hyphen
		"ab_c.cnpy",                       // illegal char
		"a b.cnpy",                        // space
		strings.Repeat("a", 64) + ".cnpy", // label too long (64)
		".cnpy",                           // empty label
	}
	for _, name := range bad {
		if cns.ValidateName(cns.NormalizeName(name)) {
			t.Fatalf("expected %q to be invalid", name)
		}
	}
	good := []string{"abc.cnpy", "a-b-c.cnpy", "pablocampogo.cnpy", "n0b.cnpy", strings.Repeat("a", 63) + ".cnpy"}
	for _, name := range good {
		if !cns.ValidateName(cns.NormalizeName(name)) {
			t.Fatalf("expected %q to be valid", name)
		}
	}
}

func TestCNSCheckRejectsInvalidInput(t *testing.T) {
	c, _ := newTestContract()
	// invalid name
	if resp := c.CheckMessageRegisterName(&cns.MessageRegisterName{Name: "bad", Owner: addr(1), Address: addr(2)}); resp.Error == nil {
		t.Fatal("expected invalid name rejection in Check")
	}
	// bad owner length
	if resp := c.CheckMessageRegisterName(&cns.MessageRegisterName{Name: "alice.cnpy", Owner: []byte{1, 2}, Address: addr(2)}); resp.Error == nil {
		t.Fatal("expected invalid address rejection in Check")
	}
	// valid: returns the owner as the authorized signer
	resp := c.CheckMessageRegisterName(&cns.MessageRegisterName{Name: "alice.cnpy", Owner: addr(1), Address: addr(2)})
	if resp.Error != nil || len(resp.AuthorizedSigners) != 1 || !bytes.Equal(resp.AuthorizedSigners[0], addr(1)) {
		t.Fatalf("unexpected check response: %+v", resp)
	}
}

func TestCNSQueryNotFoundAndEmpty(t *testing.T) {
	_, f := newTestContract()
	// no registration: primary key absent
	if _, ok := f.m[string(cns.KeyForCNSName("ghost.cnpy"))]; ok {
		t.Fatal("expected missing primary key")
	}
	// no names for an address: set key absent
	if getSet(t, f, cns.KeyForCNSNameSet(addr(7))) != nil {
		t.Fatal("expected empty set for unknown address")
	}
}

func TestFaucetMint(t *testing.T) {
	c, f := newTestContract()
	user := addr(5)
	// faucet 1_000_000 with a fee of 10_000: net account balance should be 990_000
	resp := c.DeliverMessageFaucet(&cns.MessageFaucet{Address: user, Amount: 1_000_000}, 10_000)
	if resp.Error != nil {
		t.Fatalf("faucet failed: %v", resp.Error)
	}
	acc := new(Account)
	_ = Unmarshal(f.m[string(KeyForAccount(user))], acc)
	if acc.Amount != 990_000 {
		t.Fatalf("expected account balance 990000 after faucet, got %d", acc.Amount)
	}
	pool := new(Pool)
	_ = Unmarshal(f.m[string(KeyForFeePool(1))], pool)
	if pool.Amount != 10_000 {
		t.Fatalf("expected fee pool 10000, got %d", pool.Amount)
	}
	// a second faucet accumulates on top of the existing balance
	if resp = c.DeliverMessageFaucet(&cns.MessageFaucet{Address: user, Amount: 500_000}, 10_000); resp.Error != nil {
		t.Fatalf("second faucet failed: %v", resp.Error)
	}
	_ = Unmarshal(f.m[string(KeyForAccount(user))], acc)
	if acc.Amount != 990_000+490_000 {
		t.Fatalf("expected accumulated balance, got %d", acc.Amount)
	}
	// Check rejects a faucet whose amount is zero or whose address is invalid
	if r := c.CheckMessageFaucet(&cns.MessageFaucet{Address: user, Amount: 0}); r.Error == nil {
		t.Fatal("expected zero-amount faucet to be rejected in Check")
	}
	if r := c.CheckMessageFaucet(&cns.MessageFaucet{Address: []byte{1, 2}, Amount: 1}); r.Error == nil {
		t.Fatal("expected bad-address faucet to be rejected in Check")
	}
	if r := c.CheckMessageFaucet(&cns.MessageFaucet{Address: user, Amount: 1}); r.Error != nil || len(r.AuthorizedSigners) != 1 {
		t.Fatalf("unexpected faucet check response: %+v", r)
	}
}

func TestCNSInsufficientFundsForFee(t *testing.T) {
	c, f := newTestContract()
	owner, target := addr(1), addr(2)
	// owner has only 5 but the fee is 10
	seedAccount(f, owner, 5)
	resp := c.DeliverMessageRegisterName(&cns.MessageRegisterName{Name: "alice.cnpy", Owner: owner, Address: target}, 10)
	if resp.Error == nil || resp.Error.Code != ErrInsufficientFunds().Code {
		t.Fatalf("expected ErrInsufficientFunds, got %v", resp.Error)
	}
	// with enough funds, the fee is deducted and credited to the pool
	seedAccount(f, owner, 100)
	if resp = c.DeliverMessageRegisterName(&cns.MessageRegisterName{Name: "alice.cnpy", Owner: owner, Address: target}, 10); resp.Error != nil {
		t.Fatalf("register with funds failed: %v", resp.Error)
	}
	acc := new(Account)
	_ = Unmarshal(f.m[string(KeyForAccount(owner))], acc)
	if acc.Amount != 90 {
		t.Fatalf("expected owner balance 90 after fee, got %d", acc.Amount)
	}
	pool := new(Pool)
	_ = Unmarshal(f.m[string(KeyForFeePool(1))], pool)
	if pool.Amount != 10 {
		t.Fatalf("expected fee pool 10, got %d", pool.Amount)
	}
}
