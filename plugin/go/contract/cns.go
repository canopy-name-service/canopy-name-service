package contract

import (
	"bytes"
	"math"
	"math/rand"
	"sort"

	"github.com/canopy-name-service/canopy-name-service/cns"
)

/*
This file implements the Canopy Name Service (CNS) contract handlers: a mapping from human-readable
names (e.g. "pablocampogo.cnpy") to Canopy addresses, with trustless, Merkle-verifiable lookups.

The CNS wire types (messages + records) and the canonical key layout live in the standalone `cns`
package so an external verifier (the name-solver) can import them without pulling in the plugin. This
file only holds the stateful plugin logic (the Check and Deliver handlers) built on top of them.

Every write keeps all three CNS stores in sync atomically (a single StateWrite with sets+deletes).
Keys are deterministic/canonical (lowercase-normalized name, fixed 20-byte address) and the NameSet
value is kept sorted/de-duplicated so its serialization is reproducible by a client.
*/

// addName() inserts name into a sorted, de-duplicated slice, keeping it canonical.
func addName(names []string, name string) []string {
	idx := sort.SearchStrings(names, name)
	// already present: no change
	if idx < len(names) && names[idx] == name {
		return names
	}
	// insert at idx preserving sort order
	names = append(names, "")
	copy(names[idx+1:], names[idx:])
	names[idx] = name
	return names
}

// removeName() removes name from a sorted slice (no-op if absent).
func removeName(names []string, name string) []string {
	idx := sort.SearchStrings(names, name)
	if idx < len(names) && names[idx] == name {
		return append(names[:idx], names[idx+1:]...)
	}
	return names
}

// cnsRead() reads a batch of keys from state and returns their raw values in the same order
// (nil for an absent key).
func (c *Contract) cnsRead(keys ...[]byte) ([][]byte, *PluginError) {
	reads := make([]*PluginKeyRead, len(keys))
	ids := make([]uint64, len(keys))
	for i, k := range keys {
		ids[i] = rand.Uint64()
		reads[i] = &PluginKeyRead{QueryId: ids[i], Key: k}
	}
	resp, err := c.plugin.StateRead(c, &PluginStateReadRequest{Keys: reads})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	out := make([][]byte, len(keys))
	for _, r := range resp.Results {
		if len(r.Entries) == 0 {
			continue
		}
		for i, id := range ids {
			if r.QueryId == id {
				out[i] = r.Entries[0].Value
				break
			}
		}
	}
	return out, nil
}

// chargeFee() deducts the fee from the owner account and credits the fee pool. It returns the
// updated, marshaled owner account and fee pool bytes, or an error if the owner can't cover the fee.
func (c *Contract) chargeFee(ownerBytes, feePoolBytes []byte, fee uint64) (ownerBz, feePoolBz []byte, err *PluginError) {
	owner, feePool := new(Account), new(Pool)
	if err = Unmarshal(ownerBytes, owner); err != nil {
		return
	}
	if err = Unmarshal(feePoolBytes, feePool); err != nil {
		return
	}
	// owner must be able to cover the fee
	if owner.Amount < fee {
		return nil, nil, ErrInsufficientFunds()
	}
	// overflow guard for the fee pool
	if feePool.Amount > math.MaxUint64-fee {
		return nil, nil, ErrInvalidAmount()
	}
	owner.Amount -= fee
	feePool.Amount += fee
	if ownerBz, err = Marshal(owner); err != nil {
		return
	}
	if feePoolBz, err = Marshal(feePool); err != nil {
		return
	}
	return ownerBz, feePoolBz, nil
}

// CheckMessageRegisterName() statelessly validates a 'register name' message.
func (c *Contract) CheckMessageRegisterName(msg *cns.MessageRegisterName) *PluginCheckResponse {
	if !cns.ValidateName(cns.NormalizeName(msg.Name)) {
		return &PluginCheckResponse{Error: ErrInvalidName()}
	}
	if len(msg.Owner) != 20 || len(msg.Address) != 20 {
		return &PluginCheckResponse{Error: ErrInvalidAddress()}
	}
	// the owner is the signer; the target is the recipient
	return &PluginCheckResponse{Recipient: msg.Address, AuthorizedSigners: [][]byte{msg.Owner}}
}

// CheckMessageUpdateName() statelessly validates an 'update name' message.
func (c *Contract) CheckMessageUpdateName(msg *cns.MessageUpdateName) *PluginCheckResponse {
	if !cns.ValidateName(cns.NormalizeName(msg.Name)) {
		return &PluginCheckResponse{Error: ErrInvalidName()}
	}
	if len(msg.Owner) != 20 || len(msg.NewAddress) != 20 {
		return &PluginCheckResponse{Error: ErrInvalidAddress()}
	}
	return &PluginCheckResponse{Recipient: msg.NewAddress, AuthorizedSigners: [][]byte{msg.Owner}}
}

// CheckMessageDeleteName() statelessly validates a 'delete name' message.
func (c *Contract) CheckMessageDeleteName(msg *cns.MessageDeleteName) *PluginCheckResponse {
	if !cns.ValidateName(cns.NormalizeName(msg.Name)) {
		return &PluginCheckResponse{Error: ErrInvalidName()}
	}
	if len(msg.Owner) != 20 {
		return &PluginCheckResponse{Error: ErrInvalidAddress()}
	}
	return &PluginCheckResponse{AuthorizedSigners: [][]byte{msg.Owner}}
}

// DeliverMessageRegisterName() registers a new name, failing if it already exists. It writes the
// primary record, the reverse-index entry, and the updated per-address name set atomically.
func (c *Contract) DeliverMessageRegisterName(msg *cns.MessageRegisterName, fee uint64) *PluginDeliverResponse {
	name := cns.NormalizeName(msg.Name)
	// defensive re-validation (Check already ran statelessly)
	if !cns.ValidateName(name) {
		return &PluginDeliverResponse{Error: ErrInvalidName()}
	}
	if len(msg.Owner) != 20 || len(msg.Address) != 20 {
		return &PluginDeliverResponse{Error: ErrInvalidAddress()}
	}
	nameKey := cns.KeyForCNSName(name)
	setKey := cns.KeyForCNSNameSet(msg.Address)
	ownerKey := KeyForAccount(msg.Owner)
	feePoolKey := KeyForFeePool(c.Config.ChainId)
	// read current state
	vals, err := c.cnsRead(nameKey, setKey, ownerKey, feePoolKey)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	nameBytes, setBytes, ownerBytes, feePoolBytes := vals[0], vals[1], vals[2], vals[3]
	// the name must not already exist
	if len(nameBytes) != 0 {
		return &PluginDeliverResponse{Error: ErrNameExists()}
	}
	// charge the transaction fee to the owner
	ownerBz, feePoolBz, err := c.chargeFee(ownerBytes, feePoolBytes, fee)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	// build the primary record (also used as the reverse-index value)
	record := &cns.NameRecord{Name: name, Owner: msg.Owner, Address: msg.Address}
	recordBytes, err := Marshal(record)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	// add the name to the per-address set commitment
	set := new(cns.NameSet)
	if err = Unmarshal(setBytes, set); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	set.Names = addName(set.Names, name)
	setBz, err := Marshal(set)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	// write all records atomically
	resp, err := c.plugin.StateWrite(c, &PluginStateWriteRequest{Sets: []*PluginSetOp{
		{Key: feePoolKey, Value: feePoolBz},
		{Key: ownerKey, Value: ownerBz},
		{Key: nameKey, Value: recordBytes},
		{Key: cns.KeyForCNSReverse(msg.Address, name), Value: recordBytes},
		{Key: setKey, Value: setBz},
	}})
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	return &PluginDeliverResponse{Error: resp.Error}
}

// DeliverMessageUpdateName() moves a name to a new target address. Only the owner may call it, and
// the name must exist. The reverse-index entry and set commitment are moved from the old address to
// the new one atomically.
func (c *Contract) DeliverMessageUpdateName(msg *cns.MessageUpdateName, fee uint64) *PluginDeliverResponse {
	name := cns.NormalizeName(msg.Name)
	if !cns.ValidateName(name) {
		return &PluginDeliverResponse{Error: ErrInvalidName()}
	}
	if len(msg.Owner) != 20 || len(msg.NewAddress) != 20 {
		return &PluginDeliverResponse{Error: ErrInvalidAddress()}
	}
	nameKey := cns.KeyForCNSName(name)
	ownerKey := KeyForAccount(msg.Owner)
	feePoolKey := KeyForFeePool(c.Config.ChainId)
	// read the primary record + fee accounts
	vals, err := c.cnsRead(nameKey, ownerKey, feePoolKey)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	nameBytes, ownerBytes, feePoolBytes := vals[0], vals[1], vals[2]
	// the name must exist
	if len(nameBytes) == 0 {
		return &PluginDeliverResponse{Error: ErrNameNotFound()}
	}
	record := new(cns.NameRecord)
	if err = Unmarshal(nameBytes, record); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	// only the owner may update
	if !bytes.Equal(record.Owner, msg.Owner) {
		return &PluginDeliverResponse{Error: ErrNotNameOwner()}
	}
	// charge the transaction fee to the owner
	ownerBz, feePoolBz, err := c.chargeFee(ownerBytes, feePoolBytes, fee)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	oldAddr, newAddr := record.Address, msg.NewAddress
	// build the updated record
	newRecord := &cns.NameRecord{Name: name, Owner: record.Owner, Address: newAddr}
	newRecordBytes, err := Marshal(newRecord)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	// base writes: fee accounts + updated primary record
	sets := []*PluginSetOp{
		{Key: feePoolKey, Value: feePoolBz},
		{Key: ownerKey, Value: ownerBz},
		{Key: nameKey, Value: newRecordBytes},
	}
	var deletes []*PluginDeleteOp
	if bytes.Equal(oldAddr, newAddr) {
		// address unchanged: only the reverse-index value is refreshed; the set is untouched
		sets = append(sets, &PluginSetOp{Key: cns.KeyForCNSReverse(newAddr, name), Value: newRecordBytes})
	} else {
		// move the reverse-index entry old -> new
		deletes = append(deletes, &PluginDeleteOp{Key: cns.KeyForCNSReverse(oldAddr, name)})
		sets = append(sets, &PluginSetOp{Key: cns.KeyForCNSReverse(newAddr, name), Value: newRecordBytes})
		// move the name between the per-address set commitments
		oldSetKey, newSetKey := cns.KeyForCNSNameSet(oldAddr), cns.KeyForCNSNameSet(newAddr)
		setVals, e := c.cnsRead(oldSetKey, newSetKey)
		if e != nil {
			return &PluginDeliverResponse{Error: e}
		}
		oldSet, newSet := new(cns.NameSet), new(cns.NameSet)
		if err = Unmarshal(setVals[0], oldSet); err != nil {
			return &PluginDeliverResponse{Error: err}
		}
		if err = Unmarshal(setVals[1], newSet); err != nil {
			return &PluginDeliverResponse{Error: err}
		}
		oldSet.Names = removeName(oldSet.Names, name)
		newSet.Names = addName(newSet.Names, name)
		// remove the old set entirely if it is now empty (no orphan keys)
		if len(oldSet.Names) == 0 {
			deletes = append(deletes, &PluginDeleteOp{Key: oldSetKey})
		} else {
			oldSetBz, e2 := Marshal(oldSet)
			if e2 != nil {
				return &PluginDeliverResponse{Error: e2}
			}
			sets = append(sets, &PluginSetOp{Key: oldSetKey, Value: oldSetBz})
		}
		newSetBz, e2 := Marshal(newSet)
		if e2 != nil {
			return &PluginDeliverResponse{Error: e2}
		}
		sets = append(sets, &PluginSetOp{Key: newSetKey, Value: newSetBz})
	}
	resp, err := c.plugin.StateWrite(c, &PluginStateWriteRequest{Sets: sets, Deletes: deletes})
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	return &PluginDeliverResponse{Error: resp.Error}
}

// DeliverMessageDeleteName() removes a name. Only the owner may call it, and the name must exist.
// Both the primary record and the reverse-index entry are removed, and the name is dropped from the
// per-address set commitment (which is deleted entirely if it becomes empty).
func (c *Contract) DeliverMessageDeleteName(msg *cns.MessageDeleteName, fee uint64) *PluginDeliverResponse {
	name := cns.NormalizeName(msg.Name)
	if !cns.ValidateName(name) {
		return &PluginDeliverResponse{Error: ErrInvalidName()}
	}
	if len(msg.Owner) != 20 {
		return &PluginDeliverResponse{Error: ErrInvalidAddress()}
	}
	nameKey := cns.KeyForCNSName(name)
	ownerKey := KeyForAccount(msg.Owner)
	feePoolKey := KeyForFeePool(c.Config.ChainId)
	// read the primary record + fee accounts
	vals, err := c.cnsRead(nameKey, ownerKey, feePoolKey)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	nameBytes, ownerBytes, feePoolBytes := vals[0], vals[1], vals[2]
	// the name must exist
	if len(nameBytes) == 0 {
		return &PluginDeliverResponse{Error: ErrNameNotFound()}
	}
	record := new(cns.NameRecord)
	if err = Unmarshal(nameBytes, record); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	// only the owner may delete
	if !bytes.Equal(record.Owner, msg.Owner) {
		return &PluginDeliverResponse{Error: ErrNotNameOwner()}
	}
	// charge the transaction fee to the owner
	ownerBz, feePoolBz, err := c.chargeFee(ownerBytes, feePoolBytes, fee)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	addr := record.Address
	setKey := cns.KeyForCNSNameSet(addr)
	// read + update the per-address set commitment
	setVals, err := c.cnsRead(setKey)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	set := new(cns.NameSet)
	if err = Unmarshal(setVals[0], set); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	set.Names = removeName(set.Names, name)
	// base writes: fee accounts; base deletes: primary record + reverse-index entry
	sets := []*PluginSetOp{
		{Key: feePoolKey, Value: feePoolBz},
		{Key: ownerKey, Value: ownerBz},
	}
	deletes := []*PluginDeleteOp{
		{Key: nameKey},
		{Key: cns.KeyForCNSReverse(addr, name)},
	}
	// delete the set entirely if the address has no more names (no orphan keys)
	if len(set.Names) == 0 {
		deletes = append(deletes, &PluginDeleteOp{Key: setKey})
	} else {
		setBz, e := Marshal(set)
		if e != nil {
			return &PluginDeliverResponse{Error: e}
		}
		sets = append(sets, &PluginSetOp{Key: setKey, Value: setBz})
	}
	resp, err := c.plugin.StateWrite(c, &PluginStateWriteRequest{Sets: sets, Deletes: deletes})
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	return &PluginDeliverResponse{Error: resp.Error}
}
