package contract

import (
	"math"

	"github.com/canopy-name-service/canopy-name-service/plugin/go/cns"
)

/*
This file implements a DEV/TEST-ONLY faucet transaction that mints unbacked tokens to the signer's
own account. It exists so fresh keystore accounts can obtain balance to pay transaction fees when
testing the Canopy Name Service end-to-end (mirroring the plugin tutorial's faucet).

SECURITY: this is self-authorized (signer == credited address) and mints tokens out of thin air, so
it MUST NOT be enabled on a production chain. It is intended only for local/dev testing.
*/

// CheckMessageFaucet() statelessly validates a 'faucet' message.
func (c *Contract) CheckMessageFaucet(msg *cns.MessageFaucet) *PluginCheckResponse {
	// the credited account must be a valid 20-byte address
	if len(msg.Address) != 20 {
		return &PluginCheckResponse{Error: ErrInvalidAddress()}
	}
	// the minted amount must be positive
	if msg.Amount == 0 {
		return &PluginCheckResponse{Error: ErrInvalidAmount()}
	}
	// the account is both the recipient and the authorized signer (self-faucet)
	return &PluginCheckResponse{Recipient: msg.Address, AuthorizedSigners: [][]byte{msg.Address}}
}

// DeliverMessageFaucet() mints 'amount' to the signer's account, then pays the transaction fee from
// it (crediting the fee pool). The net credit to the account is amount - fee, so amount must cover
// the fee.
func (c *Contract) DeliverMessageFaucet(msg *cns.MessageFaucet, fee uint64) *PluginDeliverResponse {
	if len(msg.Address) != 20 {
		return &PluginDeliverResponse{Error: ErrInvalidAddress()}
	}
	if msg.Amount == 0 {
		return &PluginDeliverResponse{Error: ErrInvalidAmount()}
	}
	accountKey := KeyForAccount(msg.Address)
	feePoolKey := KeyForFeePool(c.Config.ChainId)
	// read the current account + fee pool
	vals, err := c.cnsRead(accountKey, feePoolKey)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	account, feePool := new(Account), new(Pool)
	if err = Unmarshal(vals[0], account); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if err = Unmarshal(vals[1], feePool); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	// mint the requested amount into the account (overflow-guarded)
	if account.Amount > math.MaxUint64-msg.Amount {
		return &PluginDeliverResponse{Error: ErrInvalidAmount()}
	}
	account.Amount += msg.Amount
	// the account must now be able to cover the transaction fee
	if account.Amount < fee {
		return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
	}
	if feePool.Amount > math.MaxUint64-fee {
		return &PluginDeliverResponse{Error: ErrInvalidAmount()}
	}
	account.Amount -= fee
	feePool.Amount += fee
	// persist the account (set the address field for completeness) and fee pool
	account.Address = msg.Address
	accountBz, err := Marshal(account)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	feePoolBz, err := Marshal(feePool)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	resp, err := c.plugin.StateWrite(c, &PluginStateWriteRequest{Sets: []*PluginSetOp{
		{Key: feePoolKey, Value: feePoolBz},
		{Key: accountKey, Value: accountBz},
	}})
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	return &PluginDeliverResponse{Error: resp.Error}
}
