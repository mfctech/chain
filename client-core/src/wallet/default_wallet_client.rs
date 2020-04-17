use bit_vec::BitVec;
use indexmap::IndexSet;
use parity_scale_codec::Encode;
use secp256k1::schnorrsig::SchnorrSignature;
use secstr::SecUtf8;
use zxcvbn::{feedback::Feedback, zxcvbn as estimate_password_strength};

use crate::hd_wallet::HardwareKind;
use crate::service::*;
use crate::transaction_builder::UnauthorizedWalletTransactionBuilder;
use crate::transaction_builder::{SignedTransferTransaction, UnsignedTransferTransaction};
use crate::types::{
    AddressType, BalanceChange, TransactionChange, TransactionPending, WalletBalance, WalletKind,
};
use crate::wallet::syncer_logic::create_transaction_change;
use crate::{
    InputSelectionStrategy, Mnemonic, MultiSigWalletClient, UnspentTransactions, WalletClient,
    WalletTransactionBuilder,
};
use chain_core::common::{Proof, H256};
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::{str2txid, TxoPointer};
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::fee::Fee;
use chain_core::tx::witness::tree::RawXOnlyPubkey;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use chain_core::tx::{TransactionId, TxAux, TxEnclaveAux, TxObfuscated};
use client_common::tendermint::types::Time;
use client_common::tendermint::types::{AbciQueryExt, BlockResults, BroadcastTxResponse};
use client_common::tendermint::{Client, UnauthorizedClient};
use client_common::{
    seckey::derive_enckey, Error, ErrorKind, PrivateKey, PrivateKeyAction, PublicKey, Result,
    ResultExt, SecKey, SignedTransaction, Storage, Transaction, TransactionInfo,
};
use std::time::Duration;

/// Default implementation of `WalletClient` based on `Storage` and `Index`
#[derive(Debug, Default, Clone)]
pub struct DefaultWalletClient<S, C, T>
where
    S: Storage,
    C: Client,
    T: WalletTransactionBuilder,
{
    key_service: KeyService<S>,
    hd_key_service: HdKeyService<S>,
    hw_key_service: HwKeyService,
    wallet_service: WalletService<S>,
    wallet_state_service: WalletStateService<S>,
    sync_state_service: SyncStateService<S>,
    root_hash_service: RootHashService<S>,
    multi_sig_session_service: MultiSigSessionService<S>,

    tendermint_client: C,
    transaction_builder: T,
    block_height_ensure: Option<u64>,
}

impl<S, C, T> DefaultWalletClient<S, C, T>
where
    S: Storage,
    C: Client,
    T: WalletTransactionBuilder,
{
    /// Creates a new instance of `DefaultWalletClient`
    pub fn new(
        storage: S,
        tendermint_client: C,
        transaction_builder: T,
        block_height_ensure: Option<u64>,
        hw_key_service: HwKeyService,
    ) -> Self {
        Self {
            key_service: KeyService::new(storage.clone()),
            hd_key_service: HdKeyService::new(storage.clone()),
            hw_key_service,
            wallet_service: WalletService::new(storage.clone()),
            wallet_state_service: WalletStateService::new(storage.clone()),
            sync_state_service: SyncStateService::new(storage.clone()),
            root_hash_service: RootHashService::new(storage.clone()),
            multi_sig_session_service: MultiSigSessionService::new(storage),
            tendermint_client,
            transaction_builder,
            block_height_ensure,
        }
    }
}

impl<S> DefaultWalletClient<S, UnauthorizedClient, UnauthorizedWalletTransactionBuilder>
where
    S: Storage,
{
    /// Creates a new read-only instance of `DefaultWalletClient`
    pub fn new_read_only(storage: S) -> Self {
        let hw_key_service = HwKeyService::default();
        Self::new(
            storage,
            UnauthorizedClient,
            UnauthorizedWalletTransactionBuilder,
            None,
            hw_key_service,
        )
    }
}

impl<S, C, T> WalletClient for DefaultWalletClient<S, C, T>
where
    S: Storage,
    C: Client,
    T: WalletTransactionBuilder,
{
    fn get_transaction(&self, name: &str, enckey: &SecKey, txid: TxId) -> Result<Transaction> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        let private_key = self
            .wallet_private_key(name, enckey, wallet.wallet_kind)?
            .chain(|| (ErrorKind::StorageError, "can not find private key"))?;
        let tx = self.transaction_builder.decrypt_tx(txid, &private_key)?;
        Ok(tx)
    }

    fn update_hw_service(&mut self, hw_wallet_kind: HardwareKind) {
        let hw_key_service = match hw_wallet_kind {
            HardwareKind::Ledger => HwKeyService::Unauthorized(UnauthorizedHwKeyService),
            HardwareKind::Trezor => HwKeyService::Unauthorized(UnauthorizedHwKeyService),
            #[cfg(feature = "mock-hardware-wallet")]
            HardwareKind::Mock => {
                let mock = MockHardwareService::new();
                HwKeyService::Mock(mock)
            }
        };
        self.hw_key_service = hw_key_service;
    }

    fn get_wallet_kind(&self, name: &str, enckey: &SecKey) -> Result<WalletKind> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        Ok(wallet.wallet_kind)
    }

    fn send_to_address(
        &self,
        name: &str,
        enckey: &SecKey,
        amount: Coin,
        address: ExtendedAddr,
        view_keys: Vec<PublicKey>,
        network_id: u8,
    ) -> Result<TxId> {
        let current_block_height = self.get_current_block_height()?;
        let tx_out = TxOut::new(address, amount);

        let view_key = self.view_key(name, enckey)?;

        let mut access_policies = vec![TxAccessPolicy {
            view_key: view_key.into(),
            access: TxAccess::AllData,
        }];

        for key in view_keys.iter() {
            access_policies.push(TxAccessPolicy {
                view_key: key.into(),
                access: TxAccess::AllData,
            });
        }

        let attributes = TxAttributes::new_with_access(network_id, access_policies);

        let return_address = self.new_transfer_address(name, enckey)?;
        let (transaction, selected_inputs, return_amount) =
            self.create_transaction(name, enckey, vec![tx_out], attributes, None, return_address)?;

        self.broadcast_transaction(&transaction)?;
        //update the wallet state
        let tx_pending = TransactionPending {
            used_inputs: selected_inputs,
            block_height: current_block_height,
            return_amount,
        };

        self.update_tx_pending_state(name, enckey, transaction.tx_id(), tx_pending)?;

        if let TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
            payload: TxObfuscated { txid, .. },
            ..
        }) = transaction
        {
            Ok(txid)
        } else {
            Err(Error::new(
                ErrorKind::IllegalInput,
                "Transaction is not transfer transaction",
            ))
        }
    }

    /// broadcast transaction and waiting it confiremed
    fn send_to_address_commit(
        &self,
        name: &str,
        enckey: &SecKey,
        amount: Coin,
        address: ExtendedAddr,
        view_keys: Vec<PublicKey>,
        network_id: u8,
    ) -> Result<TxId> {
        let tx_id = self.send_to_address(name, enckey, amount, address, view_keys, network_id)?;
        let block_height = self.get_current_block_height()?;
        loop {
            // query tx_id from tendermint
            let confirmed = self
                .tendermint_client
                .query("meta", &tx_id.to_vec())
                .is_ok();
            if !confirmed {
                std::thread::sleep(Duration::from_secs(1));
                let current_block_height = self.get_current_block_height()?;
                if current_block_height - block_height >= self.block_height_ensure.unwrap_or(50) {
                    return Err(Error::new(
                        ErrorKind::TendermintRpcError,
                        "waiting for transaction confirmed timeout",
                    ));
                }
                continue;
            }
            break;
        }
        Ok(tx_id)
    }

    #[inline]
    fn wallets(&self) -> Result<Vec<String>> {
        self.wallet_service.names()
    }

    fn export_wallet(&self, name: &str, enckey: &SecKey) -> Result<WalletInfo> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        let private_key = self
            .key_service
            .wallet_private_key(name, enckey)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    "Can not find private key in wallet",
                )
            })?;
        let wallet_info = WalletInfo {
            name: name.into(),
            wallet,
            private_key,
            passphrase: None,
        };
        Ok(wallet_info)
    }

    fn import_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        wallet_info: WalletInfo,
    ) -> Result<SecKey> {
        check_passphrase_strength(name, passphrase)?;
        let enckey = derive_enckey(passphrase, name).err_kind(ErrorKind::InvalidInput, || {
            "unable to derive encryption key from passphrase"
        })?;
        let view_key = PublicKey::from(&wallet_info.private_key);
        if view_key != wallet_info.wallet.view_key {
            return Err(Error::new(ErrorKind::InvalidInput, "public key not match"));
        }
        self.key_service.add_wallet_private_key(
            &wallet_info.name,
            &wallet_info.private_key,
            &enckey,
        )?;

        self.wallet_service
            .set_wallet(name, &enckey, wallet_info.wallet)?;
        Ok(enckey)
    }

    fn new_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        wallet_kind: WalletKind,
    ) -> Result<(SecKey, Option<Mnemonic>)> {
        check_passphrase_strength(name, passphrase)?;

        let enckey = derive_enckey(passphrase, name).err_kind(ErrorKind::InvalidInput, || {
            "unable to derive encryption key from passphrase"
        })?;

        match wallet_kind {
            WalletKind::Basic => {
                let private_key = PrivateKey::new()?;
                let view_key = PublicKey::from(&private_key);

                self.key_service
                    .add_wallet_private_key(name, &private_key, &enckey)?;

                self.wallet_service
                    .create(name, &enckey, view_key, wallet_kind)?;

                Ok((enckey, None))
            }
            WalletKind::HD => {
                let mnemonic = Mnemonic::new();

                self.hd_key_service.add_mnemonic(name, &mnemonic, &enckey)?;

                let (public_key, private_key) =
                    self.hd_key_service
                        .generate_keypair(name, &enckey, HDAccountType::Viewkey)?;

                self.key_service
                    .add_wallet_private_key(name, &private_key, &enckey)?;

                self.wallet_service
                    .create(name, &enckey, public_key, wallet_kind)?;

                Ok((enckey, Some(mnemonic)))
            }
            WalletKind::HW => {
                // the view-key pair is the local key pair, not come from the hardware wallet.
                let private_key = PrivateKey::new()?;
                let view_key = PublicKey::from(&private_key);

                self.key_service
                    .add_wallet_private_key(name, &private_key, &enckey)?;

                self.wallet_service
                    .create(name, &enckey, view_key, wallet_kind)?;

                Ok((enckey, None))
            }
        }
    }

    fn restore_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        mnemonic: &Mnemonic,
    ) -> Result<SecKey> {
        check_passphrase_strength(name, passphrase)?;

        let enckey = derive_enckey(passphrase, name).err_kind(ErrorKind::InvalidInput, || {
            "unable to derive encryption key from passphrase"
        })?;

        self.hd_key_service.add_mnemonic(name, mnemonic, &enckey)?;

        let (public_key, private_key) =
            self.hd_key_service
                .generate_keypair(name, &enckey, HDAccountType::Viewkey)?;

        self.key_service
            .add_wallet_private_key(name, &private_key, &enckey)?;

        self.wallet_service
            .create(name, &enckey, public_key, WalletKind::HD)?;
        Ok(enckey)
    }

    fn restore_basic_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        view_key_priv: &PrivateKey,
    ) -> Result<SecKey> {
        check_passphrase_strength(name, passphrase)?;

        let enckey = derive_enckey(passphrase, name).err_kind(ErrorKind::InvalidInput, || {
            "unable to derive encryption key from passphrase"
        })?;

        let view_key = PublicKey::from(view_key_priv);
        self.key_service
            .add_wallet_private_key(name, &view_key_priv, &enckey)?;
        self.wallet_service
            .create(name, &enckey, view_key, WalletKind::Basic)?;
        Ok(enckey)
    }

    fn delete_wallet(&self, name: &str, passphrase: &SecUtf8) -> Result<()> {
        // remove from wallet/sync_state/wallet_state/key_service

        let enckey = derive_enckey(passphrase, name).err_kind(ErrorKind::InvalidInput, || {
            "unable to derive encryption key from passphrase"
        })?;

        // the passphrase is verified here.
        self.wallet_service.delete(name, &enckey)?;
        self.sync_state_service.delete_global_state(name)?;
        self.wallet_state_service
            .delete_wallet_state(name, &enckey)?;
        if self.hd_key_service.has_wallet(name)? {
            self.hd_key_service.delete_wallet(name, &enckey)?;
        }
        self.key_service.delete_wallet_private_key(name, &enckey)?;

        Ok(())
    }

    fn auth_token(&self, name: &str, passphrase: &SecUtf8) -> Result<SecKey> {
        let enckey = derive_enckey(passphrase, name).err_kind(ErrorKind::InvalidInput, || {
            "unable to derive encryption key from passphrase"
        })?;

        // test validity of enckey
        self.view_key(name, &enckey)?;
        Ok(enckey)
    }

    #[inline]
    fn view_key(&self, name: &str, enckey: &SecKey) -> Result<PublicKey> {
        self.wallet_service.view_key(name, enckey)
    }

    #[inline]
    fn view_key_private(&self, name: &str, enckey: &SecKey) -> Result<PrivateKey> {
        self.key_service
            .wallet_private_key(name, enckey)?
            .err_kind(ErrorKind::InvalidInput, || "private view key not found")
    }

    #[inline]
    fn public_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>> {
        self.wallet_service.public_keys(name, enckey)
    }

    #[inline]
    fn staking_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>> {
        self.wallet_service.staking_keys(name, enckey)
    }

    #[inline]
    fn root_hashes(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<H256>> {
        self.wallet_service.root_hashes(name, enckey)
    }

    #[inline]
    fn staking_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
    ) -> Result<IndexSet<StakedStateAddress>> {
        self.wallet_service.staking_addresses(name, enckey)
    }

    #[inline]
    fn transfer_addresses(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<ExtendedAddr>> {
        self.wallet_service.transfer_addresses(name, enckey)
    }

    #[inline]
    fn find_staking_key(
        &self,
        name: &str,
        enckey: &SecKey,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>> {
        self.wallet_service
            .find_staking_key(name, enckey, redeem_address)
    }

    #[inline]
    fn find_root_hash(
        &self,
        name: &str,
        enckey: &SecKey,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>> {
        self.wallet_service.find_root_hash(name, enckey, address)
    }

    #[inline]
    fn wallet_private_key(
        &self,
        name: &str,
        enckey: &SecKey,
        wallet_kind: WalletKind,
    ) -> Result<Option<PrivateKey>> {
        if wallet_kind != WalletKind::HW {
            let k = self.key_service.wallet_private_key(name, enckey)?;
            Ok(k)
        } else {
            unreachable!("can not get private key from HW key")
        }
    }

    fn sign_key(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<Box<dyn PrivateKeyAction>> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        match wallet.wallet_kind {
            WalletKind::HW => self.hw_key_service.get_sign_key(public_key),
            _ => {
                let private_key = self
                    .wallet_service
                    .find_private_key(name, enckey, public_key)?
                    .chain(|| {
                        (
                            ErrorKind::InvalidInput,
                            "Not able to find private key for given public_key in current wallet",
                        )
                    })?;
                Ok(Box::new(private_key))
            }
        }
    }

    #[inline]
    fn private_key(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<Option<PrivateKey>> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        match wallet.wallet_kind {
            WalletKind::HW => unreachable!("can not get private key in hw wallet"),
            _ => self
                .wallet_service
                .find_private_key(name, enckey, public_key),
        }
    }

    fn new_public_key(
        &self,
        name: &str,
        enckey: &SecKey,
        address_type: Option<AddressType>,
    ) -> Result<PublicKey> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        match wallet.wallet_kind {
            WalletKind::Basic => {
                let private_key = PrivateKey::new()?;
                let public_key = PublicKey::from(&private_key);
                self.wallet_service
                    .add_public_key(name, enckey, &public_key)?;
                self.wallet_service
                    .add_key_pairs(name, enckey, &public_key, &private_key)?;
                Ok(public_key)
            }
            WalletKind::HD => {
                let (public_key, private_key) = self.hd_key_service.generate_keypair(
                    name,
                    enckey,
                    address_type
                        .chain(|| {
                            (
                                ErrorKind::InvalidInput,
                                "Address type is needed when creating address for HD wallet",
                            )
                        })?
                        .into(),
                )?;
                self.wallet_service
                    .add_public_key(name, enckey, &public_key)?;
                self.wallet_service
                    .add_key_pairs(name, enckey, &public_key, &private_key)?;
                Ok(public_key)
            }
            WalletKind::HW => {
                let public_key = self.hw_key_service.new_staking_address()?;
                self.wallet_service
                    .add_public_key(name, enckey, &public_key)?;
                Ok(public_key)
            }
        }
    }

    fn new_staking_address(&self, name: &str, enckey: &SecKey) -> Result<StakedStateAddress> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        let public_key = match wallet.wallet_kind {
            WalletKind::Basic => {
                let private_key = PrivateKey::new()?;
                let public_key = PublicKey::from(&private_key);
                self.wallet_service
                    .add_key_pairs(name, enckey, &public_key, &private_key)?;
                public_key
            }
            WalletKind::HD => {
                let (public_key, private_key) =
                    self.hd_key_service
                        .generate_keypair(name, enckey, HDAccountType::Staking)?;
                self.wallet_service
                    .add_key_pairs(name, enckey, &public_key, &private_key)?;
                public_key
            }
            WalletKind::HW => self.hw_key_service.new_staking_address()?,
        };

        self.wallet_service
            .add_staking_key(name, enckey, &public_key)?;

        Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from(
            &public_key,
        )))
    }

    fn new_transfer_address(&self, name: &str, enckey: &SecKey) -> Result<ExtendedAddr> {
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        let public_key = match wallet.wallet_kind {
            WalletKind::Basic => {
                let private_key = PrivateKey::new()?;
                let public_key = PublicKey::from(&private_key);
                self.wallet_service
                    .add_key_pairs(name, enckey, &public_key, &private_key)?;
                public_key
            }
            WalletKind::HD => {
                let (public_key, private_key) =
                    self.hd_key_service
                        .generate_keypair(name, enckey, HDAccountType::Transfer)?;
                self.wallet_service
                    .add_key_pairs(name, enckey, &public_key, &private_key)?;
                public_key
            }
            WalletKind::HW => self.hw_key_service.new_transfer_address()?,
        };
        self.wallet_service
            .add_public_key(name, enckey, &public_key)?;

        self.new_multisig_transfer_address(name, enckey, vec![public_key.clone()], public_key, 1)
    }

    fn new_watch_staking_address(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<StakedStateAddress> {
        self.wallet_service
            .add_staking_key(name, enckey, public_key)?;

        Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from(
            public_key,
        )))
    }

    fn new_watch_transfer_address(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<ExtendedAddr> {
        self.new_multisig_transfer_address(
            name,
            enckey,
            vec![public_key.clone()],
            public_key.clone(),
            1,
        )
    }

    fn new_multisig_transfer_address(
        &self,
        name: &str,
        enckey: &SecKey,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        m: usize,
    ) -> Result<ExtendedAddr> {
        if !public_keys.contains(&self_public_key) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Signer public keys does not contain self public key",
            ));
        }

        let (root_hash, multi_sig_address) =
            self.root_hash_service
                .new_root_hash(name, public_keys, self_public_key, m, enckey)?;

        self.wallet_service.add_root_hash(name, enckey, root_hash)?;

        Ok(multi_sig_address.into())
    }

    fn generate_proof(
        &self,
        name: &str,
        enckey: &SecKey,
        address: &ExtendedAddr,
        public_keys: Vec<PublicKey>,
    ) -> Result<Proof<RawXOnlyPubkey>> {
        // To verify if the enckey is correct or not
        self.wallet_service.view_key(name, enckey)?;

        match address {
            ExtendedAddr::OrTree(ref address) => {
                self.root_hash_service
                    .generate_proof(name, address, public_keys, enckey)
            }
        }
    }

    fn required_cosigners(&self, name: &str, enckey: &SecKey, root_hash: &H256) -> Result<usize> {
        // To verify if the enckey is correct or not
        self.wallet_service.view_key(name, enckey)?;

        self.root_hash_service
            .required_signers(name, root_hash, enckey)
    }

    #[inline]
    fn balance(&self, name: &str, enckey: &SecKey) -> Result<WalletBalance> {
        // Check if wallet exists
        self.wallet_service.view_key(name, enckey)?;
        self.wallet_state_service.get_balance(name, enckey)
    }

    fn history(
        &self,
        name: &str,
        enckey: &SecKey,
        offset: usize,
        limit: usize,
        reversed: bool,
    ) -> Result<Vec<TransactionChange>> {
        // Check if wallet exists
        self.wallet_service.view_key(name, enckey)?;

        let history = self
            .wallet_state_service
            .get_transaction_history(name, enckey, reversed)?
            .filter(|change| BalanceChange::NoChange != change.balance_change)
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();

        Ok(history)
    }

    #[inline]
    fn get_transaction_change(
        &self,
        name: &str,
        enckey: &SecKey,
        transaction_id: &TxId,
    ) -> Result<Option<TransactionChange>> {
        self.wallet_state_service
            .get_transaction_change(name, enckey, transaction_id)
    }

    fn unspent_transactions(&self, name: &str, enckey: &SecKey) -> Result<UnspentTransactions> {
        // Check if wallet exists
        self.wallet_service.view_key(name, enckey)?;

        let unspent_transactions = self
            .wallet_state_service
            .get_unspent_transactions(name, enckey, false)?;

        Ok(UnspentTransactions::new(
            unspent_transactions.into_iter().collect(),
        ))
    }

    fn has_unspent_transactions(
        &self,
        name: &str,
        enckey: &SecKey,
        inputs: &[TxoPointer],
    ) -> Result<bool> {
        // Check if wallet exists
        self.wallet_service.view_key(name, enckey)?;

        self.wallet_state_service
            .has_unspent_transactions(name, enckey, inputs)
    }

    #[inline]
    fn are_inputs_unspent(
        &self,
        name: &str,
        enckey: &SecKey,
        inputs: Vec<TxoPointer>,
    ) -> Result<Vec<(TxoPointer, bool)>> {
        self.wallet_state_service
            .are_inputs_unspent(name, enckey, inputs)
    }

    #[inline]
    fn output(&self, name: &str, enckey: &SecKey, input: &TxoPointer) -> Result<TxOut> {
        // Check if wallet exists
        self.wallet_service.view_key(name, enckey)?;

        self.wallet_state_service
            .get_output(name, enckey, input)
            .and_then(|optional| {
                optional.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Output details not found for given transaction input",
                    )
                })
            })
    }

    fn create_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        input_selection_strategy: Option<InputSelectionStrategy>,
        return_address: ExtendedAddr,
    ) -> Result<(TxAux, Vec<TxoPointer>, Coin)> {
        let mut unspent_transactions = self.unspent_transactions(name, enckey)?;
        unspent_transactions.apply_all(input_selection_strategy.unwrap_or_default().as_ref());

        self.transaction_builder.build_transfer_tx(
            name,
            enckey,
            unspent_transactions,
            outputs,
            return_address,
            attributes,
        )
    }

    #[inline]
    fn broadcast_transaction(&self, tx_aux: &TxAux) -> Result<BroadcastTxResponse> {
        self.tendermint_client
            .broadcast_transaction(&tx_aux.encode())
    }

    fn export_plain_tx(&self, name: &str, enckey: &SecKey, txid: &str) -> Result<TransactionInfo> {
        let txid = str2txid(txid).chain(|| (ErrorKind::InvalidInput, "invalid transaction id"))?;
        let tx = self.get_transaction(name, enckey, txid)?;
        // get the block height
        let tx_change = self
            .wallet_state_service
            .get_transaction_history(name, enckey, false)?
            .filter(|change| BalanceChange::NoChange != change.balance_change)
            .find(|tx_change| tx_change.transaction_id == tx.id())
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    "no transaction find by transaction id",
                )
            })?;

        let tx_info = TransactionInfo {
            tx,
            block_height: tx_change.block_height,
        };
        Ok(tx_info)
    }

    /// import a plain base64 encoded plain transaction
    fn import_plain_tx(&self, name: &str, enckey: &SecKey, tx_str: &str) -> Result<Coin> {
        let tx_info = TransactionInfo::decode(tx_str)?;
        // check if the output is spent or not
        let v = self
            .tendermint_client
            .query("meta", &tx_info.tx.id().to_vec())?
            .bytes();
        let bit_flag = BitVec::from_bytes(&v);
        let spent_flags: Result<Vec<bool>> = tx_info
            .tx
            .outputs()
            .iter()
            .enumerate()
            .map(|(index, _output)| {
                bit_flag
                    .get(index)
                    .chain(|| (ErrorKind::InvalidInput, "check failed in enclave"))
            })
            .collect();
        let mut memento = WalletStateMemento::default();
        // check if tx belongs to the block
        let block = self.tendermint_client.block(tx_info.block_height)?;
        let block_result = self.tendermint_client.block_results(tx_info.block_height)?;
        let fees = block_result.fees()?;
        let paid_fee = fees.get(&tx_info.tx.id());
        if paid_fee.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "block height and transaction not match",
            ));
        }
        let wallet = self.wallet_service.get_wallet(name, enckey)?;

        let wallet_state = self.wallet_service.get_wallet_state(name, enckey)?;

        let imported_value = import_transaction(
            &wallet,
            &wallet_state,
            &mut memento,
            &tx_info,
            *paid_fee.expect("tx fee checked above"),
            block.header.time,
            spent_flags?,
        )
        .chain(|| (ErrorKind::InvalidInput, "import error"))?;

        self.wallet_state_service
            .apply_memento(name, enckey, &memento)?;
        Ok(imported_value)
    }

    fn get_current_block_height(&self) -> Result<u64> {
        let status = self.tendermint_client.status()?;
        let current_block_height = status.sync_info.latest_block_height.value();
        Ok(current_block_height)
    }

    fn update_tx_pending_state(
        &self,
        name: &str,
        enckey: &SecKey,
        tx_id: TxId,
        tx_pending: TransactionPending,
    ) -> Result<()> {
        let mut wallet_state_memento = WalletStateMemento::default();
        wallet_state_memento.add_pending_transaction(tx_id, tx_pending);
        self.wallet_state_service
            .apply_memento(name, enckey, &wallet_state_memento)
    }

    fn build_raw_transfer_tx(
        &self,
        name: &str,
        enckey: &SecKey,
        to_address: ExtendedAddr,
        amount: Coin,
        view_keys: Vec<PublicKey>,
        network_id: u8,
    ) -> Result<UnsignedTransferTransaction> {
        let unspent_transactions = self.unspent_transactions(name, enckey)?;
        let return_address = self.new_transfer_address(name, enckey)?;
        let unsigned = UnsignedTransferTransaction {
            unspent_transactions,
            view_keys,
            network_id,
            to_address,
            return_address,
            amount,
        };
        Ok(unsigned)
    }

    fn sign_raw_transfer_tx(
        &self,
        name: &str,
        enckey: &SecKey,
        unsigned_tx: UnsignedTransferTransaction,
    ) -> Result<SignedTransferTransaction> {
        let tx_out = TxOut::new(unsigned_tx.to_address, unsigned_tx.amount);

        let view_key = self.view_key(name, enckey)?;

        let mut access_policies = unsigned_tx
            .view_keys
            .iter()
            .map(|key| TxAccessPolicy {
                view_key: key.into(),
                access: TxAccess::AllData,
            })
            .collect::<Vec<_>>();

        access_policies.push(TxAccessPolicy {
            view_key: view_key.into(),
            access: TxAccess::AllData,
        });

        let attributes = TxAttributes::new_with_access(unsigned_tx.network_id, access_policies);

        let return_address = unsigned_tx.return_address.clone();

        let (transaction, selected_inputs, return_amount) =
            self.transaction_builder.build_transfer_tx(
                name,
                enckey,
                unsigned_tx.unspent_transactions,
                vec![tx_out],
                return_address,
                attributes,
            )?;
        let signed_tx = SignedTransferTransaction {
            signed_transaction: transaction,
            used_inputs: selected_inputs,
            return_amount,
        };
        Ok(signed_tx)
    }

    fn broadcast_signed_transfer_tx(
        &self,
        name: &str,
        enckey: &SecKey,
        signed_tx: SignedTransferTransaction,
    ) -> Result<TxId> {
        let current_block_height = self.get_current_block_height()?;

        self.broadcast_transaction(&signed_tx.signed_transaction)?;

        //update the wallet state
        let tx_pending = TransactionPending {
            used_inputs: signed_tx.used_inputs.clone(),
            block_height: current_block_height,
            return_amount: signed_tx.return_amount,
        };

        let transaction = signed_tx.signed_transaction;

        self.update_tx_pending_state(name, enckey, transaction.tx_id(), tx_pending)?;

        if let TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
            payload: TxObfuscated { txid, .. },
            ..
        }) = transaction
        {
            Ok(txid)
        } else {
            Err(Error::new(
                ErrorKind::IllegalInput,
                "Transaction is not transfer transaction",
            ))
        }
    }
}

impl<S, C, T> MultiSigWalletClient for DefaultWalletClient<S, C, T>
where
    S: Storage,
    C: Client,
    T: WalletTransactionBuilder,
{
    fn schnorr_signature(
        &self,
        name: &str,
        enckey: &SecKey,
        tx: &Transaction,
        public_key: &PublicKey,
    ) -> Result<SchnorrSignature> {
        // To verify if the enckey is correct or not
        self.transfer_addresses(name, enckey)?;
        let wallet = self.wallet_service.get_wallet(name, enckey)?;
        let sign_key = match wallet.wallet_kind {
            WalletKind::HW => self.hw_key_service.get_sign_key(public_key)?,
            _ => {
                let private_key = self
                    .wallet_service
                    .find_private_key(name, enckey, public_key)?
                    .chain(|| (ErrorKind::InvalidInput, ""))?;
                Box::new(private_key)
            }
        };
        sign_key.schnorr_sign(tx)
    }

    fn new_multi_sig_session(
        &self,
        name: &str,
        enckey: &SecKey,
        message: H256,
        signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
    ) -> Result<H256> {
        // To verify if the enckey is correct or not
        self.transfer_addresses(name, enckey)?;
        //        let sign_key = self.sign_key(name, enckey, &self_public_key)?;

        let self_private_key = self
            .private_key(name, enckey, &self_public_key)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    format!(
                        "Self public key ({}) is not owned by current wallet",
                        self_public_key
                    ),
                )
            })?;

        self.multi_sig_session_service.new_session(
            message,
            signer_public_keys,
            self_public_key,
            self_private_key,
            enckey,
        )
    }

    fn nonce_commitment(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        self.multi_sig_session_service
            .nonce_commitment(session_id, enckey)
    }

    fn add_nonce_commitment(
        &self,
        session_id: &H256,
        enckey: &SecKey,
        nonce_commitment: H256,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.multi_sig_session_service.add_nonce_commitment(
            session_id,
            nonce_commitment,
            public_key,
            enckey,
        )
    }

    fn nonce(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        self.multi_sig_session_service.nonce(session_id, enckey)
    }

    fn add_nonce(
        &self,
        session_id: &H256,
        enckey: &SecKey,
        nonce: &H256,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.multi_sig_session_service
            .add_nonce(session_id, &nonce, public_key, enckey)
    }

    fn partial_signature(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        self.multi_sig_session_service
            .partial_signature(session_id, enckey)
    }

    fn add_partial_signature(
        &self,
        session_id: &H256,
        enckey: &SecKey,
        partial_signature: H256,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.multi_sig_session_service.add_partial_signature(
            session_id,
            partial_signature,
            public_key,
            enckey,
        )
    }

    fn signature(&self, session_id: &H256, enckey: &SecKey) -> Result<SchnorrSignature> {
        self.multi_sig_session_service.signature(session_id, enckey)
    }

    fn transaction(
        &self,
        name: &str,
        session_id: &H256,
        enckey: &SecKey,
        unsigned_transaction: Tx,
    ) -> Result<TxAux> {
        if unsigned_transaction.inputs.len() != 1 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Multi-Sig Signing is only supported for transactions with only one input",
            ));
        }

        let output_to_spend = self.output(name, enckey, &unsigned_transaction.inputs[0])?;
        let root_hash = self
            .wallet_service
            .find_root_hash(name, enckey, &output_to_spend.address)?
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Output address is not owned by current wallet; cannot spend output in given transaction",
                )
            })?;
        let public_keys = self
            .multi_sig_session_service
            .public_keys(session_id, enckey)?;

        let proof = self
            .root_hash_service
            .generate_proof(name, &root_hash, public_keys, enckey)?;
        let signature = self.signature(session_id, enckey)?;

        let witness = TxWitness::from(vec![TxInWitness::TreeSig(signature, proof)]);
        let signed_transaction =
            SignedTransaction::TransferTransaction(unsigned_transaction, witness);

        self.transaction_builder.obfuscate(signed_transaction)
    }
}

fn check_passphrase_strength(name: &str, passphrase: &SecUtf8) -> Result<()> {
    // `estimate_password_strength` returns a score between `0-4`. Any score less than 3 should be considered too
    // weak.
    let password_entropy = estimate_password_strength(passphrase.unsecure(), &[name])
        .chain(|| (ErrorKind::IllegalInput, "Blank passphrase"))?;

    #[cfg(debug_assertions)]
    let entropy_score = 0;
    #[cfg(not(debug_assertions))]
    let entropy_score = 3;

    if password_entropy.score() < entropy_score {
        return Err(Error::new(
            ErrorKind::IllegalInput,
            format!(
                "Weak passphrase: {}",
                parse_feedback(password_entropy.feedback().as_ref())
            ),
        ));
    }

    Ok(())
}

fn parse_feedback(feedback: Option<&Feedback>) -> String {
    match feedback {
        None => "No feedback available!".to_string(),
        Some(feedback) => {
            let mut feedbacks = Vec::new();

            if let Some(warning) = feedback.warning() {
                feedbacks.push(format!("Warning: {}", warning));
            }

            for suggestion in feedback.suggestions() {
                feedbacks.push(format!("Suggestion: {}", suggestion));
            }

            if feedbacks.is_empty() {
                feedbacks.push("No feedback available!".to_string());
            }

            feedbacks.join(" | ")
        }
    }
}

fn import_transaction(
    wallet: &Wallet,
    wallet_state: &WalletState,
    memento: &mut WalletStateMemento,
    transaction_info: &TransactionInfo,
    paid_fee: Fee,
    block_time: Time,
    spent_flag: Vec<bool>,
) -> Result<Coin> {
    let transaction_change = create_transaction_change(
        wallet,
        wallet_state,
        &transaction_info.tx,
        paid_fee,
        transaction_info.block_height,
        block_time,
    )
    .chain(|| (ErrorKind::InvalidInput, "create transaction change failed"))?;
    let mut value = Coin::zero();
    let transfer_addresses = wallet.transfer_addresses();
    for (i, (output, spent)) in transaction_change
        .outputs
        .iter()
        .zip(spent_flag)
        .enumerate()
    {
        // Only add unspent transaction if output address belongs to current wallet
        if transfer_addresses.contains(&output.address) && !spent {
            memento.add_unspent_transaction(
                TxoPointer::new(transaction_change.transaction_id, i),
                output.clone(),
            );
            value = (value + output.value).chain(|| {
                (
                    ErrorKind::InvalidInput,
                    "invalid coin in outputs of transaction",
                )
            })?;
        }
    }
    memento.add_transaction_change(transaction_change);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mnemonic;
    use client_common::storage::MemoryStorage;

    #[test]
    fn check_delete_wallet() {
        let words = Mnemonic::from_secstr(&SecUtf8::from("pony thank pluck sweet bless tuna couple eight stove fluid essay debate cinnamon elite only")).unwrap();
        let passphrase = SecUtf8::from("123456");
        let wrong_passphrase = SecUtf8::from("123457");
        let client = DefaultWalletClient::new_read_only(MemoryStorage::default());
        client
            .restore_wallet("Default", &passphrase, &words)
            .expect("restore wallet");
        // FIXME this failure will leave storage in an inconsistant state
        // assert!(client.restore_wallet("test", &passphrase, &words).is_err());
        assert!(client.delete_wallet("Default", &wrong_passphrase).is_err());
        assert!(client.delete_wallet("Default1", &passphrase).is_err());
        client
            .delete_wallet("Default", &passphrase)
            .expect("delete wallet");
        client
            .restore_wallet("test", &passphrase, &words)
            .expect("restore wallet");
    }

    #[test]
    fn check_restore_wallet_twice() {
        let words = Mnemonic::from_secstr(&SecUtf8::from("pony thank pluck sweet bless tuna couple eight stove fluid essay debate cinnamon elite only")).unwrap();
        let name1 = "Default1";
        let name2 = "Default2";
        let passphrase = SecUtf8::from("123456");
        let client = DefaultWalletClient::new_read_only(MemoryStorage::default());
        let enckey1 = client
            .restore_wallet(name1, &passphrase, &words)
            .expect("restore wallet 1 failed");
        let enckey2 = client
            .restore_wallet(name2, &passphrase, &words)
            .expect("restore wallet 2 failed");
        let transfer_address_1 = client
            .new_transfer_address(name1, &enckey1)
            .expect("create transfer address 1 failed");
        let transfer_address_2 = client
            .new_transfer_address(name2, &enckey2)
            .expect("create transfer address 2 failed");
        assert_eq!(transfer_address_1, transfer_address_2);
        let staking_address_1 = client
            .new_staking_address(name1, &enckey1)
            .expect("create staking address 1 failed");
        let staking_address_2 = client
            .new_staking_address(name2, &enckey2)
            .expect("create staking address 2 failed");
        assert_eq!(staking_address_1, staking_address_2);
        let transfer_address_22 = client.new_transfer_address(name2, &enckey2).unwrap();
        assert_ne!(transfer_address_2, transfer_address_22);
        let transfer_addresses = client.transfer_addresses(name2, &enckey2).unwrap();
        assert_eq!(transfer_addresses.len(), 2);
    }
}
