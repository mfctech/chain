use client_common::tendermint::lite;
use client_common::{ErrorKind, Result, ResultExt, Storage};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use tendermint::validator;

/// key space of wallet sync state
const KEYSPACE: &str = "core_wallet_sync";

/// Sync state for wallet
#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
pub struct SyncState {
    /// last block height
    pub last_block_height: u64,
    /// last app hash
    pub last_app_hash: String,
    /// current trusted state for lite client verification
    pub trusted_state: lite::TrustedState,
}

impl SyncState {
    /// construct genesis global state
    pub fn genesis(genesis_validators: Vec<validator::Info>) -> SyncState {
        SyncState {
            last_block_height: 0,
            last_app_hash: "".to_owned(),
            trusted_state: lite::TrustedState::genesis(genesis_validators),
        }
    }
}

/// Load sync state from storage
pub fn load_sync_state<S: Storage>(storage: &S, name: &str) -> Result<Option<SyncState>> {
    storage.load(KEYSPACE, name)
}

/// Save sync state from storage
pub fn save_sync_state<S: Storage>(storage: &S, name: &str, state: &SyncState) -> Result<()> {
    storage.save(KEYSPACE, name, state)
}

/// Delete sync state from storage
pub fn delete_sync_state<S: Storage>(storage: &S, name: &str) -> Result<()> {
    storage.delete(KEYSPACE, name)?;
    Ok(())
}

/// Exposes functionalities for managing client's global state (for synchronization)
///
/// Stores `wallet-name -> global-state`
#[derive(Debug, Default, Clone)]
pub struct SyncStateService<S>
where
    S: Storage,
{
    storage: S,
}

impl<S> SyncStateService<S>
where
    S: Storage,
{
    /// Creates new instance of global state service
    #[inline]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Updates last block height and last app hash with given values
    pub fn save_global_state(&self, name: &str, state: &SyncState) -> Result<()> {
        self.storage.set(KEYSPACE, name, state.encode()).map(|_| ())
    }

    /// Deletes global state data for given wallet
    #[inline]
    pub fn delete_global_state(&self, name: &str) -> Result<()> {
        self.storage.delete(KEYSPACE, name).map(|_| ())
    }

    /// Clears all storage
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }

    /// Get wallet global state
    pub fn get_global_state(&self, name: &str) -> Result<Option<SyncState>> {
        if let Some(bytes) = self.storage.get(KEYSPACE, name)? {
            Ok(Some(SyncState::decode(&mut bytes.as_slice()).chain(
                || {
                    (
                        ErrorKind::DeserializationError,
                        format!(
                            "Unable to deserialize global state for wallet with name {}",
                            name
                        ),
                    )
                },
            )?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::{Decode, Encode};
    use tendermint::{block::Height, lite};

    use super::{lite::TrustedState, SyncState, SyncStateService, KEYSPACE};
    use client_common::storage::{MemoryStorage, Storage};
    use client_common::Result;
    use tendermint::block::signed_header::SignedHeader;
    use test_common::block_generator::{BlockGenerator, GeneratorClient};

    #[test]
    fn check_flow() {
        let storage = MemoryStorage::default();
        let global_state_service = SyncStateService::new(storage);

        let name = "name";

        assert!(global_state_service
            .get_global_state(name)
            .unwrap()
            .is_none());
        assert!(global_state_service
            .save_global_state(
                name,
                &SyncState {
                    last_block_height: 5,
                    last_app_hash:
                        "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                            .to_string(),
                    trusted_state: TrustedState::genesis(vec![]),
                }
            )
            .is_ok());
        assert_eq!(
            5,
            global_state_service
                .get_global_state(name)
                .unwrap()
                .unwrap()
                .last_block_height
        );
        assert_eq!(
            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            global_state_service
                .get_global_state(name)
                .unwrap()
                .unwrap()
                .last_app_hash
        );
        assert!(global_state_service.clear().is_ok());
        assert!(global_state_service
            .get_global_state(name)
            .unwrap()
            .is_none());
    }

    #[test]
    fn check_sync_state_serialization() {
        let c = GeneratorClient::new(BlockGenerator::one_node());
        {
            let mut gen = c.gen.write().unwrap();
            gen.gen_block(&[]);
            gen.gen_block(&[]);
        }

        let gen = c.gen.read().unwrap();
        let header1 = gen.signed_header(Height::default());
        let s = serde_json::to_string_pretty(&header1).unwrap();
        let header2: std::result::Result<SignedHeader, _> = serde_json::from_str(&s);
        let _header2 = gen.signed_header(Height::default().increment());

        let trusted_state = lite::TrustedState::new(
            lite::SignedHeader::new(header1.clone(), header1.header.clone()),
            gen.validators.clone(),
        )
        .into();
        let mut state = SyncState::genesis(vec![]);
        state.last_block_height = 1;
        state.last_app_hash =
            "0F46E113C21F9EACB26D752F9523746CF8D47ECBEA492736D176005911F973A5".to_owned();
        state.trusted_state = trusted_state;

        //        let s = r#" {"last_block_height":425,"last_app_hash":"2bc90e1c459ecf0087225490f7d8fa0168e50ecb4d9f48ce4421ebda0dbef273","trusted_state":{"header":{"version":{"block":"10","app":"0"},"chain_id":"test-chain-y3m1e6-AB","height":"425","time":"2020-04-07T10:22:38.614945Z","last_block_id":{"hash":"5D0D5AC9CE9BE2E56242EAAE79CBADEFB1AC02C53BEDEF72E1F36546D38B8E57","parts":{"total":"1","hash":"8FB34ECA32D9D1CC049DEBB83BACD9E91BC13CC51118CC011FC9D45A20272A57"}},"last_commit_hash":"026B4383A67D0C1B3E33FCC828921590737DE4790860B01AB8C3EDAE69C04607","data_hash":null,"validators_hash":"3C21EDBFF3F843947F5DD2C174F5F3621014862CEC172C2731C9439902546E58","next_validators_hash":"3C21EDBFF3F843947F5DD2C174F5F3621014862CEC172C2731C9439902546E58","consensus_hash":"048091BC7DDC283F77BFBF91D73C44DA58C3DF8A9CBC867405D8B7F3DAADA22F","app_hash":"2bc90e1c459ecf0087225490f7d8fa0168e50ecb4d9f48ce4421ebda0dbef273","last_results_hash":null,"evidence_hash":null,"proposer_address":"11D6FD7549C5673EFCE92625FB9D550EC80F40B9"},"validators":{"validators":[{"address":"11D6FD7549C5673EFCE92625FB9D550EC80F40B9","pub_key":{"type":"tendermint/PubKeyEd25519","value":"Nmegn3ZUT0HTHDwqDEujNM7k3C52zD1+YwPp/4khT/c="},"voting_power":"5000194644","proposer_priority":"0"}]}}}"#;
        //        let state: SyncState = serde_json::from_str(s).unwrap();
        let s1 = serde_json::to_string_pretty(&state).unwrap();
        let state2: std::result::Result<SyncState, _> = serde_json::from_str(&s1);
        let bytes = state.encode();
        let _state1 = SyncState::decode(&mut bytes.as_slice()).unwrap();
    }
}
