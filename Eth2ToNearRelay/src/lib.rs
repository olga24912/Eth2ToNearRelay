use types::BeaconBlockHeader;
use types::BeaconBlockBody;
use types::MainnetEthSpec;
use merkle_proof::MerkleTree;
use ethereum_types::H256;
use tree_hash::TreeHash;
use types::BeaconStateError;
use serde_json::Value;

pub fn get_header_from_json(json_str: &str) -> serde_json::Result<BeaconBlockHeader> {
    serde_json::from_str(json_str)
}

pub fn get_body_from_json(json_str: &str) -> serde_json::Result<BeaconBlockBody<MainnetEthSpec>> {
    serde_json::from_str(json_str)
}

pub fn body_json_from_block_json(block_json_str: std::string::String) -> std::string::String {
    let v: Value = serde_json::from_str(&block_json_str).unwrap();
    let body_json_str = serde_json::to_string(&v["data"]["message"]["body"]).unwrap();
    body_json_str
}

//https://docs.rs/reqwest/0.11.10/reqwest/struct.Response.html
pub async fn json_from_rpc_request(url: &str) -> std::string::String {
    reqwest::get(url).await.unwrap().text().await.unwrap()
}

pub async fn get_header_from_rpc(block_id: &str) -> serde_json::Result<BeaconBlockHeader> {
    let url = format!("https://lodestar-kiln.chainsafe.io/eth/v1/beacon/headers/{}", block_id);
    let json_str = json_from_rpc_request(&url).await;
    get_header_from_json(&json_str)
}

pub async fn get_body_from_rpc(block_id: &str) -> serde_json::Result<BeaconBlockBody<MainnetEthSpec>> {
    let url = format!("https://lodestar-kiln.chainsafe.io/eth/v2/beacon/blocks/{}", block_id);
    get_body_from_json(
        &body_json_from_block_json(
           json_from_rpc_request(&url).await))
}

pub fn build_merkle_tree_for_body(beacon_body: &BeaconBlockBody<MainnetEthSpec>) -> Result<MerkleTree, BeaconStateError>  {
    let leaves : [H256; 10] = [
           beacon_body.randao_reveal().tree_hash_root(),
           beacon_body.eth1_data().tree_hash_root(),
           beacon_body.graffiti().tree_hash_root(),
           beacon_body.proposer_slashings().tree_hash_root(),
           beacon_body.attester_slashings().tree_hash_root(),
           beacon_body.attestations().tree_hash_root(),
           beacon_body.deposits().tree_hash_root(),
           beacon_body.voluntary_exits().tree_hash_root(),
           beacon_body.sync_aggregate()?.tree_hash_root(),
           beacon_body.execution_payload()?.tree_hash_root()];

    Ok(MerkleTree::create(&leaves, 4))
}

pub fn get_Eth1Data_proof(mtree: MerkleTree) -> (H256, Vec<H256>) {
    mtree.generate_proof(1, 4)
}

pub async fn get_Eth1Data_proof_from_rpc(block_id: &str) -> (H256, Vec<H256>) {
    let body = get_body_from_rpc(block_id).await.unwrap();
    let mtree = build_merkle_tree_for_body(&body).unwrap();
    get_Eth1Data_proof(mtree)
}

pub fn check_Eth1Data_proof(eth1data_hash: H256, proof: &[H256; 4], body_hash: H256) -> bool {
    merkle_proof::verify_merkle_proof(eth1data_hash, proof, 4, 1, body_hash)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_header_from_json() {
    }

    fn test_get_body_from_json() {
    }
}
