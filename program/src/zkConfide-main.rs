#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use betting_lib::{compute_payout, PublicBetOutcome};

pub fn main() {
    let market_id = sp1_zkvm::io::read::<[u8; 32]>();
    let user = sp1_zkvm::io::read::<[u8; 20]>();
    let option = sp1_zkvm::io::read::<u8>();
    let amount = sp1_zkvm::io::read::<u64>();
    let odds = sp1_zkvm::io::read::<u64>();
    let resolved_option = sp1_zkvm::io::read::<u8>();

    let payout = compute_payout(option, resolved_option, amount, odds);

    let output = PublicBetOutcome {
        market_id,
        user,
        option,
        amount,
        payout,
    };

    let encoded = PublicBetOutcome::abi_encode(&output);
    sp1_zkvm::io::commit_slice(&encoded);
}
