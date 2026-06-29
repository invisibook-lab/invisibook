use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint64};

fn main() {
    println!("=== TFHE-rs: Plaintext vs Ciphertext u64 Comparison Benchmark ===\n");

    // Generate keys
    println!("[1/4] Generating keys...");
    let keygen_start = Instant::now();
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    let keygen_time = keygen_start.elapsed();
    println!("  Key generation: {:.3}s\n", keygen_time.as_secs_f64());

    set_server_key(server_key);

    // Test values
    let clear_a: u64 = 42;
    let clear_b: u64 = 100;

    // Encrypt one value (a)
    println!("[2/4] Encrypting value (a = {})...", clear_a);
    let enc_start = Instant::now();
    let encrypted_a = FheUint64::encrypt(clear_a, &client_key);
    let enc_time = enc_start.elapsed();
    println!("  Encryption: {:.3}s\n", enc_time.as_secs_f64());

    // Compare: encrypted_a >= clear_b (plaintext scalar)
    // Expected: 42 >= 100 => false => 0
    println!(
        "[3/4] Comparing encrypted({}) >= plaintext({})...",
        clear_a, clear_b
    );
    let cmp_start = Instant::now();
    let result_ge: FheBool = encrypted_a.ge(clear_b);
    let cmp_time = cmp_start.elapsed();
    println!("  Comparison (ge): {:.3}s\n", cmp_time.as_secs_f64());

    // Decrypt result
    println!("[4/4] Decrypting result...");
    let dec_start = Instant::now();
    let decrypted_ge: bool = result_ge.decrypt(&client_key);
    let dec_time = dec_start.elapsed();
    let result_val: u8 = if decrypted_ge { 1 } else { 0 };
    println!("  Decryption: {:.3}s\n", dec_time.as_secs_f64());

    // Verify correctness
    let expected = clear_a >= clear_b;
    assert_eq!(
        decrypted_ge, expected,
        "Mismatch! Got {}, expected {}",
        decrypted_ge, expected
    );

    println!("=== Results ===");
    println!(
        "  encrypted({}) >= plaintext({}) = {} (correct: {})",
        clear_a, clear_b, result_val, expected
    );

    // Run additional comparison operators for benchmark
    println!("\n=== Additional Comparison Benchmarks ===\n");

    let ops: Vec<(&str, Box<dyn Fn() -> FheBool>)> = {
        // Re-encrypt for each op to ensure fresh ciphertext
        let enc_a = FheUint64::encrypt(clear_a, &client_key);
        let enc_a2 = FheUint64::encrypt(clear_a, &client_key);
        let enc_a3 = FheUint64::encrypt(clear_a, &client_key);
        let enc_a4 = FheUint64::encrypt(clear_a, &client_key);
        let enc_a5 = FheUint64::encrypt(clear_a, &client_key);

        vec![
            ("gt (>)", Box::new(move || enc_a.gt(clear_b)) as Box<dyn Fn() -> FheBool>),
            ("lt (<)", Box::new(move || enc_a2.lt(clear_b))),
            ("le (<=)", Box::new(move || enc_a3.le(clear_b))),
            ("eq (==)", Box::new(move || enc_a4.eq(clear_b))),
            ("ne (!=)", Box::new(move || enc_a5.ne(clear_b))),
        ]
    };

    for (name, op) in &ops {
        let start = Instant::now();
        let res = op();
        let elapsed = start.elapsed();
        let dec: bool = res.decrypt(&client_key);
        let val: u8 = if dec { 1 } else { 0 };
        println!(
            "  {} : result = {}, time = {:.3}s",
            name,
            val,
            elapsed.as_secs_f64()
        );
    }

    // Summary
    println!("\n=== Benchmark Summary ===");
    println!("  Key generation : {:.3}s", keygen_time.as_secs_f64());
    println!("  Encryption     : {:.3}s", enc_time.as_secs_f64());
    println!("  Comparison (ge): {:.3}s", cmp_time.as_secs_f64());
    println!("  Decryption     : {:.3}s", dec_time.as_secs_f64());
    println!(
        "  Total          : {:.3}s",
        keygen_time.as_secs_f64()
            + enc_time.as_secs_f64()
            + cmp_time.as_secs_f64()
            + dec_time.as_secs_f64()
    );
}
