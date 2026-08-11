use crate::common::BdkCli;
use predicates::prelude::*;
use tempfile::TempDir;
// --- KEY COMMAND TESTS ---
mod test_key {
    use super::*;
    use serde_json::Value;

    #[test]
    fn test_cli_key_generate() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        cli.key_cmd(&["generate"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"xprv\":"))
            .stdout(predicate::str::contains("\"mnemonic\":"))
            .stdout(predicate::str::contains("\"fingerprint\":"));
    }

    #[test]
    fn test_cli_key_derive() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let generate_output = cli
            .key_cmd(&["generate"])
            .output()
            .expect("Failed to execute generate command");
        assert!(generate_output.status.success(), "Generate command failed");

        let generate_json: Value =
            serde_json::from_slice(&generate_output.stdout).expect("Invalid JSON");
        let xprv = generate_json["xprv"].as_str().expect("Missing XPRV");

        let mut cmd = cli.key_cmd(&[
            "derive",
            "--xprv",
            xprv,
            "--derivation_path",
            "m/84'/1'/0'/0",
        ]);

        cmd.assert()
            .success()
            .stdout(predicate::str::contains("\"xprv\":"))
            .stdout(predicate::str::contains("\"xpub\":"));
    }

    #[test]
    fn test_cli_key_restore() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        // Execute the command and capture the output
        let generate_cmd = cli
            .key_cmd(&["generate"])
            .output()
            .expect("Failed to execute generate command");
        assert!(generate_cmd.status.success(), "Generate command failed");

        // Parse the JSON to extract the mnemonic
        let generate_json: Value =
            serde_json::from_slice(&generate_cmd.stdout).expect("Failed to parse JSON");

        let mnemonic = generate_json["mnemonic"]
            .as_str()
            .expect("Mnemonic missing");
        let xprv = generate_json["xprv"].as_str().expect("XPRV missing");
        let finger_print = generate_json["fingerprint"]
            .as_str()
            .expect("Fingerprint missing");

        // Restore using the mnemonic
        let output_restore = cli
            .key_cmd(&["restore", "--mnemonic", mnemonic])
            .output()
            .expect("Failed to execute restore command");
        assert!(output_restore.status.success(), "Restore command failed");

        // Parse the JSON from the restore command
        let restore_json: Value =
            serde_json::from_slice(&output_restore.stdout).expect("Failed to parse JSON");

        let restored_xprv = restore_json["xprv"]
            .as_str()
            .expect("Restored XPRV missing");
        let restored_fingerprint = restore_json["fingerprint"]
            .as_str()
            .expect("Restored fingerprint missing");

        // Assert that the restored data exactly matches the generated data
        assert_eq!(
            xprv, restored_xprv,
            "The restored XPRV does not match the generated XPRV!"
        );

        assert_eq!(
            finger_print, restored_fingerprint,
            "The restored fingerprint does not match the generated fingerprint!"
        );
    }
}

// --- WALLETS COMMAND TESTS ---
mod test_wallets {
    use super::*;

    #[test]
    fn test_list_wallets_empty() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let mut cmd = cli.build_base_cmd();
        cmd.arg("wallets").arg("list");

        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("No wallets configured yet."));
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn test_list_wallets_with_entries() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        for wallet_name in ["wallet_one", "wallet_two"] {
            let desc = cli
                .cmd("descriptor", &["--type", "tr"])
                .output()
                .expect("Command to generate descriptors failed");
            let desc_values: serde_json::Value = serde_json::from_slice(&desc.stdout).unwrap();
            let pub_desc = &desc_values["public_descriptors"];
            let ext_desc = pub_desc["external"].as_str().unwrap();
            let int_desc = pub_desc["internal"].as_str().unwrap();

            cli.build_base_cmd()
                .arg("wallet")
                .arg("--wallet")
                .arg(wallet_name)
                .arg("config")
                .arg("--ext-descriptor")
                .arg(ext_desc)
                .arg("--int-descriptor")
                .arg(int_desc)
                .arg("--client-type")
                .arg("rpc")
                .arg("--database-type")
                .arg("sqlite")
                .arg("--url")
                .arg("http://localhost:18443")
                .assert()
                .success();
        }

        cli.build_base_cmd()
            .arg("wallets")
            .arg("list")
            .assert()
            .success()
            .stdout(predicate::str::contains("wallet_one"))
            .stdout(predicate::str::contains("wallet_two"));
    }
}

// --- DESCRIPTOR COMMAND TESTS ---
mod test_descriptor {
    use super::*;

    #[test]
    fn test_generate_new_descriptor() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        // Run `bdk-cli descriptor --type tr`
        cli.cmd("descriptor", &["--type", "tr"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"public_descriptors\":"))
            .stdout(predicate::str::contains("\"private_descriptors\":"))
            .stdout(predicate::str::contains("\"mnemonic\":"))
            .stdout(predicate::str::contains("\"fingerprint\":"));
    }
}

// --- COMPILE COMMAND TESTS ---
#[cfg(feature = "compiler")]
mod test_compile {
    use super::*;

    #[test]
    fn test_compile_valid_policy() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        let policy = "pk(02e5b88fdb71c696e1a473f309a47535b7190e21a22bd25e7fc8bd055db3bba12f)";

        cli.cmd("compile", &[policy, "--type", "wsh"])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"descriptor\":"))
            .stdout(predicate::str::contains("wsh("));
    }

    #[test]
    fn test_compile_invalid_policy() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("testnet", Some(temp_dir.path().to_path_buf()));

        cli.cmd("compile", &["invalid_policy", "--type", "wsh"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Invalid policy"));
    }
}

// --- CONFIG COMMAND TESTS ---
#[cfg(feature = "rpc")]
mod test_config {
    use super::*;
    use serde_json::Value;

    fn save_wallet(cli: &BdkCli, wallet_name: &str) {
        let desc = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");

        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("Invalid JSON from output descriptor");

        let pub_desc = &desc_values["public_descriptors"];

        cli.build_base_cmd()
            .arg("wallet")
            .arg("--wallet")
            .arg(wallet_name)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(pub_desc["external"].as_str().unwrap())
            .arg("--int-descriptor")
            .arg(pub_desc["internal"].as_str().unwrap())
            .arg("--client-type")
            .arg("rpc")
            .arg("--database-type")
            .arg("sqlite")
            .arg("--url")
            .arg("http://localhost:18443")
            .assert()
            .success();
    }

    #[test]
    fn test_save_and_read_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));

        let desc = cli
            .cmd("descriptor", &["--type", "tr"])
            .output()
            .expect("Command to generate descriptors failed");

        let desc_values: Value =
            serde_json::from_slice(&desc.stdout).expect("Invalid JSON from output descriptor");

        let pub_desc = &desc_values["public_descriptors"];

        let ext_desc = pub_desc["external"].as_str().unwrap();
        let int_desc = pub_desc["internal"].as_str().unwrap();
        let wallet_name = "test_config_wallet";
        let client_type = "rpc";
        let db = "sqlite";
        let url = "http://localhost:18443";

        let mut cmd_init = cli.build_base_cmd();
        cmd_init
            .arg("wallet")
            .arg("--wallet")
            .arg(wallet_name)
            .arg("config")
            .arg("--ext-descriptor")
            .arg(ext_desc)
            .arg("--int-descriptor")
            .arg(int_desc)
            .arg("--client-type")
            .arg(client_type)
            .arg("--database-type")
            .arg(db)
            .arg("--url")
            .arg(url);

        cmd_init.assert().success();

        // verify saved config
        let mut cmd = cli.build_base_cmd();
        cmd.arg("wallets").arg("list");

        let output = cmd.output().expect("Failed to execute wallets command");

        assert!(
            output.status.success(),
            "The wallets command failed to execute"
        );

        let json_output: Value =
            serde_json::from_slice(&output.stdout).expect("CLI did not output valid JSON");

        let config = &json_output[wallet_name];

        assert!(
            !config.is_null(),
            "The wallet {wallet_name} was not found in the root JSON object"
        );

        assert_eq!(config["wallet"].as_str().unwrap(), wallet_name);
        assert_eq!(config["network"].as_str().unwrap(), "regtest");
        assert_eq!(config["database_type"].as_str().unwrap(), db);
        assert_eq!(config["client_type"].as_str().unwrap(), client_type);
        assert_eq!(config["server_url"].as_str().unwrap(), url);
        assert_eq!(config["ext_descriptor"].as_str().unwrap(), ext_desc);
        assert_eq!(config["int_descriptor"].as_str().unwrap(), int_desc);
    }

    #[test]
    fn test_delete_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let remove_wallet_name = "test_delete_wallet";
        let keep_wallet_name = "test_keep_wallet";

        save_wallet(&cli, remove_wallet_name);
        save_wallet(&cli, keep_wallet_name);

        // Delete one config: the output is a confirmation message
        let output = cli
            .build_base_cmd()
            .arg("wallets")
            .arg("delete")
            .arg(remove_wallet_name)
            .output()
            .expect("Failed to execute wallets delete command");
        assert!(output.status.success(), "wallets delete failed");

        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            json["message"].as_str().unwrap(),
            "Wallet configuration 'test_delete_wallet' deleted successfully"
        );

        // Re-listing no longer contains the deleted wallet
        let output = cli
            .build_base_cmd()
            .arg("wallets")
            .arg("list")
            .output()
            .expect("Failed to execute wallets list command");

        let list: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(list.get(remove_wallet_name).is_none());
        assert!(list.get(keep_wallet_name).is_some());
    }

    #[test]
    fn test_delete_unknown_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        save_wallet(&cli, "existing_wallet");

        cli.build_base_cmd()
            .arg("wallets")
            .arg("delete")
            .arg("ghost_wallet")
            .assert()
            .failure()
            .stderr(predicate::str::contains("not found in config"));
    }

    #[test]
    fn test_delete_last_wallet_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = BdkCli::new("regtest", Some(temp_dir.path().to_path_buf()));
        let config_path = temp_dir.path().join("config.toml");

        save_wallet(&cli, "last_wallet");
        assert!(config_path.exists());

        cli.build_base_cmd()
            .arg("wallets")
            .arg("delete")
            .arg("last_wallet")
            .assert()
            .success();

        assert!(!config_path.exists());

        cli.build_base_cmd()
            .arg("wallets")
            .arg("list")
            .assert()
            .failure()
            .stderr(predicate::str::contains("No wallets configured yet."));
    }
}

//  SILENT PAYMENTS
#[cfg(feature = "silent-payments")]
mod test_silent_payments {
    use super::*;

    const SCAN: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const SPEND: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    #[test]
    fn test_silent_payment_code_network_hrp() {
        BdkCli::new("regtest", None)
            .cmd(
                "silent_payment_code",
                &["--scan_key", SCAN, "--spend_key", SPEND],
            )
            .assert()
            .success()
            .stdout(predicate::str::contains("sprt1"));

        BdkCli::new("testnet", None)
            .cmd(
                "silent_payment_code",
                &["--scan_key", SCAN, "--spend_key", SPEND],
            )
            .assert()
            .success()
            .stdout(predicate::str::contains("tsp1"));
    }

    #[test]
    fn test_silent_payment_code_rejects_invalid_pubkey() {
        BdkCli::new("regtest", None)
            .cmd(
                "silent_payment_code",
                &["--scan_key", "deadbeef", "--spend_key", SPEND],
            )
            .assert()
            .failure()
            .stderr(predicate::str::contains("malformed public key"));
    }
}
