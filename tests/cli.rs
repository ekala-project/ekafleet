//! CLI integration tests for the ekafleet binary.
//!
//! Tests all subcommands: argument parsing, help output, token generation,
//! and error handling for missing/invalid arguments.

use assert_cmd::Command;
use predicates::prelude::*;

fn ekafleet() -> Command {
    Command::cargo_bin("ekafleet").unwrap()
}

// ─── Top-level CLI ──────────────────────────────────────────────────

#[test]
fn no_args_shows_help() {
    ekafleet()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn help_flag() {
    ekafleet()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Unified fleet management for ekaos",
        ));
}

#[test]
fn invalid_subcommand() {
    ekafleet()
        .arg("nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

// ─── Token subcommand ───────────────────────────────────────────────

#[test]
fn token_create_outputs_hex_token() {
    let output = ekafleet().args(["token", "create"]).assert().success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let token = stdout.trim();

    // Must be 64 hex characters (256 bits)
    assert_eq!(token.len(), 64, "token must be 64 hex chars");
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "token must be hex: {token}"
    );
}

#[test]
fn token_create_generates_unique_tokens() {
    let get_token = || {
        let output = ekafleet().args(["token", "create"]).output().unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    };

    let t1 = get_token();
    let t2 = get_token();
    let t3 = get_token();

    assert_ne!(t1, t2, "tokens must be unique");
    assert_ne!(t2, t3, "tokens must be unique");
    assert_ne!(t1, t3, "tokens must be unique");
}

#[test]
fn token_create_with_type_flag() {
    ekafleet()
        .args(["token", "create", "--type", "server"])
        .assert()
        .success()
        .stdout(predicate::str::is_match("[0-9a-f]{64}").unwrap());
}

#[test]
fn token_help() {
    ekafleet()
        .args(["token", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generate join token"));
}

// ─── Server subcommand ──────────────────────────────────────────────

#[test]
fn server_requires_token() {
    ekafleet()
        .args(["server"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--token"));
}

#[test]
fn server_help() {
    ekafleet()
        .args(["server", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--listen")
                .and(predicate::str::contains("--token"))
                .and(predicate::str::contains("--data-dir"))
                .and(predicate::str::contains("--http-listen"))
                .and(predicate::str::contains("--peers")),
        );
}

#[test]
fn server_accepts_token_via_env() {
    // This will fail to start because it will try to bind,
    // but it should get past argument parsing
    let result = ekafleet()
        .args([
            "server",
            "--listen",
            "127.0.0.1:0",
            "--http-listen",
            "127.0.0.1:0",
        ])
        .env("EKAFLEET_TOKEN", "test-token-value")
        .timeout(std::time::Duration::from_secs(3))
        .ok();

    // If it times out, the server started (which means token was accepted from env).
    // If it fails, it should NOT be due to missing --token.
    if let Err(e) = result {
        let stderr = String::from_utf8_lossy(&e.as_output().unwrap().stderr);
        assert!(
            !stderr.contains("--token"),
            "should accept token from EKAFLEET_TOKEN env"
        );
    }
}

// ─── Agent subcommand ───────────────────────────────────────────────

#[test]
fn agent_requires_join_and_token() {
    ekafleet()
        .args(["agent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--join").or(predicate::str::contains("--token")));
}

#[test]
fn agent_help() {
    ekafleet()
        .args(["agent", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--join")
                .and(predicate::str::contains("--token"))
                .and(predicate::str::contains("--data-dir"))
                .and(predicate::str::contains("--ca-cert")),
        );
}

#[test]
fn agent_rejects_invalid_server_address() {
    let dir = tempfile::tempdir().unwrap();
    ekafleet()
        .args([
            "agent",
            "--join",
            "not-a-valid-address",
            "--token",
            "some-token",
            "--data-dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid server address"));
}

#[test]
fn agent_rejects_missing_ca_cert_file() {
    let dir = tempfile::tempdir().unwrap();
    ekafleet()
        .args([
            "agent",
            "--join",
            "127.0.0.1:7400",
            "--token",
            "tok",
            "--data-dir",
            dir.path().to_str().unwrap(),
            "--ca-cert",
            "/nonexistent/path/ca.pem",
        ])
        .assert()
        .failure();
}

// ─── Plan subcommand ────────────────────────────────────────────────

#[test]
fn plan_help() {
    ekafleet()
        .args(["plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--config").and(predicate::str::contains("--server")));
}

#[test]
fn plan_fails_without_server() {
    // Plan now tries to connect to the gRPC server
    ekafleet().args(["plan"]).assert().failure();
}

// ─── Apply subcommand ───────────────────────────────────────────────

#[test]
fn apply_help() {
    ekafleet()
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--config")
                .and(predicate::str::contains("--auto-approve"))
                .and(predicate::str::contains("--watch"))
                .and(predicate::str::contains("--server")),
        );
}

#[test]
fn apply_fails_without_server() {
    ekafleet().args(["apply"]).assert().failure();
}

// ─── Status subcommand ──────────────────────────────────────────────

#[test]
fn status_help() {
    ekafleet()
        .args(["status", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--server"));
}

#[test]
fn status_fails_without_server() {
    ekafleet().args(["status"]).assert().failure();
}

// ─── Drift subcommand ───────────────────────────────────────────────

#[test]
fn drift_help() {
    ekafleet()
        .args(["drift", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--server"));
}

#[test]
fn drift_fails_without_server() {
    ekafleet().args(["drift"]).assert().failure();
}

// ─── Rollback subcommand ────────────────────────────────────────────

#[test]
fn rollback_help() {
    ekafleet()
        .args(["rollback", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--all")
                .and(predicate::str::contains("--to"))
                .and(predicate::str::contains("--server")),
        );
}

#[test]
fn rollback_without_args_gives_guidance() {
    ekafleet()
        .args(["rollback"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Specify a machine name or --all"));
}

// ─── Capacity subcommand ────────────────────────────────────────────

#[test]
fn capacity_help() {
    ekafleet()
        .args(["capacity", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--server"));
}

#[test]
fn capacity_fails_without_server() {
    ekafleet().args(["capacity"]).assert().failure();
}

// ─── Services subcommand ────────────────────────────────────────────

#[test]
fn services_help() {
    ekafleet()
        .args(["services", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--server"));
}

#[test]
fn services_fails_without_server() {
    ekafleet().args(["services"]).assert().failure();
}

// ─── Drain subcommand ───────────────────────────────────────────────

#[test]
fn drain_requires_machine_arg() {
    ekafleet()
        .args(["drain"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("<MACHINE>").or(predicate::str::contains("machine")));
}

#[test]
fn drain_help() {
    ekafleet()
        .args(["drain", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<MACHINE>").and(predicate::str::contains("--server")));
}

#[test]
fn drain_fails_without_server() {
    ekafleet().args(["drain", "node-1"]).assert().failure();
}

// ─── Scale subcommand ───────────────────────────────────────────────

#[test]
fn scale_requires_service_and_count() {
    ekafleet().args(["scale"]).assert().failure();
}

#[test]
fn scale_help() {
    ekafleet()
        .args(["scale", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("<SERVICE>")
                .and(predicate::str::contains("<COUNT>"))
                .and(predicate::str::contains("--server")),
        );
}

#[test]
fn scale_fails_without_server() {
    ekafleet().args(["scale", "web", "3"]).assert().failure();
}

// ─── Logs subcommand ────────────────────────────────────────────────

#[test]
fn logs_requires_service() {
    ekafleet().args(["logs"]).assert().failure();
}

#[test]
fn logs_help() {
    ekafleet()
        .args(["logs", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<SERVICE>").and(predicate::str::contains("--server")));
}

#[test]
fn logs_fails_without_server() {
    ekafleet().args(["logs", "web"]).assert().failure();
}
