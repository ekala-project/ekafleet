#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use crate::raft::state::{Command, FleetStateMachine};

/// A cloud image registered with a cloud provider and tracked by ekafleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredImage {
    /// Cloud image ID (e.g., AMI ID, Azure managed image name, GCE image name).
    pub image_id: String,
    /// Human-readable image name used during registration.
    pub name: String,
    /// Nix store path hash (32 hex chars from `/nix/store/<hash>-...`).
    /// This is the content-addressable cache key.
    pub store_path_hash: String,
    /// Full Nix store path of the NixOS system closure.
    pub store_path: String,
    /// When this image was registered (epoch seconds).
    pub created_at: u64,
    /// Last time this image was used to launch an instance (epoch seconds).
    /// Updated each time the actuator creates a machine with this image.
    pub last_used_at: u64,
    /// Cloud provider name ("aws", "azure", "gcp").
    pub provider: String,
    /// Cloud region where the image is registered.
    pub region: String,
    /// Node pool this image belongs to.
    pub pool: String,
    /// Fleet name this image belongs to.
    pub fleet_name: String,
    /// Cloud storage URI for the uploaded disk image (for cleanup).
    /// e.g., "s3://bucket/name.raw", "gs://bucket/name.tar.gz"
    pub storage_uri: Option<String>,
}

/// Tracks cloud images in the Raft KV store. Provides content-addressable
/// lookup by Nix store path hash so that unchanged NixOS configurations
/// reuse existing cloud images without rebuilding.
#[derive(Clone)]
pub struct ImageTracker {
    raft: FleetStateMachine,
}

impl ImageTracker {
    const KEY_PREFIX: &str = "cloud-image/";

    pub fn new(raft: FleetStateMachine) -> Self {
        Self { raft }
    }

    /// Build a KV key for an image.
    fn key(provider: &str, region: &str, store_path_hash: &str) -> String {
        format!("{}{provider}/{region}/{store_path_hash}", Self::KEY_PREFIX)
    }

    /// Look up a cached image by provider, region, and Nix store path hash.
    pub async fn get(
        &self,
        provider: &str,
        region: &str,
        store_path_hash: &str,
    ) -> Option<RegisteredImage> {
        let key = Self::key(provider, region, store_path_hash);
        let data = self.raft.kv_get(&key).await?;
        serde_json::from_slice(&data).ok()
    }

    /// Store a registered image in the tracker.
    pub async fn put(&self, image: &RegisteredImage) {
        let key = Self::key(&image.provider, &image.region, &image.store_path_hash);
        let value = serde_json::to_vec(image).expect("RegisteredImage serialization");
        self.raft.apply_next(Command::KvPut { key, value }).await;

        tracing::info!(
            image_id = %image.image_id,
            store_path_hash = %image.store_path_hash,
            provider = %image.provider,
            region = %image.region,
            pool = %image.pool,
            "Tracked cloud image"
        );
    }

    /// Remove a tracked image.
    pub async fn delete(&self, provider: &str, region: &str, store_path_hash: &str) {
        let key = Self::key(provider, region, store_path_hash);
        self.raft.apply_next(Command::KvDelete { key }).await;

        tracing::info!(store_path_hash, provider, region, "Untracked cloud image");
    }

    /// List all tracked images.
    pub async fn list_all(&self) -> Vec<RegisteredImage> {
        self.raft
            .kv_list_prefix(Self::KEY_PREFIX)
            .await
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    /// List tracked images for a specific pool.
    pub async fn list_for_pool(&self, fleet_name: &str, pool: &str) -> Vec<RegisteredImage> {
        self.list_all()
            .await
            .into_iter()
            .filter(|i| i.fleet_name == fleet_name && i.pool == pool)
            .collect()
    }

    /// Update the `last_used_at` timestamp for an image.
    pub async fn touch(&self, provider: &str, region: &str, store_path_hash: &str) {
        if let Some(mut image) = self.get(provider, region, store_path_hash).await {
            image.last_used_at = now_epoch();
            self.put(&image).await;
        }
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> ImageTracker {
        let raft = FleetStateMachine::new();
        ImageTracker::new(raft)
    }

    fn sample_image(hash: &str) -> RegisteredImage {
        RegisteredImage {
            image_id: format!("ami-{hash}"),
            name: format!("test-workers-{hash}"),
            store_path_hash: hash.to_string(),
            store_path: format!("/nix/store/{hash}-nixos-system"),
            created_at: 1000,
            last_used_at: 1000,
            provider: "aws".to_string(),
            region: "us-east-1".to_string(),
            pool: "workers".to_string(),
            fleet_name: "test-fleet".to_string(),
            storage_uri: Some(format!("s3://bucket/{hash}.raw")),
        }
    }

    #[tokio::test]
    async fn put_and_get() {
        let tracker = make_tracker();
        let img = sample_image("abc123");

        tracker.put(&img).await;
        let found = tracker.get("aws", "us-east-1", "abc123").await;
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.image_id, "ami-abc123");
        assert_eq!(found.store_path_hash, "abc123");
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let tracker = make_tracker();
        assert!(tracker.get("aws", "us-east-1", "missing").await.is_none());
    }

    #[tokio::test]
    async fn delete_removes_image() {
        let tracker = make_tracker();
        let img = sample_image("abc123");

        tracker.put(&img).await;
        assert!(tracker.get("aws", "us-east-1", "abc123").await.is_some());

        tracker.delete("aws", "us-east-1", "abc123").await;
        assert!(tracker.get("aws", "us-east-1", "abc123").await.is_none());
    }

    #[tokio::test]
    async fn list_all() {
        let tracker = make_tracker();
        tracker.put(&sample_image("aaa")).await;
        tracker.put(&sample_image("bbb")).await;

        let all = tracker.list_all().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn list_for_pool_filters() {
        let tracker = make_tracker();
        tracker.put(&sample_image("aaa")).await;

        let mut other = sample_image("bbb");
        other.pool = "compute".to_string();
        tracker.put(&other).await;

        let workers = tracker.list_for_pool("test-fleet", "workers").await;
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].store_path_hash, "aaa");

        let compute = tracker.list_for_pool("test-fleet", "compute").await;
        assert_eq!(compute.len(), 1);
        assert_eq!(compute[0].store_path_hash, "bbb");
    }

    #[tokio::test]
    async fn touch_updates_last_used() {
        let tracker = make_tracker();
        let img = sample_image("abc123");
        tracker.put(&img).await;

        let before = tracker.get("aws", "us-east-1", "abc123").await.unwrap();
        assert_eq!(before.last_used_at, 1000);

        tracker.touch("aws", "us-east-1", "abc123").await;

        let after = tracker.get("aws", "us-east-1", "abc123").await.unwrap();
        assert!(after.last_used_at >= before.last_used_at);
    }

    #[tokio::test]
    async fn different_regions_are_separate() {
        let tracker = make_tracker();
        let img1 = sample_image("abc123");
        let mut img2 = sample_image("abc123");
        img2.region = "eu-west-1".to_string();
        img2.image_id = "ami-eu-abc123".to_string();

        tracker.put(&img1).await;
        tracker.put(&img2).await;

        let us = tracker.get("aws", "us-east-1", "abc123").await.unwrap();
        assert_eq!(us.image_id, "ami-abc123");

        let eu = tracker.get("aws", "eu-west-1", "abc123").await.unwrap();
        assert_eq!(eu.image_id, "ami-eu-abc123");
    }
}
