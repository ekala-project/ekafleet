#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::config::{CloudImageConfig, CloudProviderConfig, CloudProviderType, FleetConfig};
use crate::server::cloud::image_tracker::{ImageTracker, RegisteredImage};
use crate::server::nix;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Manages cloud images: registration, lookup, and deletion.
pub trait CloudImageManager: Send + Sync {
    /// Register a local disk image file with the cloud provider.
    /// Returns the registered cloud image.
    fn register_image(
        &self,
        image_path: &str,
        name: &str,
        store_path_hash: &str,
    ) -> impl Future<Output = Result<RegisteredImageResult, anyhow::Error>> + Send;

    /// Find an existing image by its Nix store path hash tag/label.
    fn find_image_by_hash(
        &self,
        store_path_hash: &str,
    ) -> impl Future<Output = Result<Option<String>, anyhow::Error>> + Send;

    /// Delete a cloud image by ID.
    fn delete_image(
        &self,
        image_id: &str,
    ) -> impl Future<Output = Result<(), anyhow::Error>> + Send;

    /// Delete a cloud storage object by URI (S3/GCS/Azure blob).
    fn delete_storage_object(
        &self,
        storage_uri: &str,
    ) -> impl Future<Output = Result<(), anyhow::Error>> + Send;
}

/// Result from registering an image with a cloud provider.
pub struct RegisteredImageResult {
    pub image_id: String,
    /// Cloud storage URI where the disk image was uploaded.
    pub storage_uri: String,
}

/// Object-safe version of CloudImageManager.
pub trait CloudImageManagerDyn: Send + Sync {
    fn register_image(
        &self,
        image_path: &str,
        name: &str,
        store_path_hash: &str,
    ) -> BoxFuture<'_, Result<RegisteredImageResult, anyhow::Error>>;

    fn find_image_by_hash(
        &self,
        store_path_hash: &str,
    ) -> BoxFuture<'_, Result<Option<String>, anyhow::Error>>;

    fn delete_image(
        &self,
        image_id: &str,
    ) -> BoxFuture<'_, Result<(), anyhow::Error>>;

    fn delete_storage_object(
        &self,
        storage_uri: &str,
    ) -> BoxFuture<'_, Result<(), anyhow::Error>>;
}

impl<T: CloudImageManager + 'static> CloudImageManagerDyn for T {
    fn register_image(
        &self,
        image_path: &str,
        name: &str,
        store_path_hash: &str,
    ) -> BoxFuture<'_, Result<RegisteredImageResult, anyhow::Error>> {
        let p = image_path.to_string();
        let n = name.to_string();
        let h = store_path_hash.to_string();
        Box::pin(async move { CloudImageManager::register_image(self, &p, &n, &h).await })
    }

    fn find_image_by_hash(
        &self,
        store_path_hash: &str,
    ) -> BoxFuture<'_, Result<Option<String>, anyhow::Error>> {
        let h = store_path_hash.to_string();
        Box::pin(async move { CloudImageManager::find_image_by_hash(self, &h).await })
    }

    fn delete_image(
        &self,
        image_id: &str,
    ) -> BoxFuture<'_, Result<(), anyhow::Error>> {
        let id = image_id.to_string();
        Box::pin(async move { CloudImageManager::delete_image(self, &id).await })
    }

    fn delete_storage_object(
        &self,
        storage_uri: &str,
    ) -> BoxFuture<'_, Result<(), anyhow::Error>> {
        let uri = storage_uri.to_string();
        Box::pin(async move { CloudImageManager::delete_storage_object(self, &uri).await })
    }
}

// ---------------------------------------------------------------------------
// AWS image manager
// ---------------------------------------------------------------------------

pub struct AwsImageManager {
    region: String,
    s3_bucket: String,
}

impl AwsImageManager {
    pub fn new(region: &str, s3_bucket: &str) -> Self {
        Self {
            region: region.to_string(),
            s3_bucket: s3_bucket.to_string(),
        }
    }
}

impl CloudImageManager for AwsImageManager {
    async fn register_image(
        &self,
        image_path: &str,
        name: &str,
        store_path_hash: &str,
    ) -> Result<RegisteredImageResult, anyhow::Error> {
        let s3_key = format!("{name}.raw");
        let s3_uri = format!("s3://{}/{s3_key}", self.s3_bucket);

        // 1. Upload to S3
        tracing::info!(s3_uri = %s3_uri, "Uploading disk image to S3");
        let output = tokio::process::Command::new("aws")
            .args([
                "s3", "cp", image_path, &s3_uri,
                "--region", &self.region,
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("aws s3 cp failed: {stderr}"));
        }

        // 2. Import as EBS snapshot
        let container = serde_json::json!({
            "Description": format!("ekafleet {name}"),
            "Format": "RAW",
            "UserBucket": {
                "S3Bucket": self.s3_bucket,
                "S3Key": s3_key,
            }
        });
        tracing::info!(name = %name, "Importing EBS snapshot from S3");
        let output = tokio::process::Command::new("aws")
            .args([
                "ec2", "import-snapshot",
                "--region", &self.region,
                "--disk-container", &container.to_string(),
                "--output", "json",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("aws ec2 import-snapshot failed: {stderr}"));
        }

        let import_json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let import_task_id = import_json["ImportTaskId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing ImportTaskId in response"))?
            .to_string();

        // 3. Wait for import to complete
        let snapshot_id = self.wait_for_import(&import_task_id).await?;

        // 4. Register AMI from snapshot
        let block_mappings = serde_json::json!([{
            "DeviceName": "/dev/xvda",
            "Ebs": {
                "SnapshotId": snapshot_id,
                "VolumeType": "gp3",
                "DeleteOnTermination": true,
            }
        }]);
        tracing::info!(name = %name, snapshot_id = %snapshot_id, "Registering AMI");
        let output = tokio::process::Command::new("aws")
            .args([
                "ec2", "register-image",
                "--region", &self.region,
                "--name", name,
                "--root-device-name", "/dev/xvda",
                "--block-device-mappings", &block_mappings.to_string(),
                "--architecture", "x86_64",
                "--virtualization-type", "hvm",
                "--ena-support",
                "--output", "json",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("aws ec2 register-image failed: {stderr}"));
        }

        let ami_json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let image_id = ami_json["ImageId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing ImageId in register-image response"))?
            .to_string();

        // 5. Tag the AMI
        let tags = format!(
            "Key=nix-store-hash,Value={store_path_hash} Key=managed-by,Value=ekafleet"
        );
        let _ = tokio::process::Command::new("aws")
            .args([
                "ec2", "create-tags",
                "--region", &self.region,
                "--resources", &image_id, &snapshot_id,
                "--tags", &tags,
            ])
            .output()
            .await;

        tracing::info!(image_id = %image_id, name = %name, "AWS AMI registered");

        Ok(RegisteredImageResult {
            image_id,
            storage_uri: s3_uri,
        })
    }

    async fn find_image_by_hash(
        &self,
        store_path_hash: &str,
    ) -> Result<Option<String>, anyhow::Error> {
        let filter = format!("Name=tag:nix-store-hash,Values={store_path_hash}");
        let output = tokio::process::Command::new("aws")
            .args([
                "ec2", "describe-images",
                "--region", &self.region,
                "--owners", "self",
                "--filters", &filter,
                "--output", "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            return Ok(None);
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        Ok(json["Images"]
            .as_array()
            .and_then(|imgs| imgs.first())
            .and_then(|img| img["ImageId"].as_str())
            .map(|s| s.to_string()))
    }

    async fn delete_image(&self, image_id: &str) -> Result<(), anyhow::Error> {
        tracing::info!(image_id = %image_id, "Deregistering AWS AMI");

        // Get snapshot ID before deregistering
        let output = tokio::process::Command::new("aws")
            .args([
                "ec2", "describe-images",
                "--region", &self.region,
                "--image-ids", image_id,
                "--output", "json",
            ])
            .output()
            .await?;

        let snapshot_id = if output.status.success() {
            let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            json["Images"]
                .as_array()
                .and_then(|imgs| imgs.first())
                .and_then(|img| img["BlockDeviceMappings"].as_array())
                .and_then(|bdm| bdm.first())
                .and_then(|m| m["Ebs"]["SnapshotId"].as_str())
                .map(|s| s.to_string())
        } else {
            None
        };

        // Deregister AMI
        let output = tokio::process::Command::new("aws")
            .args([
                "ec2", "deregister-image",
                "--region", &self.region,
                "--image-id", image_id,
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("aws ec2 deregister-image failed: {stderr}"));
        }

        // Delete snapshot
        if let Some(snap_id) = snapshot_id {
            let _ = tokio::process::Command::new("aws")
                .args([
                    "ec2", "delete-snapshot",
                    "--region", &self.region,
                    "--snapshot-id", &snap_id,
                ])
                .output()
                .await;
        }

        Ok(())
    }

    async fn delete_storage_object(&self, storage_uri: &str) -> Result<(), anyhow::Error> {
        tracing::info!(uri = %storage_uri, "Deleting S3 object");
        let output = tokio::process::Command::new("aws")
            .args([
                "s3", "rm", storage_uri,
                "--region", &self.region,
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("aws s3 rm failed: {stderr}"));
        }
        Ok(())
    }
}

impl AwsImageManager {
    async fn wait_for_import(&self, task_id: &str) -> Result<String, anyhow::Error> {
        loop {
            let output = tokio::process::Command::new("aws")
                .args([
                    "ec2", "describe-import-snapshot-tasks",
                    "--region", &self.region,
                    "--import-task-ids", task_id,
                    "--output", "json",
                ])
                .output()
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!(
                    "aws ec2 describe-import-snapshot-tasks failed: {stderr}"
                ));
            }

            let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            let task = &json["ImportSnapshotTasks"][0]["SnapshotTaskDetail"];
            let status = task["Status"].as_str().unwrap_or("");

            match status {
                "completed" => {
                    let snapshot_id = task["SnapshotId"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing SnapshotId after import"))?
                        .to_string();
                    tracing::info!(snapshot_id = %snapshot_id, "Snapshot import completed");
                    return Ok(snapshot_id);
                }
                "active" => {
                    let progress = task["Progress"].as_str().unwrap_or("?");
                    tracing::debug!(task_id, progress = %progress, "Snapshot import in progress");
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                }
                _ => {
                    let msg = task["StatusMessage"].as_str().unwrap_or("unknown error");
                    return Err(anyhow::anyhow!("snapshot import failed: {status}: {msg}"));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Azure image manager
// ---------------------------------------------------------------------------

pub struct AzureImageManager {
    location: String,
    resource_group: String,
    storage_account: String,
    storage_container: String,
}

impl AzureImageManager {
    pub fn new(
        location: &str,
        resource_group: &str,
        storage_account: &str,
        storage_container: Option<&str>,
    ) -> Self {
        Self {
            location: location.to_string(),
            resource_group: resource_group.to_string(),
            storage_account: storage_account.to_string(),
            storage_container: storage_container.unwrap_or("ekafleet-images").to_string(),
        }
    }
}

impl CloudImageManager for AzureImageManager {
    async fn register_image(
        &self,
        image_path: &str,
        name: &str,
        store_path_hash: &str,
    ) -> Result<RegisteredImageResult, anyhow::Error> {
        let blob_name = format!("{name}.vhd");
        let blob_url = format!(
            "https://{}.blob.core.windows.net/{}/{}",
            self.storage_account, self.storage_container, blob_name
        );

        // 1. Upload VHD to blob storage
        tracing::info!(blob_url = %blob_url, "Uploading VHD to Azure blob storage");
        let output = tokio::process::Command::new("az")
            .args([
                "storage", "blob", "upload",
                "--account-name", &self.storage_account,
                "--container-name", &self.storage_container,
                "--file", image_path,
                "--name", &blob_name,
                "--overwrite",
                "--output", "json",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("az storage blob upload failed: {stderr}"));
        }

        // 2. Create managed image
        tracing::info!(name = %name, "Creating Azure managed image");
        let output = tokio::process::Command::new("az")
            .args([
                "image", "create",
                "--resource-group", &self.resource_group,
                "--name", name,
                "--os-type", "Linux",
                "--source", &blob_url,
                "--location", &self.location,
                "--tags",
                &format!("nix-store-hash={store_path_hash}"),
                "managed-by=ekafleet",
                "--output", "json",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("az image create failed: {stderr}"));
        }

        tracing::info!(name = %name, "Azure managed image created");

        Ok(RegisteredImageResult {
            image_id: name.to_string(),
            storage_uri: blob_url,
        })
    }

    async fn find_image_by_hash(
        &self,
        store_path_hash: &str,
    ) -> Result<Option<String>, anyhow::Error> {
        let query = format!(
            "[?tags.\"nix-store-hash\"=='{store_path_hash}'].name | [0]"
        );
        let output = tokio::process::Command::new("az")
            .args([
                "image", "list",
                "--resource-group", &self.resource_group,
                "--query", &query,
                "--output", "tsv",
            ])
            .output()
            .await?;

        if !output.status.success() {
            return Ok(None);
        }

        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if name.is_empty() {
            Ok(None)
        } else {
            Ok(Some(name))
        }
    }

    async fn delete_image(&self, image_id: &str) -> Result<(), anyhow::Error> {
        tracing::info!(image = %image_id, "Deleting Azure managed image");
        let output = tokio::process::Command::new("az")
            .args([
                "image", "delete",
                "--resource-group", &self.resource_group,
                "--name", image_id,
                "--output", "json",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("az image delete failed: {stderr}"));
        }
        Ok(())
    }

    async fn delete_storage_object(&self, storage_uri: &str) -> Result<(), anyhow::Error> {
        // Extract blob name from URL
        let blob_name = storage_uri
            .rsplit('/')
            .next()
            .unwrap_or(storage_uri);

        tracing::info!(blob = %blob_name, "Deleting Azure blob");
        let output = tokio::process::Command::new("az")
            .args([
                "storage", "blob", "delete",
                "--account-name", &self.storage_account,
                "--container-name", &self.storage_container,
                "--name", blob_name,
                "--output", "json",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("az storage blob delete failed: {stderr}"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GCP image manager
// ---------------------------------------------------------------------------

pub struct GcpImageManager {
    project: String,
    gcs_bucket: String,
}

impl GcpImageManager {
    pub fn new(project: &str, gcs_bucket: &str) -> Self {
        Self {
            project: project.to_string(),
            gcs_bucket: gcs_bucket.to_string(),
        }
    }
}

impl CloudImageManager for GcpImageManager {
    async fn register_image(
        &self,
        image_path: &str,
        name: &str,
        store_path_hash: &str,
    ) -> Result<RegisteredImageResult, anyhow::Error> {
        let gcs_key = format!("{name}.tar.gz");
        let gcs_uri = format!("gs://{}/{gcs_key}", self.gcs_bucket);

        // 1. Upload to GCS
        tracing::info!(gcs_uri = %gcs_uri, "Uploading disk image to GCS");
        let output = tokio::process::Command::new("gcloud")
            .args([
                "storage", "cp", image_path, &gcs_uri,
                "--project", &self.project,
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("gcloud storage cp failed: {stderr}"));
        }

        // 2. Create GCE image
        let labels = format!(
            "nix-store-hash={},managed-by=ekafleet",
            store_path_hash.to_lowercase()
        );
        tracing::info!(name = %name, "Creating GCE image");
        let output = tokio::process::Command::new("gcloud")
            .args([
                "compute", "images", "create", name,
                "--source-uri", &gcs_uri,
                "--project", &self.project,
                "--labels", &labels,
                "--format", "json",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("gcloud compute images create failed: {stderr}"));
        }

        tracing::info!(name = %name, "GCE image created");

        Ok(RegisteredImageResult {
            image_id: name.to_string(),
            storage_uri: gcs_uri,
        })
    }

    async fn find_image_by_hash(
        &self,
        store_path_hash: &str,
    ) -> Result<Option<String>, anyhow::Error> {
        let filter = format!(
            "labels.nix-store-hash={}",
            store_path_hash.to_lowercase()
        );
        let output = tokio::process::Command::new("gcloud")
            .args([
                "compute", "images", "list",
                "--project", &self.project,
                "--filter", &filter,
                "--format", "value(name)",
            ])
            .output()
            .await?;

        if !output.status.success() {
            return Ok(None);
        }

        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if name.is_empty() {
            Ok(None)
        } else {
            // Take first line if multiple matches
            Ok(name.lines().next().map(|s| s.to_string()))
        }
    }

    async fn delete_image(&self, image_id: &str) -> Result<(), anyhow::Error> {
        tracing::info!(image = %image_id, "Deleting GCE image");
        let output = tokio::process::Command::new("gcloud")
            .args([
                "compute", "images", "delete", image_id,
                "--project", &self.project,
                "--quiet",
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("gcloud compute images delete failed: {stderr}"));
        }
        Ok(())
    }

    async fn delete_storage_object(&self, storage_uri: &str) -> Result<(), anyhow::Error> {
        tracing::info!(uri = %storage_uri, "Deleting GCS object");
        let output = tokio::process::Command::new("gcloud")
            .args([
                "storage", "rm", storage_uri,
                "--project", &self.project,
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("gcloud storage rm failed: {stderr}"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Store path hash extraction
// ---------------------------------------------------------------------------

/// Extract the 32-character hash from a Nix store path.
/// e.g., "/nix/store/abc123def456...-nixos-system-..." → "abc123def456..."
pub fn extract_store_path_hash(store_path: &str) -> Option<&str> {
    // Store paths look like: /nix/store/<32-char-hash>-<name>
    let basename = store_path.strip_prefix("/nix/store/")?;
    let hash = basename.split('-').next()?;
    if hash.len() == 32 {
        Some(hash)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Orchestration: ensure_image and cleanup
// ---------------------------------------------------------------------------

/// Default disk image attribute per cloud provider.
fn default_disk_image_attr(provider: &CloudProviderType) -> &'static str {
    match provider {
        CloudProviderType::Aws => "amazonImage",
        CloudProviderType::Azure => "azureImage",
        CloudProviderType::Gcp => "gceImage",
    }
}

/// Resolve the cloud image for a pool. Returns the image ID to use.
/// Builds and registers a new image only if the NixOS store path has changed.
pub async fn ensure_image(
    pool_name: &str,
    cloud_config: &CloudProviderConfig,
    image_config: &CloudImageConfig,
    fleet_name: &str,
    image_tracker: &ImageTracker,
    image_manager: &dyn CloudImageManagerDyn,
) -> Result<String, anyhow::Error> {
    let provider_str = match cloud_config.provider {
        CloudProviderType::Aws => "aws",
        CloudProviderType::Azure => "azure",
        CloudProviderType::Gcp => "gcp",
    };

    // 1. Build the NixOS system toplevel to get the store path
    let toplevel_attr = format!(
        "{}.config.system.build.toplevel",
        image_config.nixos_config
    );
    tracing::info!(
        pool = %pool_name,
        attr = %toplevel_attr,
        "Building NixOS system toplevel to determine store path"
    );
    let store_path = nix::build(&toplevel_attr).await
        .map_err(|e| anyhow::anyhow!("failed to build toplevel for pool {pool_name}: {e}"))?;

    // 2. Extract the content-addressable hash
    let store_path_hash = extract_store_path_hash(&store_path)
        .ok_or_else(|| anyhow::anyhow!("invalid store path format: {store_path}"))?;

    // 3. Check cache
    if let Some(cached) = image_tracker
        .get(provider_str, &cloud_config.region, store_path_hash)
        .await
    {
        tracing::info!(
            pool = %pool_name,
            image_id = %cached.image_id,
            store_path_hash = %store_path_hash,
            "Using cached cloud image (NixOS configuration unchanged)"
        );
        return Ok(cached.image_id);
    }

    // 4. Build the disk image
    let disk_attr = image_config
        .disk_image_attr
        .as_deref()
        .unwrap_or_else(|| default_disk_image_attr(&cloud_config.provider));
    let disk_image_ref = format!(
        "{}.config.system.build.{}",
        image_config.nixos_config, disk_attr
    );
    tracing::info!(
        pool = %pool_name,
        attr = %disk_image_ref,
        "Building NixOS disk image (configuration changed)"
    );
    let disk_image_path = nix::build(&disk_image_ref).await
        .map_err(|e| anyhow::anyhow!("failed to build disk image for pool {pool_name}: {e}"))?;

    // 5. Register with cloud provider
    let default_prefix = format!("{fleet_name}-{pool_name}");
    let name_prefix = image_config
        .name_prefix
        .as_deref()
        .unwrap_or(&default_prefix);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let image_name = format!("{name_prefix}-{}", &store_path_hash[..12]);

    tracing::info!(
        pool = %pool_name,
        name = %image_name,
        "Registering cloud image"
    );
    let result = image_manager
        .register_image(&disk_image_path, &image_name, store_path_hash)
        .await?;

    // 6. Track in Raft KV
    let registered = RegisteredImage {
        image_id: result.image_id.clone(),
        name: image_name,
        store_path_hash: store_path_hash.to_string(),
        store_path: store_path.clone(),
        created_at: timestamp,
        last_used_at: timestamp,
        provider: provider_str.to_string(),
        region: cloud_config.region.clone(),
        pool: pool_name.to_string(),
        fleet_name: fleet_name.to_string(),
        storage_uri: Some(result.storage_uri),
    };
    image_tracker.put(&registered).await;

    tracing::info!(
        pool = %pool_name,
        image_id = %result.image_id,
        store_path_hash = %store_path_hash,
        "Cloud image registered and cached"
    );

    Ok(result.image_id)
}

/// Clean up expired images for all pools in the fleet.
/// Called automatically after image resolution during each apply/watch cycle.
///
/// Retention policy per pool:
/// - The active image (matching current store path hash) is never deleted.
/// - The `retain_count` most recent non-active images are kept for rollback.
/// - Non-active images beyond `retain_count` and older than `max_age_seconds` are deleted.
pub async fn cleanup_expired_images(
    fleet_config: &FleetConfig,
    image_tracker: &ImageTracker,
    image_managers: &HashMap<String, Box<dyn CloudImageManagerDyn>>,
    active_hashes: &HashMap<String, String>, // pool_name → current store_path_hash
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for (pool_name, pool_config) in &fleet_config.node_pools {
        let Some(cloud) = &pool_config.cloud else {
            continue;
        };
        let Some(image_config) = &cloud.image else {
            continue;
        };

        let pool_key = pool_name.as_str();
        let manager_key = match cloud.provider {
            CloudProviderType::Aws => "aws",
            CloudProviderType::Azure => "azure",
            CloudProviderType::Gcp => "gcp",
        };
        let Some(manager) = image_managers.get(manager_key) else {
            continue;
        };

        let current_hash = active_hashes.get(pool_key);
        let mut images = image_tracker
            .list_for_pool(&fleet_config.name, pool_name)
            .await;

        // Separate active from non-active
        let (_active, mut inactive): (Vec<_>, Vec<_>) = images
            .drain(..)
            .partition(|img| {
                current_hash.map_or(false, |h| h == &img.store_path_hash)
            });

        // Sort inactive by created_at descending (newest first)
        inactive.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let retain_count = image_config.retain_count as usize;
        let max_age = image_config.max_age_seconds;

        // Keep the first `retain_count` inactive images regardless of age
        for (i, img) in inactive.iter().enumerate() {
            if i < retain_count {
                continue; // Retained for rollback
            }

            let age = now.saturating_sub(img.created_at);
            if age < max_age {
                continue; // Not yet expired
            }

            tracing::info!(
                pool = %pool_name,
                image_id = %img.image_id,
                age_days = age / 86400,
                "Cleaning up expired cloud image"
            );

            // Delete from cloud provider
            if let Err(e) = manager.delete_image(&img.image_id).await {
                tracing::warn!(
                    pool = %pool_name,
                    image_id = %img.image_id,
                    error = %e,
                    "Failed to delete expired image from cloud provider, will retry next cycle"
                );
                continue; // Don't remove from tracker if cloud deletion failed
            }

            // Delete storage object
            if let Some(uri) = &img.storage_uri {
                if let Err(e) = manager.delete_storage_object(uri).await {
                    tracing::warn!(
                        pool = %pool_name,
                        uri = %uri,
                        error = %e,
                        "Failed to delete storage object for expired image"
                    );
                }
            }

            // Remove from tracker
            image_tracker
                .delete(&img.provider, &img.region, &img.store_path_hash)
                .await;
        }
    }
}

/// Build a CloudImageManagerDyn for a given cloud config.
pub fn build_image_manager(
    cloud_config: &CloudProviderConfig,
    image_config: &CloudImageConfig,
) -> Box<dyn CloudImageManagerDyn> {
    match cloud_config.provider {
        CloudProviderType::Aws => Box::new(AwsImageManager::new(
            &cloud_config.region,
            image_config.s3_bucket.as_deref().unwrap_or(""),
        )),
        CloudProviderType::Azure => Box::new(AzureImageManager::new(
            &cloud_config.region,
            cloud_config.resource_group.as_deref().unwrap_or("ekafleet"),
            image_config.storage_account.as_deref().unwrap_or(""),
            image_config.storage_container.as_deref(),
        )),
        CloudProviderType::Gcp => Box::new(GcpImageManager::new(
            cloud_config.project.as_deref().unwrap_or(""),
            image_config.gcs_bucket.as_deref().unwrap_or(""),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hash_from_store_path() {
        let path = "/nix/store/aaaabbbbccccddddeeeeffffgggghhhh-nixos-system-24.05";
        let hash = extract_store_path_hash(path);
        assert_eq!(hash, Some("aaaabbbbccccddddeeeeffffgggghhhh"));
    }

    #[test]
    fn extract_hash_rejects_short_hash() {
        let path = "/nix/store/tooshort-nixos-system";
        assert!(extract_store_path_hash(path).is_none());
    }

    #[test]
    fn extract_hash_rejects_non_store_path() {
        let path = "/usr/bin/foo";
        assert!(extract_store_path_hash(path).is_none());
    }

    #[test]
    fn default_disk_image_attrs() {
        assert_eq!(default_disk_image_attr(&CloudProviderType::Aws), "amazonImage");
        assert_eq!(default_disk_image_attr(&CloudProviderType::Azure), "azureImage");
        assert_eq!(default_disk_image_attr(&CloudProviderType::Gcp), "gceImage");
    }
}
