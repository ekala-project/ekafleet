#![allow(dead_code)]

use std::collections::HashMap;

use crate::config::CloudProviderConfig;
use crate::server::scaling::{CloudProvider, CreateMachineRequest, MachineInstance, MachineState};

/// GCP Compute Engine cloud provider. Uses the `gcloud` CLI for all operations.
pub struct GcpCloudProvider {
    project: String,
    zone: String,
}

impl GcpCloudProvider {
    pub fn new(config: &CloudProviderConfig) -> Self {
        Self {
            project: config
                .project
                .clone()
                .unwrap_or_else(|| "default".to_string()),
            zone: config
                .zone
                .clone()
                .unwrap_or_else(|| format!("{}-a", config.region)),
        }
    }

    fn now_epoch() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Generate a unique instance name from fleet/pool context.
    /// GCE instance names must be lowercase, start with a letter, and
    /// contain only letters, numbers, and hyphens.
    fn instance_name(fleet_name: &str, pool: &str) -> String {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        format!(
            "{}-{}-{:08x}",
            fleet_name.to_lowercase(),
            pool.to_lowercase(),
            suffix
        )
    }
}

impl CloudProvider for GcpCloudProvider {
    async fn create_machine(
        &self,
        request: &CreateMachineRequest,
    ) -> Result<MachineInstance, anyhow::Error> {
        let instance_name = Self::instance_name(&request.fleet_name, &request.pool);
        let zone = request.zone.as_deref().unwrap_or(&self.zone);

        // Write user-data to a temp file
        let ud_path = format!("/tmp/ekafleet-ud-{instance_name}.sh");
        tokio::fs::write(&ud_path, &request.user_data).await?;

        let mut args = vec![
            "compute".to_string(),
            "instances".to_string(),
            "create".to_string(),
            instance_name.clone(),
            "--project".to_string(),
            request
                .project
                .as_deref()
                .unwrap_or(&self.project)
                .to_string(),
            "--zone".to_string(),
            zone.to_string(),
            "--image".to_string(),
            request.image_id.clone(),
            "--machine-type".to_string(),
            request.instance_type.clone(),
            format!("--metadata-from-file=user-data={ud_path}"),
            "--format".to_string(),
            "json".to_string(),
        ];

        // Labels (GCE labels must be lowercase key=value)
        let labels = format!(
            "ekafleet={},pool={},managed-by=ekafleet",
            request.fleet_name.to_lowercase(),
            request.pool.to_lowercase(),
        );
        args.extend(["--labels".to_string(), labels]);

        // Subnet
        if let Some(subnet) = &request.subnet_id {
            args.extend(["--subnet".to_string(), subnet.clone()]);
        }

        // Disk size
        if let Some(disk_gb) = request.disk_size_gb {
            args.extend(["--boot-disk-size".to_string(), format!("{disk_gb}GB")]);
        }

        // Service account
        if let Some(sa) = &request.iam_instance_profile {
            args.extend(["--service-account".to_string(), sa.clone()]);
        }

        // Spot/preemptible instances
        if let Some(spot) = &request.spot
            && spot.enabled
        {
            args.extend(["--provisioning-model".to_string(), "SPOT".to_string()]);
        }

        tracing::info!(
            project = %self.project,
            zone = %zone,
            machine_type = %request.instance_type,
            image = %request.image_id,
            pool = %request.pool,
            instance_name = %instance_name,
            "Creating GCP Compute Engine instance"
        );

        let output = tokio::process::Command::new("gcloud")
            .args(&args)
            .output()
            .await?;

        // Clean up temp file
        let _ = tokio::fs::remove_file(&ud_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "gcloud compute instances create failed: {stderr}"
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

        // gcloud returns an array of created instances
        let instance = json.as_array().and_then(|a| a.first()).unwrap_or(&json);

        // Extract IPs from network interfaces
        let private_ip = instance["networkInterfaces"]
            .as_array()
            .and_then(|nics| nics.first())
            .and_then(|nic| nic["networkIP"].as_str())
            .map(|s| s.to_string());

        let public_ip = instance["networkInterfaces"]
            .as_array()
            .and_then(|nics| nics.first())
            .and_then(|nic| nic["accessConfigs"].as_array())
            .and_then(|acs| acs.first())
            .and_then(|ac| ac["natIP"].as_str())
            .map(|s| s.to_string());

        tracing::info!(
            instance_name = %instance_name,
            private_ip = ?private_ip,
            "GCP instance created"
        );

        Ok(MachineInstance {
            instance_id: instance_name,
            provider: "gcp".to_string(),
            state: MachineState::Pending,
            public_ip,
            private_ip,
            labels: request.labels.clone(),
            pool: request.pool.clone(),
            created_at: Self::now_epoch(),
        })
    }

    async fn destroy_machine(&self, instance_id: &str) -> Result<(), anyhow::Error> {
        tracing::info!(
            instance = instance_id,
            project = %self.project,
            zone = %self.zone,
            "Deleting GCP Compute Engine instance"
        );

        let output = tokio::process::Command::new("gcloud")
            .args([
                "compute",
                "instances",
                "delete",
                instance_id,
                "--project",
                &self.project,
                "--zone",
                &self.zone,
                "--quiet",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "gcloud compute instances delete failed: {stderr}"
            ));
        }

        Ok(())
    }

    async fn describe_machine(
        &self,
        instance_id: &str,
    ) -> Result<Option<MachineInstance>, anyhow::Error> {
        let output = tokio::process::Command::new("gcloud")
            .args([
                "compute",
                "instances",
                "describe",
                instance_id,
                "--project",
                &self.project,
                "--zone",
                &self.zone,
                "--format",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("was not found") || stderr.contains("NOT_FOUND") {
                return Ok(None);
            }
            return Err(anyhow::anyhow!(
                "gcloud compute instances describe failed: {stderr}"
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

        let state = match json["status"].as_str() {
            Some("PROVISIONING") | Some("STAGING") => MachineState::Pending,
            Some("RUNNING") => MachineState::Running,
            Some("STOPPING") | Some("SUSPENDING") => MachineState::Stopping,
            Some("TERMINATED") | Some("SUSPENDED") => MachineState::Terminated,
            _ => MachineState::Unknown,
        };

        let mut labels = HashMap::new();
        let mut pool = String::new();
        if let Some(label_map) = json["labels"].as_object() {
            for (key, value) in label_map {
                if key == "pool" {
                    pool = value.as_str().unwrap_or("").to_string();
                } else {
                    labels.insert(key.clone(), value.as_str().unwrap_or("").to_string());
                }
            }
        }

        let private_ip = json["networkInterfaces"]
            .as_array()
            .and_then(|nics| nics.first())
            .and_then(|nic| nic["networkIP"].as_str())
            .map(|s| s.to_string());

        let public_ip = json["networkInterfaces"]
            .as_array()
            .and_then(|nics| nics.first())
            .and_then(|nic| nic["accessConfigs"].as_array())
            .and_then(|acs| acs.first())
            .and_then(|ac| ac["natIP"].as_str())
            .map(|s| s.to_string());

        Ok(Some(MachineInstance {
            instance_id: json["name"].as_str().unwrap_or(instance_id).to_string(),
            provider: "gcp".to_string(),
            state,
            public_ip,
            private_ip,
            labels,
            pool,
            created_at: 0,
        }))
    }

    async fn list_fleet_machines(
        &self,
        fleet_name: &str,
        pool: &str,
    ) -> Result<Vec<MachineInstance>, anyhow::Error> {
        let filter = format!(
            "labels.ekafleet={} AND labels.pool={} AND status=RUNNING",
            fleet_name.to_lowercase(),
            pool.to_lowercase(),
        );

        let output = tokio::process::Command::new("gcloud")
            .args([
                "compute",
                "instances",
                "list",
                "--project",
                &self.project,
                "--filter",
                &filter,
                "--format",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "gcloud compute instances list failed: {stderr}"
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let mut machines = Vec::new();

        if let Some(instances) = json.as_array() {
            for instance in instances {
                let private_ip = instance["networkInterfaces"]
                    .as_array()
                    .and_then(|nics| nics.first())
                    .and_then(|nic| nic["networkIP"].as_str())
                    .map(|s| s.to_string());

                let public_ip = instance["networkInterfaces"]
                    .as_array()
                    .and_then(|nics| nics.first())
                    .and_then(|nic| nic["accessConfigs"].as_array())
                    .and_then(|acs| acs.first())
                    .and_then(|ac| ac["natIP"].as_str())
                    .map(|s| s.to_string());

                machines.push(MachineInstance {
                    instance_id: instance["name"].as_str().unwrap_or("").to_string(),
                    provider: "gcp".to_string(),
                    state: MachineState::Running,
                    public_ip,
                    private_ip,
                    labels: HashMap::new(),
                    pool: pool.to_string(),
                    created_at: 0,
                });
            }
        }

        Ok(machines)
    }
}
