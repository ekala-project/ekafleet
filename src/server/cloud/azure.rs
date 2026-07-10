#![allow(dead_code)]

use std::collections::HashMap;

use crate::config::CloudProviderConfig;
use crate::server::scaling::{CloudProvider, CreateMachineRequest, MachineInstance, MachineState};

/// Azure Compute cloud provider. Uses the `az` CLI for all operations.
pub struct AzureCloudProvider {
    location: String,
    resource_group: String,
}

impl AzureCloudProvider {
    pub fn new(config: &CloudProviderConfig) -> Self {
        Self {
            location: config.region.clone(),
            resource_group: config
                .resource_group
                .clone()
                .unwrap_or_else(|| "ekafleet".to_string()),
        }
    }

    fn now_epoch() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Generate a unique VM name from fleet/pool context.
    fn vm_name(fleet_name: &str, pool: &str) -> String {
        let suffix: u32 = rand_u32();
        format!("{fleet_name}-{pool}-{suffix:08x}")
    }
}

/// Simple random u32 using the system clock as entropy (good enough for VM names).
fn rand_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

impl CloudProvider for AzureCloudProvider {
    async fn create_machine(
        &self,
        request: &CreateMachineRequest,
    ) -> Result<MachineInstance, anyhow::Error> {
        let vm_name = Self::vm_name(&request.fleet_name, &request.pool);

        // Write user-data to a temp file (az vm create reads from file)
        let ud_path = format!("/tmp/ekafleet-ud-{vm_name}.sh");
        tokio::fs::write(&ud_path, &request.user_data).await?;

        let mut args = vec![
            "vm".to_string(),
            "create".to_string(),
            "--resource-group".to_string(),
            self.resource_group.clone(),
            "--name".to_string(),
            vm_name.clone(),
            "--image".to_string(),
            request.image_id.clone(),
            "--size".to_string(),
            request.instance_type.clone(),
            "--location".to_string(),
            request.region.clone(),
            "--custom-data".to_string(),
            ud_path.clone(),
            "--output".to_string(),
            "json".to_string(),
        ];

        // SSH key
        if let Some(key) = &request.ssh_key_name {
            args.extend(["--ssh-key-name".to_string(), key.clone()]);
        }

        // Disk size
        if let Some(disk_gb) = request.disk_size_gb {
            args.extend([
                "--os-disk-size-gb".to_string(),
                disk_gb.to_string(),
            ]);
        }

        // Subnet
        if let Some(subnet) = &request.subnet_id {
            args.extend(["--subnet".to_string(), subnet.clone()]);
        }

        // Tags
        args.push("--tags".to_string());
        args.push(format!("ekafleet={}", request.fleet_name));
        args.push(format!("pool={}", request.pool));
        args.push("managed-by=ekafleet".to_string());

        tracing::info!(
            location = %request.region,
            size = %request.instance_type,
            image = %request.image_id,
            pool = %request.pool,
            vm_name = %vm_name,
            "Creating Azure VM"
        );

        let output = tokio::process::Command::new("az")
            .args(&args)
            .output()
            .await?;

        // Clean up temp file
        let _ = tokio::fs::remove_file(&ud_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("az vm create failed: {stderr}"));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

        let instance_id = json["id"]
            .as_str()
            .unwrap_or(&vm_name)
            .to_string();
        let private_ip = json["privateIpAddress"]
            .as_str()
            .map(|s| s.to_string());
        let public_ip = json["publicIpAddress"]
            .as_str()
            .map(|s| s.to_string());

        tracing::info!(
            vm_name = %vm_name,
            private_ip = ?private_ip,
            "Azure VM created"
        );

        Ok(MachineInstance {
            instance_id,
            provider: "azure".to_string(),
            state: MachineState::Running,
            public_ip,
            private_ip,
            labels: request.labels.clone(),
            pool: request.pool.clone(),
            created_at: Self::now_epoch(),
        })
    }

    async fn destroy_machine(&self, instance_id: &str) -> Result<(), anyhow::Error> {
        // instance_id for Azure is either the full resource ID or the VM name.
        // Extract the VM name from a resource ID if needed.
        let vm_name = instance_id
            .rsplit('/')
            .next()
            .unwrap_or(instance_id);

        tracing::info!(
            vm_name,
            resource_group = %self.resource_group,
            "Deleting Azure VM"
        );

        let output = tokio::process::Command::new("az")
            .args([
                "vm",
                "delete",
                "--resource-group",
                &self.resource_group,
                "--name",
                vm_name,
                "--yes",
                "--output",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("az vm delete failed: {stderr}"));
        }

        Ok(())
    }

    async fn describe_machine(
        &self,
        instance_id: &str,
    ) -> Result<Option<MachineInstance>, anyhow::Error> {
        let vm_name = instance_id
            .rsplit('/')
            .next()
            .unwrap_or(instance_id);

        let output = tokio::process::Command::new("az")
            .args([
                "vm",
                "show",
                "--resource-group",
                &self.resource_group,
                "--name",
                vm_name,
                "--show-details",
                "--output",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("ResourceNotFound") || stderr.contains("not found") {
                return Ok(None);
            }
            return Err(anyhow::anyhow!("az vm show failed: {stderr}"));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

        let state = match json["powerState"].as_str() {
            Some("VM running") => MachineState::Running,
            Some("VM starting") => MachineState::Pending,
            Some("VM stopping") | Some("VM deallocating") => MachineState::Stopping,
            Some("VM stopped") | Some("VM deallocated") => MachineState::Terminated,
            _ => MachineState::Unknown,
        };

        let mut labels = HashMap::new();
        let mut pool = String::new();
        if let Some(tags) = json["tags"].as_object() {
            for (key, value) in tags {
                if key == "pool" {
                    pool = value.as_str().unwrap_or("").to_string();
                } else {
                    labels.insert(
                        key.clone(),
                        value.as_str().unwrap_or("").to_string(),
                    );
                }
            }
        }

        Ok(Some(MachineInstance {
            instance_id: json["id"]
                .as_str()
                .unwrap_or(instance_id)
                .to_string(),
            provider: "azure".to_string(),
            state,
            public_ip: json["publicIps"].as_str().map(|s| s.to_string()),
            private_ip: json["privateIps"].as_str().map(|s| s.to_string()),
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
        let query = format!(
            "[?tags.ekafleet=='{fleet_name}' && tags.pool=='{pool}']"
        );

        let output = tokio::process::Command::new("az")
            .args([
                "vm",
                "list",
                "--resource-group",
                &self.resource_group,
                "--show-details",
                "--query",
                &query,
                "--output",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("az vm list failed: {stderr}"));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let mut machines = Vec::new();

        if let Some(vms) = json.as_array() {
            for vm in vms {
                let state = match vm["powerState"].as_str() {
                    Some("VM running") => MachineState::Running,
                    Some("VM starting") => MachineState::Pending,
                    _ => continue,
                };

                machines.push(MachineInstance {
                    instance_id: vm["id"].as_str().unwrap_or("").to_string(),
                    provider: "azure".to_string(),
                    state,
                    public_ip: vm["publicIps"].as_str().map(|s| s.to_string()),
                    private_ip: vm["privateIps"].as_str().map(|s| s.to_string()),
                    labels: HashMap::new(),
                    pool: pool.to_string(),
                    created_at: 0,
                });
            }
        }

        Ok(machines)
    }
}
