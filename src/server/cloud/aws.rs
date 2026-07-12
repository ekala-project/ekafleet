#![allow(dead_code)]

use std::collections::HashMap;

use crate::config::CloudProviderConfig;
use crate::server::scaling::{CloudProvider, CreateMachineRequest, MachineInstance, MachineState};

/// AWS EC2 cloud provider. Uses the `aws` CLI for all operations.
pub struct AwsCloudProvider {
    region: String,
}

impl AwsCloudProvider {
    pub fn new(config: &CloudProviderConfig) -> Self {
        Self {
            region: config.region.clone(),
        }
    }

    fn now_epoch() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl CloudProvider for AwsCloudProvider {
    async fn create_machine(
        &self,
        request: &CreateMachineRequest,
    ) -> Result<MachineInstance, anyhow::Error> {
        let mut args = vec![
            "ec2".to_string(),
            "run-instances".to_string(),
            "--region".to_string(),
            request.region.clone(),
            "--image-id".to_string(),
            request.image_id.clone(),
            "--instance-type".to_string(),
            request.instance_type.clone(),
            "--count".to_string(),
            "1".to_string(),
            "--output".to_string(),
            "json".to_string(),
        ];

        // User-data (base64-encoded bootstrap script)
        let encoded = super::bootstrap::encode_user_data(&request.user_data);
        args.extend(["--user-data".to_string(), encoded]);

        // Subnet
        if let Some(subnet) = &request.subnet_id {
            args.extend(["--subnet-id".to_string(), subnet.clone()]);
        }

        // Security groups
        if !request.security_group_ids.is_empty() {
            args.push("--security-group-ids".to_string());
            args.extend(request.security_group_ids.clone());
        }

        // SSH key
        if let Some(key) = &request.ssh_key_name {
            args.extend(["--key-name".to_string(), key.clone()]);
        }

        // Root volume size
        if let Some(disk_gb) = request.disk_size_gb {
            let block_mapping =
                format!("[{{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{{\"VolumeSize\":{disk_gb}}}}}]");
            args.extend(["--block-device-mappings".to_string(), block_mapping]);
        }

        // Tags
        let tag_spec = format!(
            "ResourceType=instance,Tags=[{{Key=ekafleet,Value={fleet}}},{{Key=pool,Value={pool}}},{{Key=managed-by,Value=ekafleet}}]",
            fleet = request.fleet_name,
            pool = request.pool,
        );
        args.extend(["--tag-specifications".to_string(), tag_spec]);

        tracing::info!(
            region = %request.region,
            instance_type = %request.instance_type,
            image = %request.image_id,
            pool = %request.pool,
            "Creating AWS EC2 instance"
        );

        let output = tokio::process::Command::new("aws")
            .args(&args)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("aws ec2 run-instances failed: {stderr}"));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let instance = &json["Instances"][0];

        let instance_id = instance["InstanceId"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let private_ip = instance["PrivateIpAddress"].as_str().map(|s| s.to_string());
        let public_ip = instance["PublicIpAddress"].as_str().map(|s| s.to_string());

        tracing::info!(
            instance_id = %instance_id,
            private_ip = ?private_ip,
            "AWS EC2 instance created"
        );

        Ok(MachineInstance {
            instance_id,
            provider: "aws".to_string(),
            state: MachineState::Pending,
            public_ip,
            private_ip,
            labels: request.labels.clone(),
            pool: request.pool.clone(),
            created_at: Self::now_epoch(),
        })
    }

    async fn destroy_machine(&self, instance_id: &str) -> Result<(), anyhow::Error> {
        tracing::info!(instance_id, region = %self.region, "Terminating AWS EC2 instance");

        let output = tokio::process::Command::new("aws")
            .args([
                "ec2",
                "terminate-instances",
                "--region",
                &self.region,
                "--instance-ids",
                instance_id,
                "--output",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "aws ec2 terminate-instances failed: {stderr}"
            ));
        }

        Ok(())
    }

    async fn describe_machine(
        &self,
        instance_id: &str,
    ) -> Result<Option<MachineInstance>, anyhow::Error> {
        let output = tokio::process::Command::new("aws")
            .args([
                "ec2",
                "describe-instances",
                "--region",
                &self.region,
                "--instance-ids",
                instance_id,
                "--output",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Instance not found is not an error — return None
            if stderr.contains("InvalidInstanceID") {
                return Ok(None);
            }
            return Err(anyhow::anyhow!(
                "aws ec2 describe-instances failed: {stderr}"
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let reservations = json["Reservations"].as_array();

        let instance = reservations
            .and_then(|r| r.first())
            .and_then(|r| r["Instances"].as_array())
            .and_then(|i| i.first());

        let Some(instance) = instance else {
            return Ok(None);
        };

        let state = match instance["State"]["Name"].as_str() {
            Some("pending") => MachineState::Pending,
            Some("running") => MachineState::Running,
            Some("shutting-down") | Some("stopping") => MachineState::Stopping,
            Some("terminated") | Some("stopped") => MachineState::Terminated,
            _ => MachineState::Unknown,
        };

        // Extract pool and fleet from tags
        let tags = instance["Tags"].as_array();
        let mut labels = HashMap::new();
        let mut pool = String::new();
        if let Some(tags) = tags {
            for tag in tags {
                let key = tag["Key"].as_str().unwrap_or("");
                let value = tag["Value"].as_str().unwrap_or("");
                if key == "pool" {
                    pool = value.to_string();
                } else {
                    labels.insert(key.to_string(), value.to_string());
                }
            }
        }

        Ok(Some(MachineInstance {
            instance_id: instance["InstanceId"].as_str().unwrap_or("").to_string(),
            provider: "aws".to_string(),
            state,
            public_ip: instance["PublicIpAddress"].as_str().map(|s| s.to_string()),
            private_ip: instance["PrivateIpAddress"].as_str().map(|s| s.to_string()),
            labels,
            pool,
            created_at: 0, // Not easily available from describe
        }))
    }

    async fn list_fleet_machines(
        &self,
        fleet_name: &str,
        pool: &str,
    ) -> Result<Vec<MachineInstance>, anyhow::Error> {
        let fleet_filter = format!("Name=tag:ekafleet,Values={fleet_name}");
        let pool_filter = format!("Name=tag:pool,Values={pool}");
        let state_filter = "Name=instance-state-name,Values=pending,running".to_string();

        let output = tokio::process::Command::new("aws")
            .args([
                "ec2",
                "describe-instances",
                "--region",
                &self.region,
                "--filters",
                &fleet_filter,
                &pool_filter,
                &state_filter,
                "--output",
                "json",
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "aws ec2 describe-instances (list) failed: {stderr}"
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let mut machines = Vec::new();

        if let Some(reservations) = json["Reservations"].as_array() {
            for reservation in reservations {
                if let Some(instances) = reservation["Instances"].as_array() {
                    for instance in instances {
                        let state = match instance["State"]["Name"].as_str() {
                            Some("pending") => MachineState::Pending,
                            Some("running") => MachineState::Running,
                            _ => continue, // Skip terminated/stopping
                        };

                        machines.push(MachineInstance {
                            instance_id: instance["InstanceId"].as_str().unwrap_or("").to_string(),
                            provider: "aws".to_string(),
                            state,
                            public_ip: instance["PublicIpAddress"].as_str().map(|s| s.to_string()),
                            private_ip: instance["PrivateIpAddress"]
                                .as_str()
                                .map(|s| s.to_string()),
                            labels: HashMap::new(),
                            pool: pool.to_string(),
                            created_at: 0,
                        });
                    }
                }
            }
        }

        Ok(machines)
    }
}
