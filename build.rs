fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/fleet.proto")?;
    tonic_build::compile_protos("proto/workload.proto")?;
    Ok(())
}
