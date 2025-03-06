use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use tokio::signal;
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, short)]
    interface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(err) => {
            let _ = err.print();
            return Err(err.into());
        }
    };

    tracing_subscriber::fmt::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nat-xdp"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = ebpf.program_mut("nat_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    info!("XDP program attached");

    let ctrl_c = signal::ctrl_c();
    eprintln!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    eprintln!("Exiting...");

    Ok(())
}
