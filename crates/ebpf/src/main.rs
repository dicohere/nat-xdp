#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv6Hdr,
};

#[xdp]
pub fn nat_xdp(ctx: XdpContext) -> u32 {
    match try_nat_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_nat_xdp(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "received a packet");
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv6 => {}
        _ => {
            debug!(&ctx, "passing non-IPv6 packet");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let ipv6_hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        error!(ctx, "packet too small");
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
