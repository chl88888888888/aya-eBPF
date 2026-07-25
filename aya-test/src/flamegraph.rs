//! Flame graph SVG generation from collected stack samples.
//!
//! Collapses [`StackEvent`] samples into folded format and renders an
//! SVG flame graph using the [`inferno`] crate.

use crate::symbolizer::Symbolizer;
use aya_test_common::{StackEvent, MAX_STACK_FRAMES};
use log::info;
use std::collections::HashMap;

/// Generates an SVG flame graph from collected [`StackEvent`] samples.
pub fn generate_flamegraph_svg(
    samples: &[StackEvent],
    output_path: &str,
) -> anyhow::Result<()> {
    if samples.is_empty() {
        info!("No stack samples collected — skipping flame graph");
        return Ok(());
    }

    let pid = samples[0].pid;
    let mut sym = Symbolizer::new(pid);

    // Collapse into folded format: "frame1;frame2;... count"
    let mut folded: HashMap<String, u64> = HashMap::new();

    for ev in samples {
        let klen = (ev.kstack_len.max(0) as usize).min(MAX_STACK_FRAMES);
        let ulen = (ev.ustack_len.max(0) as usize).min(MAX_STACK_FRAMES);

        // Single allocation — kernel + user frames in reverse (deepest first).
        let mut frames = Vec::with_capacity(klen + ulen);
        for &ip in ev.kstack_ips[..klen].iter().rev() {
            if ip != 0 {
                frames.push(sym.resolve_kernel(ip));
            }
        }
        for &ip in ev.ustack_ips[..ulen].iter().rev() {
            if ip != 0 {
                frames.push(sym.resolve(ip));
            }
        }

        if frames.is_empty() {
            continue;
        }

        let key = frames.join(";");
        *folded.entry(key).or_default() += 1;
    }

    // Serialise folded stacks
    let folded_buf: String = folded
        .iter()
        .map(|(stack, count)| format!("{} {}\n", stack, count))
        .collect();

    // Render SVG via inferno
    let mut svg = Vec::new();
    let mut opts = inferno::flamegraph::Options::default();
    opts.title = format!(
        "Redis CPU Flame Graph (PID {}, {} samples)",
        pid,
        samples.len()
    );
    if let Ok(palette) = "java".parse::<inferno::flamegraph::Palette>() {
        opts.colors = palette;
    }
    opts.count_name = "samples".to_string();

    inferno::flamegraph::from_reader(&mut opts, folded_buf.as_bytes(), &mut svg)?;

    std::fs::write(output_path, &svg)?;
    info!(
        "Flame graph written to {} ({} unique stacks from {} samples)",
        output_path,
        folded.len(),
        samples.len()
    );

    Ok(())
}
