//! Transport layer: newline-delimited JSON-RPC over stdio.
//!
//! One line in = one JSON-RPC frame. Responses are written back as a
//! single line each. Everything else — tracing, warnings — goes to
//! stderr so the stdout channel stays protocol-clean.

use std::io::Write;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::task::JoinSet;

use crate::protocol::JsonRpcMessage;
use crate::server::McpServer;

/// Run the server loop against stdin/stdout until EOF.
///
/// Each request is handled on its own task so a slow tool can't block
/// subsequent frames, but on EOF we await every in-flight task before
/// returning. Without the join at the end, piping a finite stdin would
/// drop the runtime while response writes are still pending and the
/// client would see a truncated stdout stream.
pub async fn stdio_loop(server: Arc<McpServer>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let mut reader = BufReader::new(stdin).lines();
    let mut tasks: JoinSet<()> = JoinSet::new();
    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let server = server.clone();
        let stdout = stdout.clone();
        let msg = JsonRpcMessage::parse(&line);
        tasks.spawn(async move {
            if let Some(resp) = server.handle(msg).await {
                let data = match serde_json::to_string(&resp) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to serialize response");
                        return;
                    }
                };
                let mut out = stdout.lock().await;
                if let Err(e) = write_frame(&mut *out, &data).await {
                    tracing::error!(error = %e, "stdout write failed");
                }
            }
        });
    }
    // Stdin reached EOF — drain pending responses so nothing gets cut off.
    while let Some(res) = tasks.join_next().await {
        if let Err(e) = res {
            tracing::warn!(error = %e, "mcp task join failed");
        }
    }
    // Final flush to be defensive against buffered writes.
    let mut out = stdout.lock().await;
    let _ = out.flush().await;
    Ok(())
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, line: &str) -> Result<()> {
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await?;
    Ok(())
}

/// Blocking variant for environments without a tokio runtime (unused by
/// the CLI entry-point, kept here for ad-hoc scripts).
pub fn stdio_loop_blocking(server: &McpServer) -> Result<()> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg = JsonRpcMessage::parse(&line);
        if let Some(resp) = rt.block_on(server.handle(msg)) {
            let data = serde_json::to_string(&resp)?;
            writeln!(stdout, "{data}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
