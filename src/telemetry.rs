use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io, pin::Pin};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::account::UserId;
use crate::async_stream::{AsyncPing, AsyncStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficDelta {
    pub user_id: UserId,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub opened_connections: u64,
    pub active_connections: u64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Default)]
struct UserTrafficCounters {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    opened_connections: AtomicU64,
    active_connections: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct TrafficCollector {
    counters: Arc<DashMap<UserId, Arc<UserTrafficCounters>>>,
}

impl TrafficCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, user_id: impl AsRef<str>, direction: TrafficDirection, bytes: u64) {
        if bytes == 0 {
            return;
        }

        let counters = self.counters_for(user_id.as_ref());
        match direction {
            TrafficDirection::Upload => {
                counters.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            TrafficDirection::Download => {
                counters.download_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    pub fn record_upload(&self, user_id: impl AsRef<str>, bytes: u64) {
        self.record(user_id, TrafficDirection::Upload, bytes);
    }

    pub fn record_download(&self, user_id: impl AsRef<str>, bytes: u64) {
        self.record(user_id, TrafficDirection::Download, bytes);
    }

    pub fn record_connection_open(&self, user_id: impl AsRef<str>) {
        let counters = self.counters_for(user_id.as_ref());
        counters.opened_connections.fetch_add(1, Ordering::Relaxed);
        counters.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_close(&self, user_id: impl AsRef<str>) {
        let counters = self.counters_for(user_id.as_ref());
        decrement_saturating(&counters.active_connections);
    }

    pub fn connection_guard(&self, user_id: impl Into<UserId>) -> TrafficConnectionGuard {
        let user_id = user_id.into();
        self.record_connection_open(&user_id);
        TrafficConnectionGuard {
            collector: self.clone(),
            user_id,
        }
    }

    pub fn snapshot_and_reset(&self) -> Vec<TrafficDelta> {
        let timestamp_ms = now_millis();
        let mut deltas = Vec::new();

        for entry in self.counters.iter() {
            let counters = entry.value();
            let upload_bytes = counters.upload_bytes.swap(0, Ordering::AcqRel);
            let download_bytes = counters.download_bytes.swap(0, Ordering::AcqRel);
            let opened_connections = counters.opened_connections.swap(0, Ordering::AcqRel);
            let active_connections = counters.active_connections.load(Ordering::Acquire);

            if upload_bytes == 0
                && download_bytes == 0
                && opened_connections == 0
                && active_connections == 0
            {
                continue;
            }

            deltas.push(TrafficDelta {
                user_id: entry.key().clone(),
                upload_bytes,
                download_bytes,
                opened_connections,
                active_connections,
                timestamp_ms,
            });
        }

        deltas
    }

    fn counters_for(&self, user_id: &str) -> Arc<UserTrafficCounters> {
        self.counters
            .entry(user_id.to_string())
            .or_insert_with(|| Arc::new(UserTrafficCounters::default()))
            .clone()
    }
}

#[derive(Debug)]
pub struct TrafficConnectionGuard {
    collector: TrafficCollector,
    user_id: UserId,
}

impl Drop for TrafficConnectionGuard {
    fn drop(&mut self) {
        self.collector.record_connection_close(&self.user_id);
    }
}

pub(crate) struct MeteredStream<S> {
    inner: S,
    user_id: UserId,
    collector: TrafficCollector,
    read_direction: TrafficDirection,
    write_direction: TrafficDirection,
}

impl<S> MeteredStream<S> {
    pub(crate) fn new(
        inner: S,
        user_id: UserId,
        collector: TrafficCollector,
        read_direction: TrafficDirection,
        write_direction: TrafficDirection,
    ) -> Self {
        Self {
            inner,
            user_id,
            collector,
            read_direction,
            write_direction,
        }
    }
}

impl<S> AsyncRead for MeteredStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let read = buf.filled().len().saturating_sub(before);
            if read > 0 {
                self.collector
                    .record(&self.user_id, self.read_direction, read as u64);
            }
        }
        poll
    }
}

impl<S> AsyncWrite for MeteredStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &poll
            && *written > 0
        {
            self.collector
                .record(&self.user_id, self.write_direction, *written as u64);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> AsyncPing for MeteredStream<S>
where
    S: AsyncPing + Unpin,
{
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S> AsyncStream for MeteredStream<S> where S: AsyncStream + Unpin + Send + Sync {}

fn decrement_saturating(value: &AtomicU64) {
    let mut current = value.load(Ordering::Relaxed);
    while current > 0 {
        match value.compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Relaxed)
        {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_returns_deltas_and_resets_byte_counters() {
        let collector = TrafficCollector::new();
        collector.record_upload("u1", 10);
        collector.record_download("u1", 20);
        collector.record_connection_open("u1");

        let deltas = collector.snapshot_and_reset();
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].upload_bytes, 10);
        assert_eq!(deltas[0].download_bytes, 20);
        assert_eq!(deltas[0].opened_connections, 1);
        assert_eq!(deltas[0].active_connections, 1);

        let deltas = collector.snapshot_and_reset();
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].upload_bytes, 0);
        assert_eq!(deltas[0].download_bytes, 0);
        assert_eq!(deltas[0].opened_connections, 0);
        assert_eq!(deltas[0].active_connections, 1);
    }

    #[test]
    fn connection_close_is_saturating() {
        let collector = TrafficCollector::new();
        collector.record_connection_close("u1");
        assert!(collector.snapshot_and_reset().is_empty());
    }
}
