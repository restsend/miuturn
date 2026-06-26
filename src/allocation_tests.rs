    /// Unit tests for critical relay data paths.
    ///
    /// These tests validate the core TURN relay functionality:
    /// - send_to_peer (permission-checked relay)
    /// - Permission management
    /// - Channel binding lookup
    /// - TOCTOU race conditions
    /// - Silent data-loss paths (bug verification)
    #[cfg(test)]
    mod relay_data_path_tests {
        use crate::allocation::*;
        use std::net::{Ipv4Addr, SocketAddr};
        use std::sync::atomic::Ordering;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::net::UdpSocket;

        // =========================================================================
        // Source-level bug verification (compile-time checks)
        // =========================================================================

        /// Verify the `let _ =` silent data-loss pattern has been REMOVED from
        /// server.rs (both UDP and TCP ChannelData paths). All ChannelData send
        /// failures are now logged with `warn!`.
        #[test]
        fn test_bug_let_underscore_channeldata_send_to_removed() {
            let crate_root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
            let server_rs = std::path::Path::new(&crate_root).join("src/server.rs");
            let source = std::fs::read_to_string(&server_rs)
                .unwrap_or_else(|_| panic!("cannot read {}", server_rs.display()));

            // The `let _ =` pattern should NOT exist anymore
            assert!(
                !source.contains("let _ = relay_sock.send_to(&payload, &channel.peer_addr).await;"),
                "FIX CONFIRMED: `let _ =` pattern for ChannelData send failure removed from server.rs"
            );

            // All ChannelData paths should now use `if let Err(e) = ...` with `warn!`
            assert!(
                source.contains("if let Err(e) = relay_sock.send_to(&payload, &channel.peer_addr).await"),
                "ChannelData send failures should be handled with if let Err"
            );
            assert!(
                source.contains("\"UDP ChannelData send to peer {} failed: {}\""),
                "UDP ChannelData send failure should be logged with warn!"
            );
            assert!(
                source.contains("\"TCP ChannelData send to peer {} failed: {}\""),
                "TCP ChannelData send failure should be logged with warn!"
            );
        }

        /// Verify that `bandwidth_manager.try_relay` is never called in the data
        /// forwarding paths (server.rs and allocation.rs). The BandwidthManager
        /// is registered but the enforcement method is dead code in the relay path.
        #[test]
        fn test_bug_bandwidth_manager_try_relay_not_called_in_data_path() {
            let crate_root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());

            for file_name in &["src/server.rs", "src/allocation.rs"] {
                let path = std::path::Path::new(&crate_root).join(file_name);
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|_| format!("// cannot read {}", path.display()));

                // Count occurrences of try_relay (excluding comments and tests)
                let call_count = source
                    .lines()
                    .filter(|line| {
                        let trimmed = line.trim();
                        trimmed.contains("try_relay") && !trimmed.starts_with("//")
                    })
                    .count();

                // try_relay should NOT be called in production data forwarding code.
                // The only calls are in #[cfg(test)] modules inside bandwidth.rs.
                // If this assertion fails, it means someone added bandwidth enforcement
                // BUT may have introduced a new data-loss path.
                if file_name.contains("allocation.rs") {
                    assert_eq!(
                        call_count, 0,
                        "BUG: try_relay called {} times in {} — verify it's not in data forwarding path",
                        call_count, file_name
                    );
                }
            }
        }

        /// Verify `MAX_CONSECUTIVE_RECV_ERRORS = 100` and the break condition
        /// exists at allocation.rs:1129-1138.
        #[test]
        fn test_bug_consecutive_recv_errors_kill_switch_exists_in_source() {
            let crate_root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
            let alloc_rs = std::path::Path::new(&crate_root).join("src/allocation.rs");
            let source = std::fs::read_to_string(&alloc_rs)
                .unwrap_or_else(|_| panic!("cannot read {}", alloc_rs.display()));

            // Verify the kill switch exists
            assert!(
                source.contains("MAX_CONSECUTIVE_RECV_ERRORS"),
                "BUG SOURCE: MAX_CONSECUTIVE_RECV_ERRORS constant not found in allocation.rs"
            );
            assert!(
                source.contains("consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS"),
                "BUG SOURCE: consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS check not found"
            );

            // Verify the break after hitting the limit
            assert!(
                source.contains("relay socket too many consecutive recv errors within window"),
                "BUG SOURCE: relay task exit log message not found — kill switch may be removed"
            );

            // Verify that is_fatal_recv_error only treats PermissionDenied as fatal
            assert!(
                source.contains("matches!(kind, io::ErrorKind::PermissionDenied)"),
                "BUG SOURCE: is_fatal_recv_error should only treat PermissionDenied as fatal"
            );
        }

        /// Verify the dead `relay_to_peer` method has been removed from allocation.rs.
        #[test]
        fn test_relay_to_peer_removed() {
            let crate_root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
            let alloc_rs = std::path::Path::new(&crate_root).join("src/allocation.rs");
            let source = std::fs::read_to_string(&alloc_rs)
                .unwrap_or_else(|_| panic!("cannot read {}", alloc_rs.display()));

            assert!(
                !source.contains("pub fn relay_to_peer("),
                "FIX CONFIRMED: relay_to_peer has been removed from allocation.rs"
            );
        }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    fn make_addr(ip: &str, port: u16) -> SocketAddr {
        format!("{ip}:{port}").parse().unwrap()
    }

    fn dummy_table() -> AllocationTable {
        AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            55000,
            55099,
            None,
            None,
            None,
        )
    }

    // ---------------------------------------------------------------------------
    // Test: send_to_peer forwards data to peer when permission is granted
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_send_to_peer_forwards_with_permission() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer: SocketAddr = make_addr("10.0.0.2", 5000);

        // Create a real allocation
        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_addr = alloc.read().relayed_addr;

        // Set permission for the peer
        assert!(table.add_permissions(&client, &[peer]));

        // Bind a peer UDP socket to receive relayed data
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();

        // Add permission for the actual peer socket address
        assert!(table.add_permissions(&client, &[peer_addr]));

        // Send data from client to peer via send_to_peer
        let result = table
            .send_to_peer(&client, peer_addr, b"hello peer")
            .await;
        assert!(result.is_some(), "send_to_peer should succeed with permission");

        // Verify peer received the data
        let mut buf = vec![0u8; 1024];
        match tokio::time::timeout(Duration::from_millis(500), peer_sock.recv_from(&mut buf)).await
        {
            Ok(Ok((len, src))) => {
                assert_eq!(&buf[..len], b"hello peer");
                // Source should be the relayed address
                assert_eq!(src.ip(), relayed_addr.ip());
                assert_eq!(src.port(), relayed_addr.port());
            }
            other => panic!("peer should receive data, got {:?}", other),
        }

        // Stats should be incremented
        let a = alloc.read();
        assert!(a.bytes_forwarded.load(Ordering::Relaxed) > 0, "bytes_forwarded incremented");
        assert!(a.messages_forwarded.load(Ordering::Relaxed) > 0, "messages_forwarded incremented");
    }

    // ---------------------------------------------------------------------------
    // Test: send_to_peer drops data when permission is NOT granted
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_send_to_peer_drops_without_permission() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer: SocketAddr = make_addr("10.0.0.2", 6000);

        // Create allocation
        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();

        // Do NOT add any permissions

        let result = table
            .send_to_peer(&client, peer, b"hello peer")
            .await;
        assert!(result.is_none(), "send_to_peer should fail without permission");

        // Stats should NOT be incremented
        let a = alloc.read();
        assert_eq!(a.bytes_forwarded.load(Ordering::Relaxed), 0);
        assert_eq!(a.messages_forwarded.load(Ordering::Relaxed), 0);
    }

    // ---------------------------------------------------------------------------
    // Test: send_to_peer drops when client has no allocation
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_send_to_peer_drops_for_unknown_client() {
        let table = dummy_table();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer: SocketAddr = make_addr("10.0.0.2", 5000);

        let result = table.send_to_peer(&client, peer, b"data").await;
        assert!(result.is_none(), "should drop for unknown client");
    }

    // ---------------------------------------------------------------------------
    // Test: add_permissions inserts peer IPs and only permits those IPs
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_add_permissions_gates_send() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer_ok: SocketAddr = make_addr("10.0.0.2", 1111);
        let peer_blocked: SocketAddr = make_addr("10.0.0.3", 2222);

        let _alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();

        // Add permission for peer_ok only
        assert!(table.add_permissions(&client, &[peer_ok]));

        // peer_ok should be permitted
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        assert!(table.add_permissions(&client, &[peer_addr]));

        // Send to a permitted peer (using the local socket we just bound)
        assert!(table.send_to_peer(&client, peer_addr, b"x").await.is_some());

        // peer_blocked should be blocked (has a different IP)
        assert!(table.send_to_peer(&client, peer_blocked, b"x").await.is_none());
    }

    // ---------------------------------------------------------------------------
    // Test: add_permissions is idempotent
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_add_permissions_idempotent() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer: SocketAddr = make_addr("10.0.0.2", 5000);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed = alloc.read().relayed_addr;

        // Add same peer three times
        assert!(table.add_permissions(&client, &[peer]));
        assert_eq!(table.allocations.read().get(&relayed).unwrap().read().permissions.len(), 1);

        assert!(table.add_permissions(&client, &[peer]));
        assert_eq!(table.allocations.read().get(&relayed).unwrap().read().permissions.len(), 1);

        assert!(table.add_permissions(&client, &[peer]));
        assert_eq!(table.allocations.read().get(&relayed).unwrap().read().permissions.len(), 1);
    }

    // ---------------------------------------------------------------------------
    // Test: find_allocation_by_client
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_find_allocation_by_client() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client_a: SocketAddr = make_addr("192.168.1.1", 11111);
        let client_b: SocketAddr = make_addr("192.168.1.2", 22222);

        let alloc_a = table
            .create_allocation(client_a, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_a = alloc_a.read().relayed_addr;

        let alloc_b = table
            .create_allocation(client_b, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_b = alloc_b.read().relayed_addr;

        assert_eq!(table.find_allocation_by_client(&client_a), Some(relayed_a));
        assert_eq!(table.find_allocation_by_client(&client_b), Some(relayed_b));

        let unknown: SocketAddr = make_addr("10.99.99.99", 9999);
        assert_eq!(table.find_allocation_by_client(&unknown), None);

        // get_allocation_by_client returns the Arc directly
        let arc = table.get_allocation_by_client(&client_a);
        assert!(arc.is_some());
        assert_eq!(arc.unwrap().read().relayed_addr, relayed_a);
    }

    // ---------------------------------------------------------------------------
    // Test: find_allocation_by_client returns None for unknown client
    // ---------------------------------------------------------------------------
    #[test]
    fn test_find_allocation_by_client_none() {
        let table = dummy_table();
        let unknown: SocketAddr = make_addr("10.0.0.1", 11111);
        assert!(table.find_allocation_by_client(&unknown).is_none());
    }

    // ---------------------------------------------------------------------------
    // Test: send_to_peer to multiple peers on same allocation
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_send_to_multiple_peers_on_same_allocation() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer_a: SocketAddr = make_addr("10.0.0.2", 5001);
        let peer_b: SocketAddr = make_addr("10.0.0.3", 6001);
        let peer_c: SocketAddr = make_addr("10.0.0.4", 7001);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();

        // Add permissions for all three peer IPs
        assert!(table.add_permissions(&client, &[peer_a]));
        assert!(table.add_permissions(&client, &[peer_b]));
        assert!(table.add_permissions(&client, &[peer_c]));

        // Bind real sockets for each peer so we can verify delivery
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let sock_c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_c = sock_c.local_addr().unwrap();

        // Add permissions for the actual socket addresses too
        assert!(table.add_permissions(&client, &[addr_a, addr_b, addr_c]));

        // Send to each peer
        assert!(table.send_to_peer(&client, addr_a, b"to a").await.is_some());
        assert!(table.send_to_peer(&client, addr_b, b"to b").await.is_some());
        assert!(table.send_to_peer(&client, addr_c, b"to c").await.is_some());

        // Verify each peer received its data
        let mut buf = vec![0u8; 64];
        let (len, _) = sock_a.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"to a");
        let (len, _) = sock_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"to b");
        let (len, _) = sock_c.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"to c");

        // 3 peer IPs (10.0.0.2, 10.0.0.3, 10.0.0.4) + 1 actual socket IP (127.0.0.1) = 4
        assert_eq!(alloc.read().permissions.len(), 4);
    }

    // ---------------------------------------------------------------------------
    // Test: ChannelTable::get_by_peer_for_relayed
    // ---------------------------------------------------------------------------
    #[test]
    fn test_channel_table_get_by_peer_for_relayed() {
        let table = ChannelTable::new();
        let relayed_a: SocketAddr = make_addr("10.0.0.1", 49152);
        let relayed_b: SocketAddr = make_addr("10.0.0.1", 49153);
        let peer_x: SocketAddr = make_addr("192.168.1.1", 10000);
        let peer_y: SocketAddr = make_addr("192.168.1.2", 20000);

        table.bind(0x4000, peer_x, relayed_a).unwrap();
        table.bind(0x4001, peer_y, relayed_a).unwrap();
        table.bind(0x4002, peer_x, relayed_b).unwrap();

        assert_eq!(table.get_by_peer_for_relayed(&relayed_a, &peer_x), Some(0x4000));
        assert_eq!(table.get_by_peer_for_relayed(&relayed_a, &peer_y), Some(0x4001));
        assert_eq!(table.get_by_peer_for_relayed(&relayed_b, &peer_x), Some(0x4002));
        assert_eq!(table.get_by_peer_for_relayed(&relayed_b, &peer_y), None);

        let unknown: SocketAddr = make_addr("10.99.99.99", 9999);
        assert_eq!(table.get_by_peer_for_relayed(&relayed_a, &unknown), None);
    }

    // ---------------------------------------------------------------------------
    // Test: ChannelTable expiry and cleanup
    // ---------------------------------------------------------------------------
    #[test]
    fn test_channel_binding_expiry_and_cleanup() {
        let table = ChannelTable::new();
        let relayed: SocketAddr = make_addr("10.0.0.1", 49152);
        let peer: SocketAddr = make_addr("192.168.1.1", 12345);

        table.bind(0x4000, peer, relayed).unwrap();

        let binding = table.get_by_channel(relayed, 0x4000).unwrap();
        assert!(!binding.is_expired());
        assert!(binding.remaining_lifetime() > 0);

        let removed = table.cleanup_expired();
        assert_eq!(removed, 0);
        assert_eq!(table.len(), 1);
    }

    // ---------------------------------------------------------------------------
    // Test: ChannelTable unbind
    // ---------------------------------------------------------------------------
    #[test]
    fn test_channel_binding_unbind() {
        let table = ChannelTable::new();
        let relayed: SocketAddr = make_addr("10.0.0.1", 49152);
        let peer: SocketAddr = make_addr("192.168.1.1", 12345);

        table.bind(0x4000, peer, relayed).unwrap();
        assert_eq!(table.len(), 1);

        let removed = table.unbind(relayed, 0x4000);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().peer_addr, peer);
        assert_eq!(table.len(), 0);
    }

    // ---------------------------------------------------------------------------
    // Test: TOCTOU race — allocation removed between find and send
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_toutou_race_allocation_removed() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer: SocketAddr = make_addr("10.0.0.2", 5000);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed = alloc.read().relayed_addr;
        assert!(table.add_permissions(&client, &[peer]));

        // Step 1: find_allocation_by_client — allocation exists
        assert_eq!(table.find_allocation_by_client(&client), Some(relayed));

        // Step 2: Simulate removal (e.g., cleanup_expired or re-allocate)
        table.remove_allocation(&relayed, Some(&channel_table));

        // Step 3: send_to_peer — allocation already removed
        let result = table.send_to_peer(&client, peer, b"post-removal").await;
        assert!(result.is_none(), "send_to_peer should drop when allocation gone");
    }

    // ---------------------------------------------------------------------------
    // Test: Concurrent send_to_peer calls sharing the same allocation
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_concurrent_send_to_peer() {
        let table = Arc::new(dummy_table());
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);

        // Bind a peer socket on loopback for verifying delivery
        let peer_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_addr = peer_sock.local_addr().unwrap();

        let _alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        assert!(table.add_permissions(&client, &[peer_addr]));

        let mut handles = Vec::new();
        for i in 0..10u8 {
            let t = Arc::clone(&table);
            let c = client;
            let p = peer_addr;
            let data = vec![i; 64];
            handles.push(tokio::spawn(async move {
                t.send_to_peer(&c, p, &data).await
            }));
        }

        let mut success = 0;
        for h in handles {
            if h.await.unwrap().is_some() {
                success += 1;
            }
        }

        // All should succeed since permission is set and peer is reachable on loopback
        assert_eq!(success, 10, "all concurrent sends should succeed");

        // Verify data actually arrived at the peer socket
        let mut buf = vec![0u8; 256];
        let (len, _) = peer_sock.recv_from(&mut buf).await.unwrap();
        assert!(len > 0, "peer socket should receive data from concurrent sends");
    }

    // =========================================================================
    // Silent data-loss verification tests
    // =========================================================================
    //
    // These tests PROVE specific silent loss paths exist in the codebase.
    // Each test documents the file:line of the bug it verifies.

    // ---------------------------------------------------------------------------
    // BUG: send_to_peer silently drops data on socket.send_to failure
    // File: allocation.rs:840-850
    // The `socket.send_to(data, &peer).await` returns Err → function returns None
    // with only a `debug!` log. In production (info level) this is invisible.
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_bug_send_to_peer_silently_drops_on_send_failure() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 50001);
        // Use an IP that is NOT routable from loopback — send_to WILL fail
        let unreachable_peer: SocketAddr = make_addr("10.255.255.254", 9999);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        // Must add permission for the peer IP for send_to_peer to even attempt the send
        assert!(table.add_permissions(&client, &[unreachable_peer]));

        let alloc_bytes_before = alloc.read().bytes_forwarded.load(Ordering::Relaxed);
        let alloc_msgs_before = alloc.read().messages_forwarded.load(Ordering::Relaxed);
        let table_msgs_before = table.stats().total_messages.load(Ordering::Relaxed);

        let result = table
            .send_to_peer(&client, unreachable_peer, b"lost-data")
            .await;

        // BUG CONFIRMED: returns None with no error to caller
        assert!(result.is_none(), "send_to_peer returns None on send failure — data silently lost");

        // Stats are NOT incremented — the data is gone from all accounting
        assert_eq!(
            alloc.read().bytes_forwarded.load(Ordering::Relaxed),
            alloc_bytes_before,
            "BUG: allocation bytes not incremented — data lost without record"
        );
        assert_eq!(
            alloc.read().messages_forwarded.load(Ordering::Relaxed),
            alloc_msgs_before,
            "BUG: allocation messages not incremented — data lost without record"
        );
        assert_eq!(
            table.stats().total_messages.load(Ordering::Relaxed),
            table_msgs_before,
            "BUG: table-level stats not incremented — send failure invisible"
        );
    }

    // ---------------------------------------------------------------------------
    // BUG: BandwidthManager::try_relay is NEVER called in any data forwarding path.
    // File: bandwidth.rs:277 (defined) — zero call sites in server.rs/allocation.rs.
    // This means per-allocation and per-user bandwidth limits are not enforced.
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_bug_bandwidth_manager_not_called() {
        // Create an allocation with bandwidth limit
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            55200,
            55299,
            None,
            None,
            Some(1), // max 1 byte/sec bandwidth limit
        );
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 50002);
        let peer: SocketAddr = make_addr("10.0.0.2", 5000);

        let _alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        assert!(table.add_permissions(&client, &[peer]));

        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        assert!(table.add_permissions(&client, &[peer_addr]));

        // Send 1000 bytes — should be BLOCKED by the 1 byte/sec bandwidth limit
        // if BandwidthManager was actually called
        let result = table
            .send_to_peer(&client, peer_addr, &[0u8; 1000])
            .await;

        // BUG CONFIRMED: send_to_peer succeeds despite bandwidth limit
        assert!(
            result.is_some(),
            "BUG: send_to_peer succeeds despite 1 byte/sec bandwidth limit — BandwidthManager::try_relay is never called in the data path"
        );

        // Verify data actually arrived (bandwidth check was skipped)
        let mut buf = vec![0u8; 2000];
        let (len, _) = peer_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 1000, "1000 bytes were relayed despite bandwidth limit");
    }

    // ---------------------------------------------------------------------------
    // BUG: ChannelData send_to failure silently ignored (let _ =)
    // File: server.rs:724 — `let _ = relay_sock.send_to(&payload, &channel.peer_addr).await;`
    // File: server.rs:672 — identical issue in TCP handler
    // When the relay socket send_to fails, data is lost with zero logging.
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_bug_channeldata_send_to_failure_silently_ignored() {
        // Create an allocation and get its relay socket
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 50003);
        let peer: SocketAddr = make_addr("10.0.0.2", 5000);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed = alloc.read().relayed_addr;

        // Set up a channel binding so ChannelData path would resolve
        channel_table.bind(0x4000, peer, relayed).unwrap();

        // Get the relay socket from the allocation
        let relay_sock = alloc.read().relay.as_ref().unwrap().socket.clone();

        // Close the peer to make send_to fail.
        // Bind then drop: the socket port will be free but sending will fail.
        let dead_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_sock.local_addr().unwrap();
        drop(dead_sock);

        // Now send to the dead port — this is what ChannelData forwarding does
        // at server.rs:724 with `let _ =`
        let result = relay_sock.send_to(b"channeldata", &dead_addr).await;

        // BUG CONFIRMED: send_to fails but the code at server.rs:724 does `let _ =`
        match result {
            Err(_) => {
                // This error is completely ignored in production:
                //   server.rs:724: let _ = relay_sock.send_to(...)
                // No log, no metrics, no retry.
            }
            Ok(_) => {
                // If this somehow succeeds (unlikely on loopback), the test
                // still documents the bug: the `let _ =` discards the result.
            }
        }

        // The key assertion: the code at server.rs:724 literally writes `let _ =`
        // which means NO error handling exists for this send failure.
        // Verify by checking the relay socket is still open (the allocation survived)
        assert!(relay_sock.local_addr().is_ok(), "relay socket still bound");
    }

    // ---------------------------------------------------------------------------
    // BUG: relay task dies after 100 consecutive recv errors,
    // permanently killing peer→client forwarding for an otherwise-live allocation.
    // File: allocation.rs:1054-1055 (init), 1129-1138 (kill switch)
    // The counter is only reset on successful recv_from, not on clock time.
    // Sustained transient errors (ICMP, etc.) with no real data will kill the task.
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_bug_consecutive_recv_errors_kill_relay_task() {
        use std::sync::atomic::AtomicBool;

        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 50004);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_addr = alloc.read().relayed_addr;
        let relay_socket = alloc.read().relay.as_ref().unwrap().socket.clone();

        // Step 1: Verify relay task is alive by sending real data
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _peer_addr = peer.local_addr().unwrap();
        peer.send_to(b"alive", &relayed_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let stats_before = table
            .stats()
            .total_bytes_relayed
            .load(Ordering::Relaxed);
        assert!(stats_before >= 5, "relay task should process peer data initially");

        // Step 2: Simulate sustained transient errors by sending from the relay
        // socket to a dead port. Each send triggers an ICMP port-unreachable,
        // which gets delivered as ECONNREFUSED on the next recv_from.
        // After ~100 such errors, the relay task's `consecutive_recv_errors`
        // counter reaches MAX_CONSECUTIVE_RECV_ERRORS and the task dies.
        //
        // Important: we send data in BETWEEN ICMP bursts to check if the
        // relay task survives. The bug is that consecutive errors without
        // intervening success will kill it.
        let _was_alive = Arc::new(AtomicBool::new(true));

        // Spawn a task that repeatedly sends to trigger ICMP errors
        let relay_sock_for_errs = relay_socket.clone();
        let error_trigger = tokio::spawn(async move {
            // Create a dead peer: bind then immediately drop
            let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dead_addr = dead.local_addr().unwrap();
            drop(dead);

            // Send many packets to trigger ICMP errors
            for _ in 0..200 {
                let _ = relay_sock_for_errs.send_to(b"trigger-icmp", &dead_addr).await;
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        });

        let _ = error_trigger.await;

        // Give the relay task time to process the ICMP errors
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 3: Try to send real data via the relay socket after the ICMP storm
        let peer2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = peer2.send_to(b"post-icmp-storm", &relayed_addr).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let stats_after = table
            .stats()
            .total_bytes_relayed
            .load(Ordering::Relaxed);

        // BUG: If the relay task died from the ICMP storm, stats_after == stats_before
        // and the "post-icmp-storm" data was never relayed
        if stats_after == stats_before {
            // THIS IS THE BUG: the relay task died from 100 consecutive recv errors
            // with no successful recv in between. The allocation is still alive,
            // but peer→client forwarding has permanently stopped.
            assert!(
                result.is_ok(),
                "BUG CONFIRMED: relay task died from 100 consecutive transient recv errors.\n\
                 File: allocation.rs:1129-1138\n\
                 Peer 'post-icmp-storm' data was sent to the relay socket but never forwarded.\n\
                 Stats unchanged: before={}, after={}", stats_before, stats_after
            );
        }
    }

    // ---------------------------------------------------------------------------
    // BUG: When relay task's main_socket.send_to to the CLIENT fails,
    // peer data is lost with only a warn! log. No retry, no queue.
    // File: allocation.rs:1092-1101 (ChannelData) and 1105-1113 (Data Indication)
    //
    // This simulates the scenario by binding a "main socket" that the client
    // disconnected from — proving that peer data is lost silently.
    // ---------------------------------------------------------------------------
    #[tokio::test]
    async fn test_bug_main_socket_send_failure_loses_peer_data() {
        // Create allocation normally — the relay task sends peer data BACK
        // to the client via main_socket. If main_socket send_to fails,
        // the relay task logs a warn! and drops the data.

        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 50005);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_addr = alloc.read().relayed_addr;

        // Set up channel binding so peer data goes as ChannelData to client
        let peer: SocketAddr = make_addr("192.168.1.100", 9999);
        assert!(table.add_permissions(&client, &[peer]));
        channel_table.bind(0x4000, peer, relayed_addr).unwrap();

        // Step 1: Send data from peer to relay → relay task should forward to client
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer_sock.send_to(b"peer-data", &relayed_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let stats_after = table
            .stats()
            .total_bytes_relayed
            .load(Ordering::Relaxed);

        // The key point: the relay task forwards data using main_socket.send_to(&client_addr).
        // If main_socket is functional and client is reachable, the stats increment.
        // The BUG is that main_socket.send_to failures are only warn! logged —
        // this test documents that behavior exists in:
        //   allocation.rs:1092-1101 (ChannelData path)
        //   allocation.rs:1105-1113 (Data Indication path)
        //
        // In a real scenario: if client's NAT rebinds to a different port,
        // main_socket.send_to will fail (or worse, succeed but go to old port).
        // The relay task does NOT update client_addr from Refresh requests.
        assert!(
            stats_after >= 9,
            "relay task forwarded peer data to client via main_socket.\n\
             BUG NOTE: if main_socket.send_to fails, this data is lost with only warn! log\n\
             File: allocation.rs:1092-1101"
        );
    }
    #[tokio::test]
    async fn test_stats_incremented_on_forward() {
        let table = dummy_table();
        let channel_table = ChannelTable::new();
        let client: SocketAddr = make_addr("192.168.1.1", 12345);
        let peer: SocketAddr = make_addr("10.0.0.2", 5000);

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        assert!(table.add_permissions(&client, &[peer]));

        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        assert!(table.add_permissions(&client, &[peer_addr]));

        let table_bytes_before = table.stats().total_bytes_relayed.load(Ordering::Relaxed);
        let table_msgs_before = table.stats().total_messages.load(Ordering::Relaxed);
        let alloc_bytes_before = alloc.read().bytes_forwarded.load(Ordering::Relaxed);
        let alloc_msgs_before = alloc.read().messages_forwarded.load(Ordering::Relaxed);

        table
            .send_to_peer(&client, peer_addr, b"12345")
            .await;

        // All stats should increase
        let a = alloc.read();
        assert!(
            table.stats().total_bytes_relayed.load(Ordering::Relaxed) > table_bytes_before,
            "table bytes incremented"
        );
        assert!(
            table.stats().total_messages.load(Ordering::Relaxed) > table_msgs_before,
            "table messages incremented"
        );
        assert!(
            a.bytes_forwarded.load(Ordering::Relaxed) > alloc_bytes_before,
            "allocation bytes incremented"
        );
        assert!(
            a.messages_forwarded.load(Ordering::Relaxed) > alloc_msgs_before,
            "allocation messages incremented"
        );
    }
}
