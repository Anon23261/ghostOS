#ifndef GHOST_NETWORK_H
#define GHOST_NETWORK_H

#include <stdint.h>
#include <stdbool.h>
#include "network_types.h"
#include "network_errors.h"

// Maximum number of network interfaces
#define MAX_NETWORK_INTERFACES 8

// Maximum number of concurrent connections
#define MAX_NETWORK_CONNECTIONS 256

// Network packet maximum sizes
#define MAX_PACKET_SIZE 1500
#define MIN_PACKET_SIZE 64

// Network interface structure
struct NetworkInterface {
    uint32_t id;
    NetworkAddress addr;
    bool enabled;
    uint32_t flags;
    uint32_t mtu;
    uint32_t tx_queue_len;
    uint32_t rx_queue_len;
    uint8_t* tx_buffer;
    uint8_t* rx_buffer;
    void* driver_data;
};

// Network connection structure
struct NetworkConnection {
    uint32_t id;
    NetworkAddress local_addr;
    NetworkAddress remote_addr;
    NetworkState state;
    uint32_t flags;
    uint32_t timeout;
    uint32_t last_activity;
    NetworkInterface* interface;
    void* private_data;
};

// Network packet structure
struct NetworkPacket {
    uint32_t id;
    NetworkAddress src;
    NetworkAddress dst;
    uint16_t protocol;
    uint16_t flags;
    uint32_t length;
    uint8_t* data;
    void* private_data;
};

// Initialization
NetworkError init_network(void);
NetworkError cleanup_network(void);

// Interface management
NetworkError init_network_interfaces(void);
NetworkError register_network_interface(NetworkInterface* iface);
NetworkError unregister_network_interface(NetworkInterface* iface);
NetworkError configure_network_interface(NetworkInterface* iface, const NetworkAddress* addr);

// Connection management
NetworkError create_connection(NetworkConnection** conn);
NetworkError close_connection(NetworkConnection* conn);
NetworkError find_connection(uint32_t id, NetworkConnection** conn);
NetworkError update_connection_state(NetworkConnection* conn, NetworkState state);

// Packet operations
NetworkError send_packet(NetworkConnection* conn, const NetworkPacket* packet);
NetworkError receive_packet(NetworkConnection* conn, NetworkPacket* packet);
NetworkError verify_packet_integrity(const NetworkPacket* packet);
NetworkError create_packet(NetworkPacket** packet, uint32_t size);
NetworkError destroy_packet(NetworkPacket* packet);

// Security operations
NetworkError verify_connection_security(NetworkConnection* conn);
NetworkError handle_network_violation(NetworkConnection* conn, NetworkEventType event_type);
NetworkError verify_network_integrity(void);

#endif // GHOST_NETWORK_H
