#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "../../include/net/network.h"
#include "../../include/net/network_types.h"
#include "../../include/memory/kmalloc.h"
#include "../../include/kernel/spinlock.h"

// Protocol constants
#define PROTOCOL_VERSION 1
#define MAX_PACKET_FRAGMENTS 16
#define MAX_PACKET_PAYLOAD (MAX_PACKET_SIZE - sizeof(PacketHeader))
#define MIN_PACKET_PAYLOAD (MIN_PACKET_SIZE - sizeof(PacketHeader))

// Protocol header structure
typedef struct {
    uint32_t version;          // Protocol version
    uint32_t sequence;         // Packet sequence number
    uint32_t flags;           // Protocol flags
    uint32_t total_size;      // Total payload size
    uint32_t fragment_offset; // Offset of this fragment
    uint32_t fragment_size;   // Size of this fragment
    uint32_t checksum;        // Header checksum
    uint32_t payload_checksum; // Payload checksum
} PacketHeader;

// Fragment tracking structure
typedef struct {
    uint8_t* data;
    uint32_t size;
    uint32_t offset;
    bool received;
} PacketFragment;

// Packet assembly context
typedef struct {
    PacketHeader header;
    PacketFragment fragments[MAX_PACKET_FRAGMENTS];
    uint32_t fragments_received;
    uint32_t total_fragments;
    uint32_t total_size;
    uint64_t timestamp;
    bool complete;
} PacketAssemblyContext;

// Protocol state
static spinlock_t protocol_lock = SPINLOCK_INIT;
static uint32_t next_sequence = 1;

// Calculate checksum
static uint32_t calculate_checksum(const void* data, size_t size) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t checksum = 0;
    
    for (size_t i = 0; i < size; i++) {
        checksum = ((checksum << 5) + checksum) + bytes[i];
    }
    
    return checksum;
}

// Validate protocol header
static NetworkError validate_header(const PacketHeader* header) {
    if (!header) return NET_ERR_INVALID_PARAM;

    // Check version
    if (header->version != PROTOCOL_VERSION) {
        return NET_ERR_PROTOCOL_VERSION;
    }

    // Validate sizes
    if (header->total_size > MAX_PACKET_SIZE || 
        header->total_size < MIN_PACKET_SIZE ||
        header->fragment_size > MAX_PACKET_PAYLOAD ||
        header->fragment_offset >= header->total_size) {
        return NET_ERR_PACKET_INVALID;
    }

    // Verify header checksum
    uint32_t saved_checksum = header->checksum;
    ((PacketHeader*)header)->checksum = 0;
    uint32_t calculated_checksum = calculate_checksum(header, sizeof(PacketHeader));
    ((PacketHeader*)header)->checksum = saved_checksum;

    if (saved_checksum != calculated_checksum) {
        return NET_ERR_PACKET_CHECKSUM;
    }

    return NET_ERR_SUCCESS;
}

// Fragment packet
NetworkError fragment_packet(const NetworkPacket* packet, NetworkPacket** fragments, uint32_t* num_fragments) {
    if (!packet || !fragments || !num_fragments) return NET_ERR_INVALID_PARAM;
    if (packet->length == 0 || packet->length > MAX_PACKET_SIZE) return NET_ERR_PACKET_INVALID;

    spinlock_acquire(&protocol_lock);

    // Calculate number of fragments needed
    uint32_t fragment_count = (packet->length + MAX_PACKET_PAYLOAD - 1) / MAX_PACKET_PAYLOAD;
    if (fragment_count > MAX_PACKET_FRAGMENTS) {
        spinlock_release(&protocol_lock);
        return NET_ERR_PACKET_TOO_LARGE;
    }

    // Allocate fragments
    *fragments = kmalloc(sizeof(NetworkPacket) * fragment_count);
    if (!*fragments) {
        spinlock_release(&protocol_lock);
        return NET_ERR_OUT_OF_MEMORY;
    }

    // Fragment the packet
    uint32_t sequence = next_sequence++;
    uint32_t offset = 0;

    for (uint32_t i = 0; i < fragment_count; i++) {
        NetworkPacket* fragment = &(*fragments)[i];
        uint32_t fragment_size = (i == fragment_count - 1) ? 
            packet->length - offset : MAX_PACKET_PAYLOAD;

        // Allocate fragment data
        fragment->data = kmalloc(fragment_size + sizeof(PacketHeader));
        if (!fragment->data) {
            // Clean up on error
            for (uint32_t j = 0; j < i; j++) {
                kfree((*fragments)[j].data);
            }
            kfree(*fragments);
            spinlock_release(&protocol_lock);
            return NET_ERR_OUT_OF_MEMORY;
        }

        // Set up header
        PacketHeader* header = (PacketHeader*)fragment->data;
        header->version = PROTOCOL_VERSION;
        header->sequence = sequence;
        header->flags = packet->flags | NET_FLAG_FRAGMENTED;
        header->total_size = packet->length;
        header->fragment_offset = offset;
        header->fragment_size = fragment_size;
        header->payload_checksum = calculate_checksum(
            packet->data + offset, fragment_size);

        // Copy data
        uint8_t* fragment_data = fragment->data + sizeof(PacketHeader);
        for (uint32_t j = 0; j < fragment_size; j++) {
            fragment_data[j] = packet->data[offset + j];
        }

        // Calculate header checksum
        header->checksum = 0;
        header->checksum = calculate_checksum(header, sizeof(PacketHeader));

        fragment->length = fragment_size + sizeof(PacketHeader);
        offset += fragment_size;
    }

    *num_fragments = fragment_count;
    spinlock_release(&protocol_lock);
    return NET_ERR_SUCCESS;
}

// Reassemble packet
NetworkError reassemble_packet(const NetworkPacket* fragment, PacketAssemblyContext* context) {
    if (!fragment || !context) return NET_ERR_INVALID_PARAM;
    if (fragment->length < sizeof(PacketHeader)) return NET_ERR_PACKET_INVALID;

    spinlock_acquire(&protocol_lock);

    // Get and validate header
    const PacketHeader* header = (const PacketHeader*)fragment->data;
    NetworkError err = validate_header(header);
    if (err != NET_ERR_SUCCESS) {
        spinlock_release(&protocol_lock);
        return err;
    }

    // Initialize context if this is the first fragment
    if (!context->fragments_received) {
        context->header = *header;
        context->total_size = header->total_size;
        context->total_fragments = (header->total_size + MAX_PACKET_PAYLOAD - 1) / MAX_PACKET_PAYLOAD;
        context->complete = false;

        if (context->total_fragments > MAX_PACKET_FRAGMENTS) {
            spinlock_release(&protocol_lock);
            return NET_ERR_PACKET_TOO_LARGE;
        }

        // Initialize fragments
        for (uint32_t i = 0; i < context->total_fragments; i++) {
            context->fragments[i].data = NULL;
            context->fragments[i].received = false;
        }
    }
    // Verify fragment belongs to this packet
    else if (header->sequence != context->header.sequence) {
        spinlock_release(&protocol_lock);
        return NET_ERR_PACKET_INVALID;
    }

    // Calculate fragment index
    uint32_t fragment_index = header->fragment_offset / MAX_PACKET_PAYLOAD;
    if (fragment_index >= context->total_fragments) {
        spinlock_release(&protocol_lock);
        return NET_ERR_PACKET_INVALID;
    }

    // Store fragment if not already received
    if (!context->fragments[fragment_index].received) {
        uint32_t payload_size = header->fragment_size;
        uint8_t* payload = fragment->data + sizeof(PacketHeader);

        // Verify payload checksum
        uint32_t calculated_checksum = calculate_checksum(payload, payload_size);
        if (calculated_checksum != header->payload_checksum) {
            spinlock_release(&protocol_lock);
            return NET_ERR_PACKET_CHECKSUM;
        }

        // Allocate and copy fragment data
        context->fragments[fragment_index].data = kmalloc(payload_size);
        if (!context->fragments[fragment_index].data) {
            spinlock_release(&protocol_lock);
            return NET_ERR_OUT_OF_MEMORY;
        }

        for (uint32_t i = 0; i < payload_size; i++) {
            context->fragments[fragment_index].data[i] = payload[i];
        }

        context->fragments[fragment_index].size = payload_size;
        context->fragments[fragment_index].offset = header->fragment_offset;
        context->fragments[fragment_index].received = true;
        context->fragments_received++;

        // Check if packet is complete
        if (context->fragments_received == context->total_fragments) {
            context->complete = true;
        }
    }

    spinlock_release(&protocol_lock);
    return NET_ERR_SUCCESS;
}

// Get reassembled packet
NetworkError get_reassembled_packet(PacketAssemblyContext* context, NetworkPacket** packet) {
    if (!context || !packet) return NET_ERR_INVALID_PARAM;

    spinlock_acquire(&protocol_lock);

    if (!context->complete) {
        spinlock_release(&protocol_lock);
        return NET_ERR_NOT_READY;
    }

    // Allocate packet
    *packet = kmalloc(sizeof(NetworkPacket));
    if (!*packet) {
        spinlock_release(&protocol_lock);
        return NET_ERR_OUT_OF_MEMORY;
    }

    (*packet)->data = kmalloc(context->total_size);
    if (!(*packet)->data) {
        kfree(*packet);
        spinlock_release(&protocol_lock);
        return NET_ERR_OUT_OF_MEMORY;
    }

    // Combine fragments
    uint32_t offset = 0;
    for (uint32_t i = 0; i < context->total_fragments; i++) {
        PacketFragment* fragment = &context->fragments[i];
        for (uint32_t j = 0; j < fragment->size; j++) {
            (*packet)->data[offset + j] = fragment->data[j];
        }
        offset += fragment->size;
    }

    (*packet)->length = context->total_size;
    (*packet)->flags = context->header.flags & ~NET_FLAG_FRAGMENTED;

    // Clean up fragments
    for (uint32_t i = 0; i < context->total_fragments; i++) {
        if (context->fragments[i].data) {
            kfree(context->fragments[i].data);
        }
    }

    spinlock_release(&protocol_lock);
    return NET_ERR_SUCCESS;
}

// Clean up assembly context
NetworkError cleanup_assembly_context(PacketAssemblyContext* context) {
    if (!context) return NET_ERR_INVALID_PARAM;

    spinlock_acquire(&protocol_lock);

    for (uint32_t i = 0; i < context->total_fragments; i++) {
        if (context->fragments[i].data) {
            kfree(context->fragments[i].data);
            context->fragments[i].data = NULL;
        }
        context->fragments[i].received = false;
    }

    context->fragments_received = 0;
    context->complete = false;

    spinlock_release(&protocol_lock);
    return NET_ERR_SUCCESS;
}
