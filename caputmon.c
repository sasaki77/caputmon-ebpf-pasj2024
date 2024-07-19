#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 6
#define ETH_HLEN 14

int ca_filter(struct __sk_buff *skb)
{

    u8 *cursor = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    // filter IP packets (ethernet type = 0x0800)
    if (!(ethernet->type == 0x0800))
    {
        goto DROP;
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    // filter TCP packets (ip next protocol = 0x06)
    if (ip->nextp != IP_TCP)
    {
        goto DROP;
    }

    u32 tcp_header_length = 0;
    u32 ip_header_length = 0;
    u32 payload_offset = 0;
    u32 payload_length = 0;

    // calculate ip header length
    // value to multiply * 4
    // e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
    ip_header_length = ip->hlen << 2; // SHL 2 -> *4 multiply

    // check ip header length against minimum
    if (ip_header_length < sizeof(*ip))
    {
        goto DROP;
    }

    // shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length - sizeof(*ip)));

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    // calculate tcp header length
    // value to multiply *4
    // e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
    tcp_header_length = tcp->offset << 2; // SHL 2 -> *4 multiply

    // calculate payload offset and length
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    payload_length = ip->tlen - ip_header_length - tcp_header_length;

    // minimum length of ca request is always greater than 16 bytes
    if (payload_length < 16)
    {
        goto DROP;
    }

    __u16 ca_command = load_half(skb, payload_offset);
    __u16 ca_payload_size = load_half(skb, payload_offset + 2);

    // 0x00: CA_PROTO_VERSION
    if (ca_command == 0 && ca_payload_size == 0)
    {
        goto KEEP;
    }
    // 0x04: CA_PROTO_WRITE
    if (ca_command == 4)
    {
        __u16 ca_dbr_type = load_half(skb, payload_offset + 4);
        if (ca_dbr_type > 38)
        {
            goto DROP;
        }

        goto KEEP;
    }
    // 0x0c: CA_PROTO_CLEAR_CHANNEL
    if (ca_command == 12 && ca_payload_size == 0)
    {
        goto KEEP;
    }
    // 15: "CA_PROTO_READ_NOTIFY",
    if (ca_command == 15)
    {
        goto KEEP;
    }
    // 18: "CA_PROTO_CREATE_CHAN",
    if (ca_command == 18)
    {
        goto KEEP;
    }
    // 22: "CA_PROTO_ACCESS_RIGHTS",
    if (ca_command == 22)
    {
        goto KEEP;
    }

    // no CA match
    goto DROP;

// keep the packet and send it to userspace returning -1
KEEP:
    return -1;

// drop the packet returning 0
DROP:
    return 0;
}
