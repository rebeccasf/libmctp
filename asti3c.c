/* SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include "libmctp-log.h"
#include "libmctp-alloc.h"
#include "libmctp-asti3c.h"

#undef pr_fmt
#define pr_fmt(x) "asti3c: " x
#define BMC_I3C_SLAVE_ADDR       0x08

static uint8_t crc8 (uint8_t crc, const uint8_t *data, uint8_t len)
{
        int i, j;

        if (data == NULL)
                return crc;

        for (i = 0; i < len; ++i) {
                crc ^= data[i];

                for (j = 0; j < 8; ++j) {
                        if ((crc & 0x80) != 0)
                                crc = (uint8_t) ((crc << 1) ^ 0x07);
                        else
                                crc <<= 1;
                }
        }

        return crc;
}

static int mctp_asti3c_tx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp_asti3c_pkt_private *pkt_prv =
		(struct mctp_asti3c_pkt_private *)pkt->msg_binding_private;
	ssize_t write_len, len;

	if (pkt_prv->fd < 0) {
		mctp_prerr("Invalid file descriptor passed");
		return -1;
	}

	len = mctp_pktbuf_size(pkt);

	/* /dev/i3c-mctp-dev CRC/PECs are appended in hardware, skipping calculation here.
	 * /sys/bus/i3c/i3c-x/slavemq CRC/PECs are not appended in hardware, manually calculation here */

	mctp_prdebug("Transmitting packet, len: %zu", len);
	mctp_trace_tx(pkt->data, len);

        if (pkt_prv->append_pec) {
		uint8_t i3c_addr = (BMC_I3C_SLAVE_ADDR << 1) | 0x01;
		uint8_t pec;
		uint8_t *buffer = malloc(len + 1);
		pec = crc8(0, &i3c_addr, 1);
		pec = crc8(pec, (uint8_t *)pkt->data, len);

		memcpy(buffer, pkt->data, len);
		buffer[len] = pec;
		len+= 1;
		write_len = write(pkt_prv->fd, buffer, len);
		mctp_trace_tx(buffer, len);
		free(buffer);
        } else {
		write_len = write(pkt_prv->fd, pkt->data, len);
	}

	if (write_len != len) {
		mctp_prerr("TX error write_len=%d len=%d", write_len, len);
		return -1;
	}

	return 0;
}

struct mctp_binding_asti3c *mctp_asti3c_init(void)
{
	struct mctp_binding_asti3c *asti3c;

	asti3c = __mctp_alloc(sizeof(*asti3c));
	if (!asti3c)
		return NULL;

	memset(asti3c, 0, sizeof(*asti3c));

	asti3c->binding.name = "asti3c";
	asti3c->binding.version = 1;
	asti3c->binding.tx = mctp_asti3c_tx;
	asti3c->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	asti3c->binding.pkt_priv_size = sizeof(struct mctp_asti3c_pkt_private);

	return asti3c;
}

void mctp_asti3c_free(struct mctp_binding_asti3c *asti3c)
{
	__mctp_free(asti3c);
}

int mctp_asti3c_poll(int fd, int timeout)
{
	struct pollfd fds[1];
	int rc;

	fds[0].fd = fd;
	fds[0].events = POLLIN | POLLOUT;

	rc = poll(fds, 1, timeout);

	if (rc > 0)
		return fds[0].revents;

	if (rc < 0) {
		mctp_prwarn("Poll returned error status (errno=%d)", errno);

		return -1;
	}

	return 0;
}

int mctp_asti3c_rx(struct mctp_binding_asti3c *asti3c, int fd)
{
	uint8_t data[MCTP_I3C_BUFFER_SIZE];
	struct mctp_asti3c_pkt_private pkt_prv;
	struct mctp_pktbuf *pkt;
	ssize_t read_len;
	int rc;

	if (fd < 0) {
		mctp_prerr("Invalid file descriptor");
		return -1;
	}

	read_len = read(fd, &data, sizeof(data));
	if (read_len < 0) {
		mctp_prerr("Reading RX data failed (errno = %d)", errno);
		return -1;
	}

	mctp_trace_rx(&data, read_len);

	/* PEC is verified at hardware level and does not
	propogate to userspace, thus do not deal with PEC byte */

	if ((read_len > (MCTP_BTU + MCTP_HEADER_SIZE)) ||
	    (read_len < (MCTP_HEADER_SIZE))) {
		mctp_prerr("Incorrect packet size: %zd", read_len);
		return -1;
	}

	pkt_prv.fd = fd;

	pkt = mctp_pktbuf_alloc(&asti3c->binding, 0);
	if (!pkt) {
		mctp_prerr("pktbuf allocation failed");
		return -1;
	}

	rc = mctp_pktbuf_push(pkt, data, read_len);

	if (rc) {
		mctp_prerr("Cannot push to pktbuf");
		mctp_pktbuf_free(pkt);
		return -1;
	}

	memcpy(pkt->msg_binding_private, &pkt_prv, sizeof(pkt_prv));

	mctp_bus_rx(&asti3c->binding, pkt);

	return 0;
}
