/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <stdio.h>

#include "libmctp-starfive-pcie.h"
#include "libmctp-cmds.h"
#include "libmctp-log.h"
#include "starfive-pcie.h"

#include <linux/starfive-mctp.h>

#undef pr_fmt
#define pr_fmt(fmt) "test_starfive_pcie: " fmt

#define PACKET_SIZE (STARFIVE_MCTP_PCIE_VDM_HDR_SIZE + 64)

static int stubbed_fd = 3;
static uint16_t stubbed_bdf = 0x100;
static uint8_t stubbed_medium_id = 0x9;

/* Packet with */
static uint8_t rx_test_packet[][PACKET_SIZE] = {
	/* test_rx_routing1 */
	{ 0x73, 0x00, 0x10, 0x01, 0x00, 0x92, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xd9, 0x00, 0x8a, 0x0b },
	/* test_rx_routing2 */
	{ 0x72, 0x00, 0x10, 0x01, 0x00, 0x34, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xd9, 0x00, 0x8a, 0x0b },
	/* test_rx_routing3 */
	{ 0x70, 0x00, 0x10, 0x01, 0x00, 0x34, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xd9, 0x7e, 0x8a, 0x0b },
	/* test_rx_remote_id1 */
	{ 0x73, 0x00, 0x10, 0x01, 0x00, 0x92, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xd9, 0x00, 0x8a, 0x0b },
	/* test_rx_remote_id2 */
	{ 0x72, 0x00, 0x10, 0x01, 0x00, 0x34, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xd9, 0x00, 0x8a, 0x0b },
	/* test_rx_verify_payload1 */
	{ 0x73, 0x00, 0x10, 0x01, 0x00, 0x92, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xd9, 0x00, 0x8a, 0x0b },
	/* test_rx_verify_payload2 */
	{ 0x72, 0x00, 0x10, 0x06, 0x00, 0xb0, 0x20, 0x7f, 0x07, 0x00,
	  0x1a, 0xb4, 0x01, 0x00, 0x50, 0xd0, 0x00, 0x00, 0x0a, 0x00,
	  0xff, 0x02, 0x01, 0x60, 0x00, 0x02, 0x08, 0x02, 0x07, 0x00,
	  0x01, 0x20, 0x00, 0x02, 0x08, 0x02, 0x06, 0x01 },
	/* test_rx_tag */
	{ 0x72, 0x00, 0x10, 0x01, 0x00, 0x92, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xdf, 0x00, 0x8a, 0x0b },
	/* negative_test_rx_routing1 */
	{ 0x71, 0x00, 0x10, 0x01, 0x00, 0x92, 0x10, 0x7f, 0x01, 0x00, 0x1a,
	  0xb4, 0x01, 0xff, 0x50, 0xd9, 0x00, 0x8a, 0x0b },
};

struct starfive_pcie_test_ctx {
	struct mctp *mctp;
	struct mctp_binding_starfive_pcie *starfive_pcie;
};

/* Mocking of system calls */

int open(const char *pathname, int flags)
{
	return stubbed_fd;
}

int close(int fd)
{
	assert(fd == stubbed_fd);
	return 0;
}

int ioctl(int fd, unsigned long request, void *data)
{
	assert(fd == stubbed_fd);

	switch (request) {
	case STARFIVE_MCTP_IOCTL_GET_BDF: {
		struct starfive_mctp_get_bdf *bdf =
			(struct starfive_mctp_get_bdf *)data;
		bdf->bdf = stubbed_bdf;
		break;
	}
	case STARFIVE_MCTP_IOCTL_GET_MEDIUM_ID: {
		struct starfive_mctp_get_medium_id *medium_id =
			(struct starfive_mctp_get_medium_id *)data;
		medium_id->medium_id = stubbed_medium_id;
		break;
	}
	default:
		mctp_prdebug("Unrecognized ioctl");
		assert(0);
		break;
	}

	return 0;
}

#define POLLIN 1

typedef long nfds_t;

struct pollfd {
	int fd;
	short events;
	short revents;
};

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	fds[0].revents = POLLIN;
	return 1;
}

ssize_t read(int fd, void *buf, size_t count)
{
	static int index = 0;

	assert(fd == stubbed_fd);

	if (count > sizeof(rx_test_packet[index]))
		count = sizeof(rx_test_packet[index]);

	memcpy(buf, &rx_test_packet[index], count);

	index++;

	return count;
}

ssize_t write(int __fd, void *data, size_t data_size)
{
	assert(__fd == stubbed_fd);

	return 0;
}

static void init_test_ctx(struct starfive_pcie_test_ctx *ctx)
{
	struct mctp_binding_starfive_pcie *starfive_pcie;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	starfive_pcie = mctp_starfive_pcie_init();
	assert(starfive_pcie);
	assert(strcmp(starfive_pcie->binding.name, "starfive_pcie") == 0);
	assert(starfive_pcie->binding.version == 1);

	rc = mctp_register_bus_dynamic_eid(mctp, &starfive_pcie->binding);
	assert(rc == 0);

	ctx->mctp = mctp;
	ctx->starfive_pcie = starfive_pcie;
}

static void destroy_test_ctx(struct starfive_pcie_test_ctx *ctx)
{
	mctp_starfive_pcie_free(ctx->starfive_pcie);
	mctp_destroy(ctx->mctp);
}

static void dump_payload(uint8_t *payload, size_t len)
{
	char dump[5 * len];
	int pos = 0;
	int i;

	for (i = 0; i < len; i++)
		pos += sprintf(dump + pos, "%#02x ", payload[i]);

	mctp_prdebug("payload: %s", dump);
}

static void test_rx_verify_payload1(mctp_eid_t src, void *data, void *msg,
				    size_t len, bool tag_owner, uint8_t tag,
				    void *ext)
{
	uint8_t expected_data[] = { 0x00, 0x8a, 0x0b };
	int rc;

	mctp_prdebug("rx payload len: %#zx", len);

	assert(len == 3);

	dump_payload(msg, len);

	rc = memcmp(expected_data, msg, len);
	assert(rc == 0);
}

static void test_rx_verify_payload2(mctp_eid_t src, void *data, void *msg,
				    size_t len, bool tag_owner, uint8_t tag,
				    void *ext)
{
	uint8_t expected_data[] = { 0x00, 0x00, 0x0a, 0x00, 0xff, 0x02,
				    0x01, 0x60, 0x00, 0x02, 0x08, 0x02,
				    0x07, 0x00, 0x01, 0x20, 0x00, 0x02,
				    0x08, 0x02, 0x06, 0x01 };
	int rc;

	mctp_prdebug("rx payload len: %#zx", len);

	assert(len == 22);

	dump_payload(msg, len);

	rc = memcmp(expected_data, msg, len);

	assert(rc == 0);
}

static void test_rx_remote_id1(mctp_eid_t src, void *data, void *msg,
			       size_t len, bool tag_owner, uint8_t tag,
			       void *ext)
{
	struct mctp_starfive_pcie_pkt_private *pkt_prv =
		(struct mctp_starfive_pcie_pkt_private *)ext;

	mctp_prdebug("rx remote id: %#04x", pkt_prv->remote_id);

	assert(pkt_prv->remote_id == 0x92);
}

static void test_rx_remote_id2(mctp_eid_t src, void *data, void *msg,
			       size_t len, bool tag_owner, uint8_t tag,
			       void *ext)
{
	struct mctp_starfive_pcie_pkt_private *pkt_prv =
		(struct mctp_starfive_pcie_pkt_private *)ext;

	mctp_prdebug("rx remote id: %#04x", pkt_prv->remote_id);

	assert(pkt_prv->remote_id == 0x34);
}

static void test_rx_routing1(mctp_eid_t src, void *data, void *msg, size_t len,
			     bool tag_owner, uint8_t tag, void *ext)
{
	struct mctp_starfive_pcie_pkt_private *pkt_prv =
		(struct mctp_starfive_pcie_pkt_private *)ext;

	mctp_prdebug("rx routing: %#x", pkt_prv->routing);

	assert(pkt_prv->routing == PCIE_BROADCAST_FROM_RC);
}

static void test_rx_routing2(mctp_eid_t src, void *data, void *msg, size_t len,
			     bool tag_owner, uint8_t tag, void *ext)
{
	struct mctp_starfive_pcie_pkt_private *pkt_prv =
		(struct mctp_starfive_pcie_pkt_private *)ext;

	mctp_prdebug("rx routing: %#x", pkt_prv->routing);

	assert(pkt_prv->routing == PCIE_ROUTE_BY_ID);
}

static void test_rx_routing3(mctp_eid_t src, void *data, void *msg, size_t len,
			     bool tag_owner, uint8_t tag, void *ext)
{
	struct mctp_starfive_pcie_pkt_private *pkt_prv =
		(struct mctp_starfive_pcie_pkt_private *)ext;

	mctp_prdebug("rx routing: %#x", pkt_prv->routing);

	assert(pkt_prv->routing == PCIE_ROUTE_TO_RC);
}

static void test_rx_tag(mctp_eid_t src, void *data, void *msg, size_t len,
			bool tag_owner, uint8_t tag, void *ext)
{
	mctp_prdebug("rx tag: %#02x", tag);

	assert(tag == 7);
}

static void negative_test_rx_routing1(mctp_eid_t src, void *data, void *msg,
				      size_t len, bool tag_owner, uint8_t tag,
				      void *ext)
{
	struct mctp_starfive_pcie_pkt_private *pkt_prv =
		(struct mctp_starfive_pcie_pkt_private *)ext;

	mctp_prdebug("rx routing: %#x", pkt_prv->routing);

	assert(0);
}

static void run_rx_test(mctp_rx_fn rx_fn)
{
	struct starfive_pcie_test_ctx ctx;
	int rc;

	init_test_ctx(&ctx);

	mctp_set_rx_all(ctx.mctp, rx_fn, NULL);

	rc = mctp_starfive_pcie_poll(ctx.starfive_pcie, 1000);
	if (rc & POLLIN) {
		rc = mctp_starfive_pcie_rx(ctx.starfive_pcie);
		assert(rc == 0);
	}

	destroy_test_ctx(&ctx);
}

static void run_rx_negative_test(mctp_rx_fn rx_fn)
{
	struct starfive_pcie_test_ctx ctx;
	int rc;

	init_test_ctx(&ctx);

	mctp_set_rx_all(ctx.mctp, rx_fn, NULL);

	rc = mctp_starfive_pcie_poll(ctx.starfive_pcie, 1000);
	if (rc & POLLIN) {
		rc = mctp_starfive_pcie_rx(ctx.starfive_pcie);
		assert(rc != 0);
	}

	destroy_test_ctx(&ctx);
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	run_rx_test(test_rx_routing1);
	run_rx_test(test_rx_routing2);
	run_rx_test(test_rx_routing3);
	run_rx_test(test_rx_remote_id1);
	run_rx_test(test_rx_remote_id2);
	run_rx_test(test_rx_verify_payload1);
	run_rx_test(test_rx_verify_payload2);
	run_rx_test(test_rx_tag);

	run_rx_negative_test(negative_test_rx_routing1);

	return 0;
}
