/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/starfive-mctp.h>

#include "container_of.h"
#include "libmctp-alloc.h"
#include "libmctp-starfive-pcie.h"
#include "libmctp-log.h"
#include "starfive-pcie.h"

#undef pr_fmt
#define pr_fmt(fmt) "STARFIVE pcie: " fmt

/*
 * PCIe header template in "network format" - Big Endian
 */
static const struct mctp_pcie_hdr mctp_pcie_hdr_template_be = {
	.fmt_type = MSG_4DW_HDR,
	.mbz_attr_length = MCTP_PCIE_VDM_ATTR,
	.code = MSG_CODE_VDM_TYPE_1,
	.vendor = VENDOR_ID_DMTF_VDM
};

int mctp_starfive_pcie_get_eid_info_ioctl(struct mctp_binding_starfive_pcie *starfive_pcie,
				    void *eid_info, uint16_t count,
				    uint8_t start_eid)
{
	struct starfive_mctp_get_eid_info get_eid_info;
	int rc;

	get_eid_info.count = count;
	get_eid_info.start_eid = start_eid;
	get_eid_info.ptr = (uintptr_t)eid_info;

	rc = ioctl(starfive_pcie->fd, STARFIVE_MCTP_IOCTL_GET_EID_INFO, &get_eid_info);
	if (!rc) {
		uintptr_t ptr = (uintptr_t)get_eid_info.ptr;

		memcpy(eid_info, (void *)ptr, get_eid_info.count);
	}

	return rc;
}

int mctp_starfive_pcie_set_eid_info_ioctl(struct mctp_binding_starfive_pcie *starfive_pcie,
				    void *eid_info, uint16_t count)
{
	struct starfive_mctp_set_eid_info set_eid_info;

	set_eid_info.count = count;
	set_eid_info.ptr = (uintptr_t)eid_info;

	return ioctl(starfive_pcie->fd, STARFIVE_MCTP_IOCTL_SET_EID_INFO,
		     &set_eid_info);
}

static int mctp_starfive_pcie_get_bdf_ioctl(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	struct starfive_mctp_get_bdf bdf;
	int rc;

	rc = ioctl(starfive_pcie->fd, STARFIVE_MCTP_IOCTL_GET_BDF, &bdf);
	if (!rc)
		starfive_pcie->bdf = bdf.bdf;

	return rc;
}

int mctp_starfive_pcie_get_bdf(struct mctp_binding_starfive_pcie *starfive_pcie, uint16_t *bdf)
{
	int rc;

	rc = mctp_starfive_pcie_get_bdf_ioctl(starfive_pcie);
	if (!rc)
		*bdf = starfive_pcie->bdf;

	return rc;
}

static int
mctp_starfive_pcie_get_medium_id_ioctl(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	struct starfive_mctp_get_medium_id get_medium_id;
	int rc;

	rc = ioctl(starfive_pcie->fd, STARFIVE_MCTP_IOCTL_GET_MEDIUM_ID,
		   &get_medium_id);
	if (!rc)
		starfive_pcie->medium_id = get_medium_id.medium_id;

	return rc;
}

int mctp_starfive_pcie_register_default_handler(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	return ioctl(starfive_pcie->fd, STARFIVE_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER);
}

int mctp_starfive_pcie_register_type_handler(struct mctp_binding_starfive_pcie *starfive_pcie,
				       uint8_t mctp_type,
				       uint16_t pci_vendor_id,
				       uint16_t vendor_type,
				       uint16_t vendor_type_mask)
{
	struct starfive_mctp_type_handler_ioctl type_handler;

	type_handler.mctp_type = mctp_type;
	type_handler.pci_vendor_id = pci_vendor_id;
	type_handler.vendor_type = vendor_type;
	type_handler.vendor_type_mask = vendor_type_mask;

	return ioctl(starfive_pcie->fd, STARFIVE_MCTP_IOCTL_REGISTER_TYPE_HANDLER,
		     &type_handler);
}

int mctp_starfive_pcie_unregister_type_handler(struct mctp_binding_starfive_pcie *starfive_pcie,
					 uint8_t mctp_type,
					 uint16_t pci_vendor_id,
					 uint16_t vendor_type,
					 uint16_t vendor_type_mask)
{
	struct starfive_mctp_type_handler_ioctl type_handler;

	type_handler.mctp_type = mctp_type;
	type_handler.pci_vendor_id = pci_vendor_id;
	type_handler.vendor_type = vendor_type;
	type_handler.vendor_type_mask = vendor_type_mask;

	return ioctl(starfive_pcie->fd, STARFIVE_MCTP_IOCTL_UNREGISTER_TYPE_HANDLER,
		     &type_handler);
}

uint8_t mctp_starfive_pcie_get_medium_id(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	return starfive_pcie->medium_id;
}

static int mctp_starfive_pcie_open(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	int fd = open(starfive_pcie->mctp_dev, O_RDWR);

	if (fd < 0) {
		mctp_prerr("Cannot open: %s, errno = %d", starfive_pcie->mctp_dev, errno);

		return fd;
	}

	starfive_pcie->fd = fd;
	return 0;
}

static void mctp_starfive_pcie_close(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	close(starfive_pcie->fd);
	starfive_pcie->fd = -1;
}

/*
 * Start function. Opens driver, read bdf and medium_id
 */
static int mctp_starfive_pcie_start(struct mctp_binding *b)
{
	struct mctp_binding_starfive_pcie *starfive_pcie = binding_to_starfive_pcie(b);
	int rc;

	assert(starfive_pcie);

	rc = mctp_starfive_pcie_open(starfive_pcie);
	if (rc)
		return -errno;

	rc = mctp_starfive_pcie_get_bdf_ioctl(starfive_pcie);
	if (rc)
		goto out_close;

	rc = mctp_starfive_pcie_get_medium_id_ioctl(starfive_pcie);
	if (rc)
		goto out_close;

	return 0;

out_close:
	mctp_starfive_pcie_close(starfive_pcie);
	return -errno;
}

static uint8_t mctp_starfive_pcie_tx_get_pad_len(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) - sz;
}

static uint16_t mctp_starfive_pcie_tx_get_payload_size_dw(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) / sizeof(uint32_t) - MCTP_HDR_SIZE_DW;
}
/*
 * Tx function which writes single packet to device driver
 */
static int mctp_starfive_pcie_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_starfive_pcie_pkt_private *pkt_prv =
		(struct mctp_starfive_pcie_pkt_private *)pkt->msg_binding_private;
	struct mctp_binding_starfive_pcie *starfive_pcie = binding_to_starfive_pcie(b);
	struct mctp_pcie_hdr *hdr = (struct mctp_pcie_hdr *)pkt->data;
	uint16_t payload_len_dw = mctp_starfive_pcie_tx_get_payload_size_dw(pkt);
	uint8_t pad = mctp_starfive_pcie_tx_get_pad_len(pkt);
	ssize_t write_len, len;

	if (pkt_prv->remote_id == starfive_pcie->bdf) {
		mctp_prerr("Invalid Target ID (matches own BDF)");
		return -1;
	}

	memcpy(hdr, &mctp_pcie_hdr_template_be, sizeof(*hdr));

	mctp_prdebug("TX, len: %d, pad: %d", payload_len_dw, pad);

	PCIE_SET_ROUTING(hdr, pkt_prv->routing);
	PCIE_SET_DATA_LEN(hdr, payload_len_dw);
	PCIE_SET_REQ_ID(hdr, starfive_pcie->bdf);
	PCIE_SET_TARGET_ID(hdr, pkt_prv->remote_id);
	PCIE_SET_PAD_LEN(hdr, pad);

	len = (payload_len_dw * sizeof(uint32_t)) +
	      STARFIVE_MCTP_PCIE_VDM_HDR_SIZE;

	mctp_trace_tx(pkt->data, len);

	write_len = write(starfive_pcie->fd, pkt->data, len);
	if (write_len < 0) {
		mctp_prerr("TX error");
		return -1;
	}

	return 0;
}

static size_t mctp_starfive_pcie_rx_get_payload_size(struct mctp_pcie_hdr *hdr)
{
	size_t len_dw = PCIE_GET_DATA_LEN(hdr);
	uint8_t pad = PCIE_GET_PAD_LEN(hdr);

	/* According to PCIe Spec, 0 means 1024 DW */
	if (len_dw == 0)
		len_dw = PCIE_MAX_DATA_LEN_DW;

	return len_dw * sizeof(uint32_t) - pad;
}

/*
 * Simple poll implementation for use
 */
int mctp_starfive_pcie_poll(struct mctp_binding_starfive_pcie *starfive_pcie, int timeout)
{
	struct pollfd fds[1];
	int rc;

	fds[0].fd = starfive_pcie->fd;
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

static bool mctp_starfive_pcie_is_routing_supported(int routing)
{
	switch (routing) {
	case PCIE_ROUTE_TO_RC:
	case PCIE_ROUTE_BY_ID:
	case PCIE_BROADCAST_FROM_RC:
		return true;
	default:
		return false;
	}
}

int mctp_starfive_pcie_rx(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	uint32_t data[MCTP_STARFIVE_PCIE_BINDING_DEFAULT_BUFFER];
	struct mctp_starfive_pcie_pkt_private pkt_prv;
	struct mctp_pktbuf *pkt;
	struct mctp_pcie_hdr *hdr;
	ssize_t read_len;
	size_t payload_len;
	int rc;

	read_len = read(starfive_pcie->fd, &data, sizeof(data));
	if (read_len < 0) {
		mctp_prerr("Reading RX data failed (errno = %d)", errno);
		return -1;
	}

	mctp_trace_rx(&data, read_len);

	if (read_len != STARFIVE_PCIE_PACKET_SIZE(MCTP_BTU)) {
		mctp_prerr("Incorrect packet size: %zd", read_len);
		return -1;
	}

	hdr = (struct mctp_pcie_hdr *)data;
	payload_len = mctp_starfive_pcie_rx_get_payload_size(hdr);

	pkt_prv.routing = PCIE_GET_ROUTING(hdr);

	if (!mctp_starfive_pcie_is_routing_supported(pkt_prv.routing)) {
		mctp_prerr("unsupported routing value: %d", pkt_prv.routing);
		return -1;
	}

	pkt_prv.remote_id = PCIE_GET_REQ_ID(hdr);

	pkt = mctp_pktbuf_alloc(&starfive_pcie->binding, 0);
	if (!pkt) {
		mctp_prerr("pktbuf allocation failed");
		return -1;
	}

	rc = mctp_pktbuf_push(pkt, data + PCIE_HDR_SIZE_DW,
			      payload_len + sizeof(struct mctp_hdr));

	if (rc) {
		mctp_prerr("Cannot push to pktbuf");
		mctp_pktbuf_free(pkt);
		return -1;
	}

	memcpy(pkt->msg_binding_private, &pkt_prv, sizeof(pkt_prv));

	mctp_bus_rx(&starfive_pcie->binding, pkt);

	return 0;
}

/*
 * Initializes PCIe binding structure
 */
struct mctp_binding_starfive_pcie *mctp_starfive_pcie_init(void)
{
	struct mctp_binding_starfive_pcie *starfive_pcie;

	starfive_pcie = __mctp_alloc(sizeof(*starfive_pcie));
	if (!starfive_pcie)
		return NULL;

	memset(starfive_pcie, 0, sizeof(*starfive_pcie));

	starfive_pcie->binding.name = "starfive_pcie";
	starfive_pcie->binding.version = 1;
	starfive_pcie->binding.tx = mctp_starfive_pcie_tx;
	starfive_pcie->binding.start = mctp_starfive_pcie_start;
	starfive_pcie->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	strcpy(starfive_pcie->mctp_dev, STARFIVE_DRV_FILE);

	assert(starfive_pcie->binding.pkt_size - sizeof(struct mctp_hdr) <=
	       PCIE_MAX_DATA_LEN);

	/* where mctp_hdr starts in in/out comming data
	 * note: there are two approaches: first (used here) that core
	 * allocates pktbuf to contain all binding metadata or this is handled
	 * other way by only by binding.
	 * This might change as smbus binding implements support for medium
	 * specific layer */
	starfive_pcie->binding.pkt_pad = sizeof(struct mctp_pcie_hdr);
	starfive_pcie->binding.pkt_priv_size =
		sizeof(struct mctp_starfive_pcie_pkt_private);

	return starfive_pcie;
}

/*
 * Change the file name of MCTP device
 */
void mctp_starfive_pcie_mctp_dev_name(struct mctp_binding_starfive_pcie *starfive_pcie, char *name)
{
	if (strcmp(name, ""))
		strcpy(starfive_pcie->mctp_dev, name);
}

/*
 * Closes file descriptor and releases binding memory
 */
void mctp_starfive_pcie_free(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	mctp_starfive_pcie_close(starfive_pcie);
	__mctp_free(starfive_pcie);
}

/*
 * Returns generic binder handler from PCIe binding handler
 */
struct mctp_binding *mctp_starfive_pcie_core(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	return &starfive_pcie->binding;
}

int mctp_starfive_pcie_get_fd(struct mctp_binding_starfive_pcie *starfive_pcie)
{
	return starfive_pcie->fd;
}
