#ifndef LIBMCTP_SMBUS_H
#define LIBMCTP_SMBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

#define MCTP_HEADER_SIZE 4
#define MCTP_PAYLOAD_SIZE 64

#define SMBUS_HEADER_SIZE 4
#define SMBUS_PEC_BYTE_SIZE 1

#define SMBUS_TX_BUFF_SIZE                                                     \
	((MCTP_HEADER_SIZE) + (SMBUS_HEADER_SIZE) + (MCTP_PAYLOAD_SIZE) +      \
	 (SMBUS_PEC_BYTE_SIZE))
struct mctp_binding_smbus {
	struct mctp_binding binding;
	int out_fd;
	int in_fd;

	unsigned long bus_id;

	/* receive buffer */
	uint8_t rxbuf[1024];
	struct mctp_pktbuf *rx_pkt;

	/* temporary transmit buffer */
	uint8_t txbuf[SMBUS_TX_BUFF_SIZE];
};

struct mctp_binding_smbus *mctp_smbus_init(void);
void mctp_smbus_register_bus(struct mctp_binding_smbus *smbus,
			     struct mctp *mctp, mctp_eid_t eid);
int mctp_smbus_read(struct mctp_binding_smbus *smbus);
void mctp_smbus_free(struct mctp_binding_smbus *smbus);
int mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd);
int mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd);
void mctp_binding_set_slave_addr_callback(int (*slaveAddrCallback)(uint8_t,
								   uint8_t *));
#ifdef __cplusplus
}
#endif
#endif /*LIBMCTP_SMBUS_H */
