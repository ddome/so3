/*
 * firewall.h
 */

#ifndef FIREWALL_H
#define FIREWALL_H

#define	MAXRULES	128

typedef enum {ALL, UDP, TCP, ICMP} proto_t;
typedef enum {ALLOW, DENY} action_t;
typedef enum {INPUT, OUTPUT} table_t;
typedef enum { NO_STATE=0, NEW, ESTABLISHED, INVALID, RELATED } status_t;
typedef u16_t port_t;
typedef u32_t mask_t;

typedef struct fwrule {
	unsigned int id;
	ipaddr_t src_ip;
	ipaddr_t dst_ip;
	action_t action;
	proto_t protocol;
	port_t src_port;
	port_t dst_port;
	mask_t netmaskin;
	mask_t netmaskout;
	status_t status;
} fwrule_t;

void fw_init(void);
void load_defaults(void);
int add_rule(table_t table, fwrule_t rule);
int del_rule(unsigned int id);
int list_rules(table_t table);
void change_policy(action_t action);
int flush_table(table_t table);
int can_pass(table_t table, ipaddr_t src_ip, ipaddr_t dst_ip, proto_t proto,
		int src_port, int dst_port,int state);

u32_t	generateMask(u32_t premask);

#endif
