/*
 * firewall.c
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <net/gen/netdb.h>
#include <net/gen/in.h>
#include <net/gen/inet.h>
#include <net/gen/ip_hdr.h>
#include <net/gen/icmp_hdr.h>
#include <math.h>

#include "inet.h"
#include "type.h"
#include "io.h"
#include <sys/ioctl.h>
#include <net/gen/ip_io.h>


#include "firewall.h"
#include "list.h"

#define TCS_CLOSED		0
#define TCS_LISTEN		1
#define TCS_SYN_RECEIVED	2
#define TCS_SYN_SENT		3
#define TCS_ESTABLISHED		4
#define TCS_CLOSING		5

listADT rtables[2];
int nextid = 1;
int default_policy = ALLOW;

THIS_FILE

PUBLIC int idCmp(void *elem1, void *elem2)
{
	fwrule_t *first, *second;
	first = (fwrule_t *)elem1;
	second = (fwrule_t *)elem2;

	if (first->id > second->id)
		return 1;
	else if (first->id == second->id)
		return 0;
	else
		return -1;
}

PUBLIC void fw_init(void)
{
	printf("The Minix firewall is starting :D\n");
	
	rtables[0] = NewList(idCmp, sizeof(fwrule_t));
	rtables[1] = NewList(idCmp, sizeof(fwrule_t));

}



PUBLIC int add_rule(table, rule)
table_t table;
fwrule_t rule;
{
	rule.id = nextid++;
	printf("Agregando regla con id %d\n", rule.id);
	Insert(rtables[table], &rule);
	return 1;
}

PUBLIC int del_rule(id)
unsigned int id;
{
	int status;
	fwrule_t rule;

	rule.id = id;

	if (ElementBelongs(rtables[0], &rule))
	{
		status = Delete(rtables[0], &rule);
	}
	else
	{
		status = Delete(rtables[1], &rule);
	}

	return status;
}

PUBLIC void change_policy(action)
action_t action;
{
	default_policy = action;
}

PUBLIC int list_rules(table)
table_t table;
{
	fwrule_t rule;

	SetBegin(rtables[table]);

	while (GetDato(rtables[table], &rule))
	{
		printf("ID: %d\n", rule.id);
		if (rule.src_ip != 0)
		{
			printf("IP Src: ");
			writeIpAddr(rule.src_ip);
			printf("/%d\n", rule.netmaskin);

		}

		if (rule.dst_ip != 0)
		{
			printf("IP Dst: ");
			writeIpAddr(rule.dst_ip);	
			printf("/%d\n", rule.netmaskout);
		}

		if (rule.protocol != 0)
		{
			printf("Protocol: ");
			if (rule.protocol == TCP)
				printf("TCP\n");
			else if (rule.protocol == UDP)
				printf("UDP\n");
			else
				printf("ICMP\n");
		}

		if (rule.src_port != 0)
		{
			printf("Source port: %d\n", rule.src_port);
		}

		if (rule.dst_port != 0)
		{
			printf("Dest. port: %d\n", rule.dst_port);
		}
		
		if(rule.status != 0)
		{
			printf("Connection status: ");
			if( rule.status==NEW )
			    printf("DEFAULT\n");
			else if( rule.status==ESTABLISHED )
			    printf("ESTABLISHED\n");
			else if( rule.status==INVALID )
			    printf("INVALID\n");
			else if( rule.status==RELATED )
			    printf("RELATED\n");
		}

		if (rule.action == DENY)
		{
			printf("Action: DENY\n");
		}
		else
		{
			printf("Action: ALLOW\n");
		}
	}

	return 0;
}

PUBLIC int flush_table(table)
table_t table;
{
    FreeList(rtables[table]);
    /* creo una nueva tabla para reemplazarla */
    rtables[table] = NewList(idCmp, sizeof(fwrule_t));

	
	return 0;

}

/* Minix llora cuando recibe parametros de tipo short.
 * Asi que: recibimos un int y en la estructura hay un u16_t. */
PUBLIC int can_pass(table, src_ip, dst_ip, proto, src_port, dst_port,state)
table_t table;
ipaddr_t src_ip;
ipaddr_t dst_ip;
proto_t proto;
int src_port;
int dst_port;
int state;
{
    fwrule_t rule;
    u32_t  	 mask;
    int udp_conn=0;

    /*Si vino una mensaje UDP prendo un flag para no filtrar.*/
    if(state==-1)
	udp_conn=1;

    SetBegin(rtables[table]);
    while (GetDato(rtables[table], &rule))
    {
        /* si no matchea el protocolo paso a la siguiente regla */
        if (rule.protocol != ALL)
        {
        	if (rule.protocol != proto)
            		continue;
        }

        /* si la regla tiene 0 como puerto es que matchea cualquiera */
        if (rule.src_port != 0)
        {
        	if (rule.src_port != ntohs(src_port))
            		continue;
        }
        if (rule.dst_port != 0)
        {
        	if (rule.dst_port != ntohs(dst_port))
            		continue;
        }

        /* matchear las ip. por ahora ni bola a la mascara */
        if (rule.src_ip != 0)
        {
        	if( rule.netmaskin != 0 )
        	{
        		mask = generateMask(rule.netmaskin);
       
        		if ( mask&src_ip != rule.src_ip)
        		            continue;
        		
        	}
        	else if (rule.src_ip != src_ip)
            		continue;
        	
        }
        
        if (rule.dst_ip != 0)
        {
        	
        	if( rule.netmaskout != 0 )
        	{
        		mask = generateMask(rule.netmaskout);
        		

        		if ( mask&dst_ip != rule.dst_ip)
        		            continue;
        		
        	}
        	else  if (rule.dst_ip != dst_ip)
            		continue;
        
        }
	
	/*Si es UDP sigo como si nada.*/
	if(!udp_conn)
	{
	    /*Si es TCP pregunto si la regla filtra por ESTABLISHED. Es decir que no dejara pasar
	     *paquetes entrantes o salientes (segun si estamos en la tabla INPUT o OUTPUT) que no
	     *pertenezcan a una sesion establecida.*/
	    if(rule.status==ESTABLISHED)
	    {
		/*Si llega un pedido de conexion lo rechaza*/
		if(table == INPUT && state == TCS_LISTEN)
		{
			    return 0;
	        }
		/*Si intento conectarme me rechaza el intento de conexion*/
	        if(table == OUTPUT && state == TCS_SYN_SENT)
	        {
	        	return 0;
	        }	
	    }
	}
	

        /* si llegue hasta aca es que la regla matchea.
           como usamos first-match wins devuelvo la accion a tomar */
        printf("La regla con id %d matcheo\n", rule.id);
        return rule.action == ALLOW;

    }

	return default_policy == ALLOW;
}

u32_t
generateMask(premask)
u32_t premask;
{
	u32_t num = 0;
	int i;
	
	for( i = 0 ; i < premask ; i++ )
	{
		num += pow(2,31-i);
	}
		
    return num;
	
}


