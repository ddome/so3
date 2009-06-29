#ifndef MI_COMUNICACION_H
#define MI_COMUNICACION_H
/*casos:
opcode:*/
#include "/usr/src/inet/generic/firewall.h"
#define ADD_RULE	1
#define LIST_RULE	2
#define SAVE		3
#define DELETE		4
#define DELETE_RULE	5
#define CHANGE_POLICY	6
#define NONE		-5
/*estructura:*/

typedef struct nwio_firewall { 
int opcode;
int tabla;
fwrule_t campos;
} t_miMensaje;

/*En caso de no haber informacion en los campos, se coloca un -5 para los int, y para los direcicones ip se coloca 0.0.0.0*/
#endif
