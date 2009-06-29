
#include <fireWall.h>
#include <miComunicacion.h>
#include <minix/type.h>
#include <net/gen/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/gen/in.h>
#include <minix/syslib.h>
#include "/usr/src/inet/generic/firewall.h"
#include <net/gen/ip_io.h>

#define INET_PID 5
#define TIPO_MENSAJE 1
#define INPUT 0
#define OUTPUT 1
#define PATH_FIREWALL_CONF "/etc/firewall.conf"
#define MAX_LINEA 200
void enviarPaquete(t_miMensaje * paquete);
void analizarLinea(char* cadena);
static int lineass;
int
main(void)
{
	
	
	FILE * default_file;
	/*Flags*/
	
	int fd;
	int status;

	t_miMensaje paquete;	/*Paquete de informacion!!*/

	/*Auxiliares*/
	char aux_s[17];
	char aux[MAX_LINEA];
	
	/*Inicializacion*/
	lineass=0;
	fd = open("/dev/ip", O_RDWR);

	/*Magic Code*/
	
	paquete.opcode= DELETE_RULE;
	paquete.tabla= INPUT;
	paquete.campos.src_ip=inet_addr("0.0.0.0");
	paquete.campos.netmaskin=NONE;
	paquete.campos.dst_ip=inet_addr("0.0.0.0");
	paquete.campos.netmaskout=NONE;
	paquete.campos.protocol=NONE;
	paquete.campos.src_port=NONE;
	paquete.campos.dst_port=NONE;
	paquete.campos.action=NONE;
	paquete.campos.id=NONE;

	status = ioctl(fd, NWIOFIREWALL, &paquete);
	if(status==-1)
	{
		printf("01:Error al inicializar tabla.\n");
		exit(1);
	}
	paquete.opcode= DELETE_RULE;
	paquete.tabla=OUTPUT;
	paquete.campos.src_ip=inet_addr("0.0.0.0");
	paquete.campos.netmaskin=NONE;
	paquete.campos.dst_ip=inet_addr("0.0.0.0");
	paquete.campos.netmaskout=NONE;
	paquete.campos.protocol=NONE;
	paquete.campos.src_port=NONE;
	paquete.campos.dst_port=NONE;
	paquete.campos.action=NONE;
	paquete.campos.id=NONE;
	
	status = ioctl(fd, NWIOFIREWALL, &paquete);
	
	if(status==-1)
	{
		printf("02:Error al inicializar tabla.\n");
		exit(1);
	}
	
	if((default_file = fopen(PATH_FIREWALL_CONF,"r"))==NULL)
	{
		printf("03:Error al cargar las reglas basicas.\n");
		return;
	}
	else
	while(fgets(aux,MAX_LINEA,default_file)!=NULL)
	{
		analizarLinea(aux);
		lineass++;
	}
	return 0;
}

void
analizarLinea(char* cadena)
{
	/*Se supone que el archivo esta bien formado*/
	/*
	FORMATO DE CADENA:
	   1 * 2 *  3  *     4   *   5  *   6      *   7    *   8    *   9    *      10    *  11 
	TABLA*ID*src_ip*netmaskin*dst_ip*netmaskout*protocol*src_port*dst_port*filter_state*action
	*/
	t_miMensaje paquete;	/*Paquete de informacion!!*/
	char * token;
	int na;
	char ** auxiliar;
	int nro1,nro2,nro3,nro4;	
	char saux[20];
	int n=1;
	int status, fd;
	fd = open("/dev/ip", O_RDWR);

	cadena[strlen(cadena)-1]=0;
	paquete.opcode= ADD_RULE;
	paquete.tabla= 3;
	paquete.campos.src_ip=inet_addr("0.0.0.0");
	paquete.campos.netmaskin=NONE;
	paquete.campos.dst_ip=inet_addr("0.0.0.0");
	paquete.campos.netmaskout=NONE;
	paquete.campos.protocol=NONE;
	paquete.campos.src_port=NONE;
	paquete.campos.dst_port=NONE;
	paquete.campos.action=NONE;
	paquete.campos.id=NONE;
	token = strtok(cadena,"*");
	do{
		switch(n)
		{
			case 1:
				if(strcmp("INPUT",token)!=0)
				{
					if(strcmp("OUTPUT",token)!=0)
					{
						fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
						return;
					}
					else
						paquete.tabla=OUTPUT;
				}
				else
					paquete.tabla = INPUT;
				break;
			case 2:
				na=strtol(token,auxiliar,10);
				if((**auxiliar)!='\0')
				{	
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				paquete.campos.id=na;
				break;
			case 3:
				if(sscanf(token,"%d.%d.%d.%d",&nro1,&nro2,&nro3,&nro4)!=4)
				{
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				sprintf(saux,"%d.%d.%d.%d",nro1,nro2,nro3,nro4);
				paquete.campos.src_ip=inet_addr(saux);
				break;
			case 4:
				na=strtol(token,auxiliar,10);
				if((**auxiliar)!='\0')
				{	
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				if(na<0 || na > 30)
				{
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}

				paquete.campos.netmaskin=na;
				break;
			case 5:
				if(sscanf(token,"%d.%d.%d.%d",&nro1,&nro2,&nro3,&nro4)!=4)
				{
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				sprintf(saux,"%d.%d.%d.%d",nro1,nro2,nro3,nro4);
				paquete.campos.dst_ip=inet_addr(saux);
				break;
			case 6:
				na=strtol(token,auxiliar,10);
				if((**auxiliar)!='\0')
				{	
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				if(na<0 || na > 30)
				{
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				paquete.campos.netmaskout=na;
				break;
			case 7:
				if(strcmp("tcp",token)!=0)
				{
					if(strcmp("udp",token)!=0)
					{
						if(strcmp("icmp",token)!=0)
						{
							if(strcmp("all",token)!=0)
							{	
								fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
								return;
							}
							else
								paquete.campos.protocol=ALL;
						}
						else
							paquete.campos.protocol=ICMP;
					}
					else
						paquete.campos.protocol=UDP;
				}
				else
					paquete.campos.protocol=TCP;
				break;

			case 8:
				na=strtol(token,auxiliar,10);
				if((**auxiliar)!='\0')
				{	
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				if(na<0 || na > 65535)
				{
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				paquete.campos.src_port=na;
				break;
			case 9:
				na=strtol(token,auxiliar,10);
				if((**auxiliar)!='\0')
				{	
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				if(na<0 || na > 65535)
				{
					fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
					return;
				}
				paquete.campos.dst_port=na;
				break;
			case 10:
			    /*Levanto la condicion para filtrar por estados. DEFAULT indica que no hay que
			     *filtrar por estados. Segun como se haya definido la regla, esto filtrara los
			     *pedidos de conexion entrantes pero se podra establecer una conexion y no filtrara
			     *las respuestas.*/
				if(strcmp(token,"DEFAULT")!=0)
				{
					if(strcmp(token,"ESTABLISHED")!=0)
					{
						fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
						return;
					}
					else
						paquete.campos.status=ESTABLISHED;
				}
				else
				    paquete.campos.status=NEW;
				    break;
			case 11:
				if(strcmp("ACCEPT",token)!=0)
				{
					if(strcmp("DENY",token)!=0)
					{
						fprintf(stderr,"Linea %d del archivo corrupta.\n",lineass);
						return;
					}
					else
						paquete.campos.action=DENY;
				}
				else
					paquete.campos.action=ALLOW;
				break;
		}
		n++;
	}while((token=strtok(NULL,"*"))!=NULL);
	status = ioctl(fd, NWIOFIREWALL, &paquete);
	if(status==-1)
	{
		printf("14:Error al inicializar tabla.\n");
		exit(1);
	}
	
	return;
}
