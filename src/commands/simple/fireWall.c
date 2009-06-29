
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

/*------------------------------------------------*/
/*Sacarlo para no compilar con los printf de debug*/
/*------------------------------------------------*/
#define INET_PID 5
#define TIPO_MENSAJE 1
#define INPUT 0
#define OUTPUT 1
void enviarPaquete(t_miMensaje * paquete);
static void usage(void);
static char* prog_name;
int
main(int argc, char *argv[])
{
	
	/*Flags*/
	int A_flag, L_flag, s_flag;
	int d_flag, p_flag, j_flag;
	int D_flag, t_flag, gu_flag;
	int P_flag;
	int gd_flag, n_flagin;
	int F_flag,n_flagout, terminar;
	int nru,nrd,nrt,nrc;
	int X_flag,X_value;
	/*Valores*/
	int A_value;
	proto_t p_value;
	int L_value, D_value;
	int F_value;
	int P_value;
	action_t j_value;
	port_t gu_value;
	int n_valuein;
	mask_t n_valueinc;
	int n_valueout;
	mask_t n_valueoutc;
	port_t gd_value;
	ipaddr_t s_value;
	ipaddr_t d_value;
	int c;
	int fd;
	int status;

	t_miMensaje paquete;	/*Paquete de informacion!!*/

	/*Auxiliares*/
	char aux_s[17];
	
	/*Inicializacion*/
	prog_name= argv[0];
	A_flag= 0;
	L_flag= 0;
	F_flag= 0;
	s_flag= 0;
	d_flag= 0;
	p_flag= 0;
	j_flag= 0;
	D_flag= 0;
	t_flag= 0;
	P_flag= 0;
	X_flag= 0;
	n_flagin=n_flagout=0;
	gu_flag= 0; /* guion 1 */
	gd_flag= 0; /* guion 2 */
	terminar = 0;


	fd = open("/dev/ip", O_RDWR);

	/*Magic Code*/
	while ((c =getopt(argc, argv, "F:P:hA:L:s:d:p:j:D:t:I:O:")) != -1)
	{
		if(terminar)
			usage();
		switch(c)
		{
		case 'h':
			usage();
		case 'A':
			if(A_flag)
			{
				usage();
				exit(1);
			}
			A_flag = 1;
			if(strcmp(optarg,"INPUT")!=0)
			{
				if(strcmp(optarg,"OUTPUT")!=0)
				{
					usage();
					exit(1);
				}
				A_value=OUTPUT;
			}
			else
				A_value=INPUT;
			break;
		case 'L':
			if(L_flag||A_flag)
			{
				printf("Mal ingreso de parametros\n");
				usage();
				exit(1);
			}
			L_flag = 1;
			if(strcmp(optarg,"INPUT")!=0)
			{
				if(strcmp(optarg,"OUTPUT")!=0)
				{
					printf("Mal ingreso de parametros\n");
					usage();
				}
				L_value=OUTPUT;
			}
			else
				L_value=INPUT;
			terminar=1;
			break;
		case 'P':
			if(P_flag||A_flag)
			{
				printf("Mal ingreso de parametros\n");
				usage();
				exit(1);
			}
			P_flag = 1;
			if(!strcmp(optarg, "ACCEPT"))
			{
				P_value=ALLOW;
			}
			else if (!strcmp(optarg, "DENY"))
			{
				P_value=DENY;
			}
			else
			{
				printf("Mal ingreso de parametros\n");
				usage();
				exit(1);
			}	
			terminar = 1;
			break;
		case 'F':
			if(F_flag||A_flag)
			{
				printf("Mal ingreso de parametros\n");
				usage();
				exit(1);
			}
			F_flag = 1;
			if(strcmp(optarg,"INPUT")!=0)
			{
				if(strcmp(optarg,"OUTPUT")!=0)
				{
					printf("Mal ingreso de parametros\n");
					usage();
				}
				else
					F_value=OUTPUT;
			}
			else
				F_value=INPUT;
			terminar=1;
			break;
		case 's':
			if(!A_flag || s_flag)
			{
				printf("Mal ingreso de parametros\n");
				usage();
			}
			s_flag = 1;
			if(sscanf(optarg,"%d.%d.%d.%d/%d",&nru,&nrd,&nrt,&nrc,&n_valuein)!=5)
				usage();
			if(n_valuein<0||n_valuein>30)
				usage();
			n_flagin=1;
			sprintf(aux_s,"%d.%d.%d.%d",nru,nrd,nrt,nrc);
			s_value=inet_addr(aux_s);
			n_valueinc=n_valuein;
			break;
		case 'd':
			if(!A_flag || d_flag)
			{	
				printf("Mal ingreso de parametros\n");
				usage();
			}
			d_flag = 1;
			if(sscanf(optarg,"%d.%d.%d.%d/%d",&nru,&nrd,&nrt,&nrc,&n_valueout)!=5)
			{
				usage();
			}
			if(n_valueout<0||n_valueout>30)
			{
				printf("Mal ingreo de datos\n");
				usage();
			}
			n_flagout=1;
			sprintf(aux_s,"%d.%d.%d.%d",nru,nrd,nrt,nrc);
			d_value=inet_addr(aux_s);
			n_valueoutc=n_valueout;
			break;
		case 'p':
			if(!A_flag|| p_flag)
			{
				printf("Mal ingreso de parametros\n");
				usage();
			}
			p_flag = 1;
			if(strcmp(optarg,"tcp")!=0)
			{
				if(strcmp(optarg,"udp")!=0)
				{
					if(strcmp(optarg,"icmp")!=0)
					{
						printf("Mal ingreso de parametros\n");
						usage();
					}
					p_value=ICMP;
				}
				else
					p_value=UDP;
			}
			else
				p_value=TCP;
			break;
		case 'j':
			if(!A_flag|| j_flag)
			{
				printf("Mal ingreso de parametros\n");
				usage();
			}
			j_flag = 1;
			if(strcmp(optarg,"ACCEPT")!=0)
			{
				if(strcmp(optarg,"DENY")!=0)
				{
					printf("Mal ingreso de parametros\n");
					usage();
				}
				j_value=DENY;
			}
			else
				j_value=ALLOW;

			terminar=1;
			break;
		case 'D':
			if(D_flag || A_flag)
			{
				printf("Mal ingreso de parametros\n");
				usage();
			}
			D_flag=1;
			D_value= atoi(optarg);
			terminar=1;
			break;
		case 'O':
				if(gu_flag||!A_flag||!p_flag)
				{
					printf("Mal ingreso de parametros\n");
					usage();
				}
				gu_flag=1;
				gu_value =(port_t) atoi(optarg);
				if(gu_value<1||gu_value>65535)
					usage();
				break;
		case 'I':
				if(gd_flag||!A_flag||!p_flag)
				{
					printf("Mal ingreso de parametros\n");
					usage();
				}
				gd_flag=1;
				gd_value =(port_t) atoi(optarg);
				if(gd_value<1||gd_value>65535)
					usage();
				break;
		case 'X':
				/*Levanto la condicion para filtrar por estados. DEFAULT indica que no hay que
				*filtrar por estados. Segun como se haya definido la regla, esto filtrara los
				*pedidos de conexion entrantes pero se podra establecer una conexion y no filtrara
				*las respuestas.*/
				if(!A_flag || X_flag)
				{
					printf("Mal ingreso de parametros\n");
					usage();
				}
				X_flag=1;
				if( strcmp(optarg,"DEFAULT")!=0 )
				{
					if( strcmp(optarg,"ESTABLISHED")!=0 )
					{
						printf("Mal ingreso de parametros\n");
						usage();
					}
					else
						X_value=ESTABLISHED;
				}
				else
					X_value=NEW;
				break;
		default:
			usage();
		}
	}
	if(!terminar)
		usage();
	/*DEBUG_ME*/
	#ifdef DEBUG_ME
	if(L_flag)
	{
		printf("Debo Listar(1 IN 2 OUT): %d\n",L_value);
		exit(0);
	}
	if(D_flag)
	{
		printf("Borro la regla con id: %d\n",D_value);
		exit(0);
	}
	if(gt_flag)
	{
		printf("Guardo las reglas\n");
		exit(0);
	}
	if(j_flag)
	{
		printf("Codigo de A (1 In | 2 Out): %d\n",A_value);
		if(s_flag)
		{
			printf("Numero de IP S:");
			writeIpAddr(s_value);
			printf("\n");
		}
		if(n_flagin)
		{
			printf("Numero de bits de Red Source: %d\n",n_valuein);
			printf("Numero anterior convertido: %u\n",n_valueinc);
		}
		if(d_flag)
		{
			printf("Numero de IP D:");
			writeIpAddr(d_value);
			printf("\n");
		}
		if(n_flagout)
		{
			printf("Numero de bits de Red Destino: %d\n",n_valueout);
			printf("Numero anterior convertido: %u\n",n_valueoutc);
		}
		if(p_flag)
			printf("Protocolo TCP 3 UDP 4 : %d\n",p_value);
		if(gd_flag)
			printf("Puerto de origen: %d\n",gd_value);
		if(gu_flag)
			printf("Puerto de destino: %d\n",gu_value);
		if(X_flag)
			printf("Estado de las conexiones a filtrar: %d\n",X_value);
		printf("Valor de j (Accept 5 Deny 6): %d\n",j_value);
	}
	#endif
	if(L_flag)
	{
		paquete.opcode= LIST_RULE;
		paquete.tabla=L_value;
		paquete.campos.src_ip=inet_addr("0.0.0.0");
		paquete.campos.netmaskin=NONE;
		paquete.campos.dst_ip=inet_addr("0.0.0.0");;
		paquete.campos.netmaskout=NONE;
		paquete.campos.protocol=NONE;
		paquete.campos.src_port=NONE;
		paquete.campos.dst_port=NONE;
		paquete.campos.action=NONE;
		paquete.campos.id=NONE;

	}
	else if(F_flag)
	{
		paquete.opcode= DELETE_RULE;
		paquete.tabla=F_value;
		paquete.campos.src_ip=inet_addr("0.0.0.0");
		paquete.campos.netmaskin=NONE;
		paquete.campos.dst_ip=inet_addr("0.0.0.0");;
		paquete.campos.netmaskout=NONE;
		paquete.campos.protocol=NONE;
		paquete.campos.src_port=NONE;
		paquete.campos.dst_port=NONE;
		paquete.campos.action=NONE;
		paquete.campos.id=NONE;

	}
	else if(P_flag)
	{
		paquete.opcode = CHANGE_POLICY;
		paquete.tabla=NONE;
		paquete.campos.src_ip=0;
		paquete.campos.dst_ip=0;
		paquete.campos.netmaskin=NONE;
		paquete.campos.protocol=NONE;
		paquete.campos.src_port=NONE;
		paquete.campos.dst_port=NONE;
		paquete.campos.action=P_value;
		paquete.campos.id=NONE;
	}
	else if(D_flag)
	{
		paquete.opcode= DELETE;
		paquete.tabla=NONE;
		paquete.campos.src_ip=inet_addr("0.0.0.0");
		paquete.campos.netmaskin=NONE;
		paquete.campos.dst_ip=inet_addr("0.0.0.0");;
		paquete.campos.netmaskout=NONE;
		paquete.campos.protocol=NONE;
		paquete.campos.src_port=NONE;
		paquete.campos.dst_port=NONE;
		paquete.campos.action=NONE;
		paquete.campos.id=D_value;
	}
	else if(j_flag)
	{
		paquete.opcode= ADD_RULE;
		paquete.tabla=A_value;
		if(s_flag)
		{
			paquete.campos.src_ip=s_value;
			paquete.campos.netmaskin=n_valueinc;
		}
		else	
		{
			paquete.campos.src_ip=0;
			paquete.campos.netmaskin=0;
		}
		if(d_flag)
		{
			paquete.campos.dst_ip=d_value;
			paquete.campos.netmaskout=n_valueoutc;
		}
		else
		{
			paquete.campos.dst_ip=0;
			paquete.campos.netmaskout=0;
		}
		if(p_flag)
			paquete.campos.protocol=p_value;
		else
			paquete.campos.protocol=ALL;
		if(gd_flag)
			paquete.campos.src_port=gd_value;
		else
			paquete.campos.src_port=0;	
		if(gu_flag)
			paquete.campos.dst_port=gu_value;
		else
			paquete.campos.dst_port=0;
		/*Agrego el nuevo parametro para enviarle a ioctl() para poder comunicarme con
		 *el firewall.*/
		if(X_flag)
			paquete.campos.status=X_value;
		else
			paquete.campos.status=0;
		paquete.campos.action=j_value;
		
		paquete.campos.id=NONE;
	}
	else
		usage();

	status = ioctl(fd, NWIOFIREWALL, &paquete);
	/*recibirRespuesta();*/
	exit(0);
}

static void 
usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s\n[-A (INPUT|OUTPUT) (-s(NroIP/#bit de Red)|-d(NroIP/#bit de Red)) (-p(tcp|udp|icmp)) (-I Port|-O Port) -j(ACCEPT|DENY)| -X(DEFAULT|ESTABLISHED)",prog_name);
	fprintf(stderr, "\n-L (INPUT|OUTPUT)|");
	fprintf(stderr, "\n-F (INPUT|OUTPUT)|");
	fprintf(stderr, "\n-P (ACCEPT|DENY)");
	fprintf(stderr, "\n-D (id)]\n");
	exit(1);
}

