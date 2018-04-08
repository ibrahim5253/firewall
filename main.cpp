#include <bits/stdc++.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/un.h>
#include <stdarg.h>

#define BUF_SIZE 4096
char buf[BUF_SIZE+1];

#define handle_error(msg) \
    do {perror(msg); exit(EXIT_FAILURE);} while(0)

#define TEST

int my_scanf(const char * fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    char buf[100];
    if (fgets(buf, sizeof buf, stdin) == NULL)
        handle_error("fgets");

    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';

    int ret = strlen(buf)?vsscanf(buf, fmt, args):0;

    va_end(args);
    return ret;
}

unsigned long long tpc=0, tpd=0, tpp=0;

using namespace std;

using ip4addr=uint32_t;
using macaddr=unsigned long long;
using ip4pref=pair<ip4addr, ip4addr>;
using ipproto=unsigned char;

struct aggrule {
    ip4pref prefix;
    pair<int, int> port_range;
    ipproto proto;

    aggrule() : prefix(make_pair(0, 0)), port_range(make_pair(0, 1<<16)), proto(250) {}
    aggrule(ip4pref p, pair<int, int> pr, ipproto pt) : prefix(p), port_range(pr), proto(pt) {}
    bool operator<(const aggrule g) const
    {
        return this->prefix < g.prefix or this->port_range < g.port_range or\
                            this->proto < g.proto;
    }
};

uint32_t read_net, read_mask, write_net, write_mask;

map<macaddr, long> blocked_macs;
map<ip4pref, long> blocked_ip4s;
map<ipproto, long> blocked_ip_p;
map<aggrule, long> comp_rules  ;

map<ipproto,string> ip_p_list({make_pair(1, "ICMP"),
                               make_pair(6, "TCP" ),
                               make_pair(17,"UDP")});

inline macaddr mac_stoll(unsigned char m[6])
{
    return  m[0]*(1ll<<40) + m[1]*(1ll<<32) + m[2]*(1ll<<24) + \
            m[3]*(1ll<<16) + m[4]*(1ll<<8 ) + m[5];
}

inline void mac_lltoa(const macaddr& m, unsigned char s[6])
{
    int mask = (1<<8)-1;
    s[5] = m&mask,       s[4] = (m>>8 )&mask, s[3] = (m>>16)&mask;
    s[2] = (m>>24)&mask, s[1] = (m>>32)&mask, s[0] = m>>40;
}

inline void print_mac(unsigned char m[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

inline void print_mac(const macaddr& m)
{
    unsigned char m1[6];
    mac_lltoa(m, m1);
    print_mac(m1);
}

inline ip4addr ip4_stol(unsigned char m[4])
{
    return m[0]*(1l<<24) + m[1]*(1l<<16) + m[2]*(1l<<8) + m[3];
}

inline void ip4_ltoa(const ip4addr& m, unsigned char s[4])
{
    int mask = (1<<8)-1;
    s[3] = m&mask, s[2] = (m>>8)&mask, s[1] = (m>>16)&mask, s[0] = m>>24;
}

inline void print_ip4(unsigned char m[4])
{
    printf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]);
}

inline void print_ip4(const ip4addr& m)
{
    unsigned char m1[4];
    ip4_ltoa(m, m1);
    print_ip4(m1);
}

void display_ethernet_header()
{
    struct ether_header *eth = (struct ether_header *)buf;
    printf("Pack Typ: ");
    switch (ntohs(eth->ether_type)) {
    case ETHERTYPE_ARP:
        printf("ARP\n");
        break;
    case ETHERTYPE_IP:
        printf("IP\n");
        break;
    default:
        printf("Unknown\n");
    }
    printf("Dest MAC: "), print_mac(eth->ether_dhost), printf("\n");
    printf("Src  MAC: "), print_mac(eth->ether_shost), printf("\n");
    fflush(stdout);
}

void display_ip_header()
{
    struct ip *ip_h = (struct ip *)(buf + sizeof(struct ether_header));
    printf("%s > ", inet_ntoa(ip_h->ip_dst));
    printf("%s \n", inet_ntoa(ip_h->ip_src));
    fflush(stdout);
}

void bind_pkt_socket(int sck, const char* ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sck, SIOCGIFINDEX, (void*)&ifr)) 
        handle_error("ioctl-pkt");
    
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof addr);
    addr.sll_family   = AF_PACKET; 
    addr.sll_ifindex  = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sck, (struct sockaddr *)&addr, sizeof addr)) 
        handle_error("bind-pkt");

    if (ioctl(sck, SIOCGIFNETMASK, (void*)&ifr))
        handle_error("ioctl-ifnetmask");
    read_mask = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr;

    if (ioctl(sck, SIOCGIFADDR, (void*)&ifr))
        handle_error("ioctl-ifaddr");
    read_net = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr & read_mask;
}

void bind_ip_socket(int sck, const char* ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sck, SIOCGIFADDR, (void*)&ifr))
        handle_error("ioctl-ip");
    write_net = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    if (bind(sck, &(ifr.ifr_addr), sizeof ifr.ifr_addr))
        handle_error("bind-ip");

    if (ioctl(sck, SIOCGIFNETMASK, (void*)&ifr))
        handle_error("ioctl-ifnetmask");
    write_mask = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr;

    write_net &= write_mask;
}

bool is_blocked_mac(struct ether_header *eth)
{
    return blocked_macs.count(mac_stoll(eth->ether_shost)) and \
            ++blocked_macs[mac_stoll(eth->ether_shost)];
}

bool is_blocked_ip4(struct ip *iph)
{
    ip4addr dst = ntohl(iph->ip_src.s_addr);
    for (auto& p: blocked_ip4s)
        if ( (dst&p.first.second) == (p.first.first&p.first.second) ) 
            return true and ++blocked_ip4s[p.first];
    return false;
}

bool is_blocked_ipp(struct ip *iph)
{
    //printf("IP Proto: %d\n", ntohs(iph->ip_p));
    return blocked_ip_p.count(iph->ip_p) and ++blocked_ip_p[iph->ip_p];
}

bool match_aggrules(struct ip *iph)
{
    char *th = buf+sizeof(struct ether_header)+iph->ip_hl*4;
    ipproto proto=iph->ip_p; 
    int port=-1; 
    ip4addr srcip = ntohl(iph->ip_src.s_addr);
    
    if (proto==6) port=ntohs(((struct tcphdr*)th)->th_dport);
    else if (proto==17) port=ntohs(((struct udphdr*)th)->uh_dport);

    for (auto &i : comp_rules) {
        auto& r=i.first;
        if ((r.proto==250 or r.proto==proto) and \ 
            (r.prefix.second&srcip) == (r.prefix.first&r.prefix.second) and \
            (proto==1 or port>=r.port_range.first and port<=r.port_range.second))

            return true and ++comp_rules[r];
    }
    return false;
}

void send_packet(int sck, int bytes)
{
    struct ether_header *eth = (struct ether_header*)buf;
    int offset = sizeof(struct ether_header);
    struct ip *iph = (struct ip*)(buf + offset);

    // Filter rules
    
    if ((iph->ip_src.s_addr & write_mask) == write_net) return; // src inside  local network
    if ((iph->ip_dst.s_addr & write_mask) != write_net) return; // dst outside local network

    ++tpc;
    if (is_blocked_mac(eth) or is_blocked_ip4(iph) or 
        is_blocked_ipp(iph) or match_aggrules(iph)) 
    {
        ++tpd;
        return;
    }


    /*************/

    ++tpp;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = 0;
    addr.sin_addr   = iph->ip_dst;
    if (sendto(sck, buf+offset, bytes-offset, 0, (const struct sockaddr*)&addr, sizeof addr) < 0)
        perror("Error sending packet");
}

inline void print_options()
{
    printf("1. Add\n2. Delete\n3. Statistics\n4. Clear Stats\n\n"), fflush(stdout);
}

inline void print_types()
{
    printf("1. Block MAC\n2. Block IPs\n3. Block IP Protocol\n"
           "4. Aggregate Rule(Prefix-Port-Proto)\n\n"), fflush(stdout);
}

inline void print_stats(int f=0, int f1=0)
{
    if(f1) goto label;
    printf("1. Blocked MACs: %s",f?"\n\nMAC\t\tNumber of packets\n":"");
    for (auto& m: blocked_macs) 
        print_mac(m.first), f?printf("\t\t%ld\n", m.second):printf(", ");
    printf("\n2. Blocked IPs: %s",f?"\n\nNet\t\tNumber of packets\n":"");
    for (auto& p: blocked_ip4s)
        print_ip4(p.first.first),printf("/%d", __builtin_popcountl(p.first.second)),\
            f?printf("\t\t%ld\n", p.second):printf(", ");
    printf("\n3. Block IP Protocols: %s",f?"\n\nProtocol\tNumber of packets\n":"");
    for (auto& p: blocked_ip_p)
        printf("%-7s",ip_p_list[p.first].c_str()),f?printf("\t\t%ld\n",p.second):printf(", ");
    printf("\n4. Compound Rules%s\n", f?"\t\tNumber of packets":"");
label:
    int i=0;
    for (auto it=comp_rules.begin(); it != comp_rules.end(); ++it)
        printf("  %d. ",i++),print_ip4(it->first.prefix.first),printf("/%d:[%d-%d] %s ",\
                __builtin_popcountl(it->first.prefix.second),\
                it->first.port_range.first, it->first.port_range.second, ip_p_list[it->first.proto].c_str()),
        f?printf("\t\t\t%ld\n",it->second):printf("\n");
    if (f) 
        printf("Total Packets processed: %llu\nPackets Dropped: %llu\nPackets Passed: %llu",tpc,tpd,tpp );
    printf("\n\n"), fflush(stdout);
}

inline ip4pref input_pref(int f=0)
{
    unsigned char ip4[4]{0}; int len=0;
    printf("IP Prefix(a.b.c.d/x) %s: ", f?"[default:0.0.0.0/0 - matches everything]":"");
    my_scanf("%hhu.%hhu.%hhu.%hhu/%d", &ip4[0], &ip4[1], &ip4[2], &ip4[3], &len);

    return make_pair(ip4_stol(ip4), ((1l<<32)-1) - ((1l<<32-len)-1));
}

inline macaddr input_mac()
{
    unsigned char mac[6];
    printf("MAC(aa:bb:cc:dd:ee:ff): ");
    my_scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], \
            &mac[3], &mac[4], &mac[5]);

    return mac_stoll(mac);
}

inline pair<int, int> input_port_range()
{
    printf("Port range to be disabled [default: 0-65535, blocks all]: ");
    int st=0, ed=65535;
    my_scanf("%d-%d",&st,&ed);

    return  make_pair(st, ed);
}

void print_ip_p_list()
{
    printf("Protocol list\n");
    for (auto& p: ip_p_list)
        printf("%-4s %2d\n", p.second.c_str(), p.first);
}

inline ipproto input_proto(int f=0)
{
    ipproto ipp=250;
    print_ip_p_list(), printf("\nIP Protocol%s: ", f?" [default matches all]":""); 
    my_scanf("%hhu", &ipp);

    return ipp;
}

inline void add_aggrule()
{
    aggrule R(input_pref(1), input_port_range(), input_proto(1));    
    comp_rules.insert(make_pair(R, 0l));
}


void del_aggrule()
{
    print_stats(0,1);
    printf("Index of the rule to be deleted: ");
    int idx;
    my_scanf("%d", &idx);
    auto it = comp_rules.begin(); 
    if(idx<comp_rules.size()) advance(it, idx), comp_rules.erase(it);
}

void clear_stats()
{
    tpc=tpd=tpp=0;
    for (auto& r: blocked_macs) r.second=0;
    for (auto& r: blocked_ip4s) r.second=0;
    for (auto& r: blocked_ip_p) r.second=0;
    for (auto& r: comp_rules  ) r.second=0;
}


inline void handle_op(int t)
{
    printf("Index of the rule-type of the rule to be %s: ", (t?"added":"deleted"));
    int opt=-1;my_scanf("%d", &opt);
    ipproto ip_p;int idx;
    macaddr mac; ip4pref pref;
    switch(opt) {
        case 1:
            mac = input_mac();

            if (t) blocked_macs.insert(make_pair(mac, 0l));
            else blocked_macs.erase(mac);

            break;

        case 2:
            pref = input_pref();

            if (t) blocked_ip4s.insert(make_pair(pref, 0l));
            else blocked_ip4s.erase(pref);

            break;

        case 3:
            ip_p = input_proto();
            
            if (t) blocked_ip_p.insert(make_pair(ip_p, 0l));
            else blocked_ip_p.erase(ip_p);

            break;

        case 4:
            if (t) add_aggrule(); 
            else   del_aggrule();
            break;
        default:;
    }
}

void user_interface()
{
    while(1) {
        print_options();
        int opt=-1; my_scanf("%d", &opt);
        macaddr mac; int rno;
        switch(opt) {
            case 1:
                print_types();
                handle_op(1);
                break;
            case 2:
                print_stats(0);
                handle_op(0);
                break;
            case 3:
                print_stats(1);
                break;
            case 4:
                clear_stats();
                break;
            default:;
        }
    }
}

void load_rules(const char* fname)
{
    ifstream fin(fname);
    if (not fin.is_open()) return;
    string line;
    while(getline(fin, line)) {
        //printf("%s", line.c_str());
        stringstream ss(line);
        string t;ss>>t;
        if (t=="MAC") {
            string mm;ss>>mm;
            unsigned char m[6];
            sscanf(mm.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]);
            blocked_macs.insert(make_pair(mac_stoll(m), 0l));
        }
        if (t=="AGG") {
            aggrule r; string s; int k;
            unsigned char p, ip[4];
            ss>>s;sscanf(s.c_str(), "%hhu", &r.proto);
            ss>>s;sscanf(s.c_str(), "%hhu.%hhu.%hhu.%hhu/%d", &ip[0],&ip[1],&ip[2],&ip[3],&k);
            r.prefix = make_pair(ip4_stol(ip), ((1ll<<32)-1)-((1ll<<(32-k))-1));
            ss>>s;sscanf(s.c_str(), "%d-%d", &r.port_range.first, &r.port_range.second);
            comp_rules.insert(make_pair(r, 0l));
        }
    }
    fin.close();
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        printf("usage: %s in_intf out_intf\n", argv[0]);
        return 0;
    }

    int sck_read, sck_write;
    if ((sck_read = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) 
        handle_error("socket_r");
    if ((sck_write = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
        handle_error("socket_w");
    
    bind_pkt_socket(sck_read,  argv[2]);
    bind_ip_socket (sck_write, argv[1]);

#ifdef TEST
    load_rules(argc>=4 ? argv[3]: "dummy");
#endif
    thread T(user_interface);

    while(1) {
        int bytes_read;
        if ((bytes_read = recvfrom(sck_read, buf, BUF_SIZE, 0, NULL, NULL)) < 0) {
            perror("Error reading from the socket.\n");
            fflush(stdout);
            continue;
        }
        send_packet(sck_write, bytes_read);
    }
    return 0;
}
