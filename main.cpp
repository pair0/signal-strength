#include "main.h"

using namespace std;

void usage(){ //경고 메시지
    printf("signal-strength <interface> <mac>\n");
    printf("signal-strength mon0 00:11:22:33:44:55\n");
}

u_int8_t pcap_antenna(u_int8_t antenna){
    u_int8_t n;
    n = ~antenna;
    n += 1;
    return n;
}

int AP_packet_chapter(char* dev, char* ap_mac){
    struct Radiotap_header* radiotap = (struct Radiotap_header*)malloc(sizeof(struct Radiotap_header));
    struct Beacon* beacon = (struct Beacon*)malloc(sizeof(struct Beacon));
    struct Wireless* wrls = (struct Wireless*)malloc(sizeof(struct Wireless));
    struct S_tag* s_tag = (struct S_tag*)malloc(sizeof(struct S_tag));
    struct DS_tag* ds_tag = (struct DS_tag*)malloc(sizeof(struct DS_tag));
    
    int beacon_count = 0;
    
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        const u_char* ESSID;
        const u_char* Supported_Rates;

        char essid_c[2];
        char *essid_c_final = (char *)calloc(30, sizeof(char));
        char *bssid_c = (char *)calloc(20, sizeof(char));

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        radiotap = (struct Radiotap_header*)packet;
        beacon = (struct Beacon*)(packet+radiotap->length);

        if(beacon->type == 0x0080){
            
            wrls = (struct Wireless*)(packet+radiotap->length+sizeof(struct Beacon));
            ESSID = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless);
            s_tag = (struct S_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len);
            Supported_Rates = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag);
            const u_char* ex = packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag) + s_tag->s_len;
            
            if(ex[0] == 0x03) ds_tag = (struct DS_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag)+s_tag->s_len);
            else ds_tag = (struct DS_tag*)(packet + radiotap->length+sizeof(struct Beacon)+sizeof(struct Wireless)+wrls->ssid_len+sizeof(struct S_tag)+s_tag->s_len);
            
            //bssid 생성
            if(beacon->bssid() == Mac(ap_mac)){
                //beacon 생성
                beacon_count += 1;

                // essid 생성
                for(int i = 0; i<wrls->ssid_len; i++){
                    sprintf(essid_c, "%c", ESSID[i]);
                    strcat(essid_c_final, essid_c);
                }

                system("clear");
                puts("BSSID\t\t\tPWR  Beacons\tCH\tESSID\n");
                if(pcap_antenna(radiotap->Antenna_signal) >= 100){
                    std::cout << std::string(beacon->bssid()) << "\t";
                    printf("-%d \t%d\t%d\t%s\n", pcap_antenna(radiotap->Antenna_signal), beacon_count, ds_tag->current_channel, essid_c_final);
                }else if(pcap_antenna(radiotap->Antenna_signal) < 100 && pcap_antenna(radiotap->Antenna_signal) >= 10 ){
                    std::cout << std::string(beacon->bssid()) << "\t";
                    printf("-%d  \t%d\t%d\t%s\n", pcap_antenna(radiotap->Antenna_signal), beacon_count, ds_tag->current_channel, essid_c_final);
                }else if(pcap_antenna(radiotap->Antenna_signal) < 10){
                    std::cout << std::string(beacon->bssid()) << "\t";
                    printf("-%d   \t%d\t%d\t%s\n", pcap_antenna(radiotap->Antenna_signal), beacon_count, ds_tag->current_channel, essid_c_final);
                }
                free(essid_c_final);
                free(bssid_c);
            }
        }else{ //Probe Request일 시
            packet = packet + radiotap->length;
        }
    }
    printf("\n\n");

    free(radiotap);
    free(beacon);
    free(wrls);
    free(s_tag);
    free(ds_tag);
    pcap_close(pcap);
    return 0;
}

int main(int argc, char** argv){
    char* dev;
    char* ap_mac;

    if (argc == 3){
        dev = *(argv+1);
        ap_mac = *(argv + 2); 
    } else {
        usage();
        return -1;
    }
    
    return AP_packet_chapter(dev, ap_mac);

}