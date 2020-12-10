#include <iostream>
#include <iomanip>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <bits/stdc++.h>

using namespace std;

void parsingHttp(uint8_t* data, int length);
void getHttpURL(uint8_t* data, int length, char* temp);
static uint32_t checkPacket(nfq_data* tb, int &flag, char* url);
static int callback(nfq_q_handle *qhandle, nfgenmsg *nfmsg, nfq_data *nfa, void *data);

void getError(string error) {
    perror(error.c_str());
    exit(1);
}

void printLine() {
	cout << "-----------------------------------------------" << endl;
}

void printByHexData(u_int8_t *printArr, int length) {
	for(int i=0; i<length; i++) {
		if(i%16 == 0)
			cout << endl;
		cout << setfill('0');
		cout << setw(2) << hex << (int)printArr[i] << " ";
	}
	cout << dec << endl;
	printLine();
}

int main(int argc, char *argv[]) {
    struct nfq_handle* handle = nfq_open();

    /*open lib handle*/
    if(!handle)
        getError("error during nfq_open()");

    /*unbinding existing nf_queue handler for AF_INET*/
    if(nfq_unbind_pf(handle,AF_INET) < 0)
        getError("error during nfq_unbind_pf()");

    /*binding nfnetlink_queue as nf_queue handler for AF_INET*/
    if(nfq_bind_pf(handle,AF_INET) < 0)
        getError("error during nfq_bind_pf()");

    /*binding this socket to queue '0'*/
    struct nfq_q_handle* qhandle = nfq_create_queue(handle, 0, &callback, argv[1]); //you can give user defined parameter at last parameter. (e.g., nfq_create_queue(handle,0,&callback,&userClass);)
    if(!qhandle)
        getError("error during nfq_create_queue()");

    /*setting copy_packet mode*/

    if(nfq_set_mode(qhandle, NFQNL_COPY_PACKET, 0xffff) < 0)
        getError("can't set packet_copy mode");

    int fd = nfq_fd(handle);
    int rv=0;
    char buf[4096] __attribute__ ((aligned));


    while (true) {
        if((rv=recv(fd,buf,sizeof(buf),0))>=0) //if recv success
            nfq_handle_packet(handle,buf,rv); //call callback method
    }
    return 0;
}

void parsingHttp(uint8_t* data, int length) {
  char temp[length] = {0,};

  for(int i=0; i<length; i++) {
    if(data[i] == 0x0d && data[i+1] == 0x0a) {
      sprintf(temp, "%s\n", temp);
      i++;
    } else {
      sprintf(temp, "%s%c", temp, data[i]);
    }
  }

  sprintf(temp, "%s%x", temp, 0x00);
  cout << temp << endl;
}

int parsingHttpLine(uint8_t* data, int length) {
  int i;
  // char temp[4096] __attribute__ ((aligned));;

  for(i=0; i<length; i++) {
    if(data[i] == 0x0d && data[i+1] == 0x0a) {
      break;
    } else {
      // sprintf(temp, "%s%c", temp, data[i]);
    }
  }

  return i+2;
}

void getHttpURL(uint8_t* data, int length, char* packetURL) {
  // parsing the http packet and find the URL ("Host: ")

  int num = parsingHttpLine(data, length);
  data += num;

  sprintf(packetURL, "%c", data[0]);
  for(int i=1; i<length-num; i++){
    if(data[i] == 0x0d && data[i+1] == 0x0a) {
      break;
    } else {
      sprintf(packetURL, "%s%c", packetURL, data[i]);
    }
  }

  // cout << "[The host name] " << packetURL << endl;
  cout << endl;
}

static uint32_t checkPacket(nfq_data* tb, int &flag, char* url) {
  // cout << "In checkPacket: " << url << endl;
  int id, protocol, hook = 0;
  struct nfqnl_msg_packet_hdr *ph;

  ph = nfq_get_msg_packet_hdr(tb);
  if(ph) {
    id = ntohl(ph->packet_id);
    protocol = ntohl(ph->hw_protocol);
    hook = ph->hook;
  }

  uint8_t* data;
  int ret = nfq_get_payload(tb, &data);

  if(ret <= 0) { //no ip packet
      return id;
  }

  //
  flag = NF_ACCEPT;

  // packet header
  struct ip* ipHeader;
  struct tcphdr* tcpHeader;

  ipHeader = (struct ip*)data;
  int ipHeaderLength = ipHeader->ip_hl * 4;

  if(ipHeader->ip_p == IPPROTO_TCP) { // check if it is tcp header
    data += ipHeaderLength;
    tcpHeader = (struct tcphdr*)data;
    int tcpHeaderLength = tcpHeader->doff * 4;
    int destPort = htons(tcpHeader->dest);
    int sourPort = htons(tcpHeader->source);

    cout << "destPort: " << destPort << endl;
    cout << "sourPort: " << sourPort << endl;

    if(sourPort == 0x0050) { // http port: 80(0x0050)
      data += tcpHeaderLength;

      if((ret-ipHeaderLength-tcpHeaderLength) > 0) {
        // Editing: Need to fetch packet URL and compare
        char packetURL[4096] __attribute__ ((aligned));
        getHttpURL(data, ret-ipHeaderLength-tcpHeaderLength, packetURL);
        cout << packetURL << endl;
        cout << url << endl;
        int isURL = strcmp((char*)url, (char*)packetURL);
        cout << isURL << endl;

        if(isURL == 0) {
          // If the URL you want to block, then block it.
          flag = NF_DROP;
        }
      }
    }
  }

  return id;
}

static int callback(nfq_q_handle *qhandle, nfgenmsg *nfmsg, nfq_data *nfa, void *data) {
  (void)nfmsg;
  char url[4096] __attribute__ ((aligned));

  int flag = 0;
  sprintf(url, "Host: %s", (char*)data);
  // cout << "callback: " << url << endl;
  uint32_t id = checkPacket(nfa, flag, url); // call another method

  // cout << "test callback: " << (char*)data << endl;

  return nfq_set_verdict(qhandle, id, flag, 0, NULL);
}
