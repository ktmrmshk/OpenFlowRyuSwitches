from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib.ip import ipv4_to_bin, ipv4_to_bin

from ryu.ofproto.ether import ETH_TYPE_8021Q
from ryu.ofproto import ether

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import addrconv

import socket
import struct

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
import json
import logging
ppanel_instance_name = 'ppanel_app'

### USE rest api instread!
# kita_vid = None
# kita_lago_ip = "10.0.0.100"
# kita_lago_mac = "90:e2:ba:92:e2:cc"
# kita_lago_port = 1
#
#  ex) curl -X PUT -d '{"mac" : "90:e2:ba:92:e2:cc", "ip" : "10.0.0.100"}' http://127.0.0.1:8080/conf/nw/0000000000000001


class PPanel(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    #for rest interface
    _CONTEXTS = { 'wsgi': WSGIApplication }
    
    def __init__(self, *args, **kwargs):
        super(PPanel, self).__init__( *args, **kwargs)
        
        '''
        eliminate 'my_nw' to use new 'subnet'
        
        subnet = [ { '123456789(dpid)':{'subname':'net1', 'ip':'192.168.0.1',
                         'netmask':'255.255.255.0', 'mac':'11:22:33:44:55:66', 
                         'arp_table':[], port} ####'member_port':{'untagged':[], 'tagged':[], 'vid':'123'}},
                          { subnet2 } ... },
                   { '34567812(dpid)': {subnetA}, {subnetB} ... }, ...  ] 
        my_sub1 = subnet['123456789']
        my_sub1['subname'] = 'yolo_net2'
        my_sub1['ip'] = '192.168.0.1'
        ....
        
        similarly 'arp_table' and 'route_table' have dpid be key of dictionary
        
        '''
        self.my_nw={}
        self.my_nw['ip']=None
        self.my_nw['mac']=None
        self.my_nw['mask']=None
        self.my_nw['gw']=None

        self.subnet={}
        self.route_table = {}
        #self.arp_table = {}
        self.switches = {}
        
        
        # for rest api
        wsgi = kwargs['wsgi']
        wsgi.register(PPanelController, {ppanel_instance_name : self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, ev):
        '''
        [set_feature]
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.clear_table(datapath)
        
        # set init
        self.switches[datapath.id] = datapath
        #self.arp_table.setdefault(datapath.id, {})
        self.route_table.setdefault(datapath.id, [])
        self.subnet.setdefault(datapath.id, {})
        
        print self.switches
        #print self.arp_table
        print self.route_table
        print self.subnet
        
        self.logger.info('switch joined: dpid=%016x' % datapath.id)
        
        self.default_drop(datapath, 1)
        #self.default_drop(ev, 2)

    def __find_subname_from_inport(self, dpid, in_port):
        for k, v in self.subnet[dpid].items():
            if str(in_port) == v['port']:
                return k        
        return None
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packetin_handler(self, ev):
        '''
        [packet-in-entry_point]
        '''
        #self.__packetin_arp(ev, kita_lago_mac, kita_lago_port, kita_lago_ip, kita_vid)
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        
        if not pkt_ethernet:
            return
        
        #arp
        subname=self.__find_subname_from_inport(datapath.id, in_port)
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            #if pkt_arp.dst_ip == self.my_nw['ip']:
            if subname == None:
                return
            if pkt_arp.dst_ip == self.subnet[datapath.id][subname]['ip']:
                #self._handle_arp(datapath, port, pkt_ethernet, pkt_arp, mac, ip, vid)
                self._handle_arp(ev, subname)
            return

        #icmp
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4.dst == self.subnet[datapath.id][subname]['ip']:
            pkt_icmp = pkt.get_protocol(icmp.icmp)
            if pkt_icmp:
                self._handle_icmp(ev, subname)
                return
            else:
                '''ip dest of incoming packet is switch but not icmp packet'''       
                return
        else:
            '''ip packet and ip dest is not to this swtich ==> routing'''
            self._handle_route_packet(ev)
            pass
        return

    def _handle_route_packet(self, ev):
        #print '_handle_route_packet()'
        msg = ev.msg
        datapath = msg.datapath
        
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
#         pkt_icmp = pkt.get_protocol(icmp.icmp)
        in_port = msg.match['in_port']
        
        ### find next hop
        nexthop = self._find_next_hop( datapath.id, pkt_ipv4.dst)
        if nexthop == None:
            return
        print 'nexthop=',nexthop        
        
        ### resolve subnet routing 
        fwd_subname=None
        for subname_, val in self.subnet[datapath.id].items():
            if self.is_same_subnet(nexthop, val['network_address'], val['netmask']):
                fwd_subname=subname_
                break
        print 'fwd_subnmane=', fwd_subname
        
        if fwd_subname==None:
            print 'routing of %s is not found' % nexthop
            return 
        
        ### resolve apr
        dst_mac=self._get_mac_from_ip(datapath.id, nexthop, fwd_subname)        
        print 'dst_ip=%s, dst_mac=%s' % (nexthop, dst_mac)
        
        if dst_mac == None:
            print 'arp to %s is not resolved' % nexthop
            return
        
        print 'arp to %s is resolved' % nexthop
        
        #### set flow table
        parser = datapath.ofproto_parser
        #print 'in_port=%d' % in_port, type(in_port)
        src_port=in_port
        src_subname=self.__find_subname_from_inport(datapath.id, in_port)
        #src_network_address = self.subnet[datapath.id][src_subname]['network_address']
        #src_netmask = self.subnet[datapath.id][src_subname]['netmask']
        priority=5001
        match_to_dst = parser.OFPMatch(in_port=in_port, eth_dst=self.subnet[datapath.id][src_subname]['mac'], eth_type=0x800, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst)
        actions_to = []
        actions_to.append(parser.OFPActionSetField( eth_src=self.subnet[datapath.id][fwd_subname]['mac'] ))
        actions_to.append(parser.OFPActionSetField( eth_dst=dst_mac ))
        actions_to.append(parser.OFPActionOutput(int(self.subnet[datapath.id][fwd_subname]['port']), 0) )
        #actions_to = []
        self.add_flow(datapath, priority, match_to_dst, actions_to)
        
        match_from_dst=parser.OFPMatch(in_port=int(self.subnet[datapath.id][fwd_subname]['port']), eth_dst=self.subnet[datapath.id][fwd_subname]['mac'], eth_type=0x800, ipv4_src=pkt_ipv4.dst, ipv4_dst=pkt_ipv4.src)
        actions = []
        actions.append(parser.OFPActionSetField( eth_src=self.subnet[datapath.id][src_subname]['mac'] ))
        actions.append(parser.OFPActionSetField( eth_dst=pkt_ethernet.src ))
        actions.append( parser.OFPActionOutput(in_port, 0) )
        self.add_flow(datapath, priority+1, match_from_dst, actions)       
        
        ### packet out original
        pkt_ethernet.src = self.subnet[datapath.id][fwd_subname]['mac']
        pkt_ethernet.dst = dst_mac
        out_port = int(self.subnet[datapath.id][fwd_subname]['port'])
        
        #out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                          in_port=in_port, actions=actions_to, data=msg.data)
        #datapath.send_msg(out)
        self._send_packet(datapath, out_port, pkt)
        
    def _find_next_hop(self, dpid, dst_ip):
        for entry in self.route_table[dpid]:
            if self.is_same_subnet(dst_ip, entry['dst_ip'], entry['netmask']):
                if entry['connected']:
                    return dst_ip
                else:
                    return entry['nexthop']
        else:
            print "no route"
            return None
        
    def _get_mac_from_ip(self, dpid, target_ip, subname):
        '''
        return mac, or None if arp cannnot be resolved 
        '''
        dst_mac = self.__get_mac_from_ip_in_arptable(self.subnet[dpid][subname]['arp_table'], target_ip)
        if dst_mac != None:
            return dst_mac

        self._solve_arp(dpid, target_ip, subname)
        import time
        #print 'sleeping....'
        time.sleep(1)
        dst_mac = self.__get_mac_from_ip_in_arptable(self.subnet[dpid][subname]['arp_table'], target_ip)
        return dst_mac   
        
    def __get_mac_from_ip_in_arptable(self, arp_table, target_ip):
        for ip_, mac_ in arp_table.items():
            if target_ip == ip_:
                return mac_
        else:
            return None
        
    def _solve_arp(self, dpid, target_ip, subname):
        out_port = int(self.subnet[dpid][subname]['port'])
        my_ip = self.subnet[dpid][subname]['ip']
        my_mac = self.subnet[dpid][subname]['mac']
        self.request_arp(dpid, out_port, target_ip, my_ip, my_mac)
            
    ###### on coding part ##### move this part other line later ....
    def init_subnet(self, datapath, subname, ip, netmask, mac, port):
        network_address = self.get_network_address_text(ip, netmask)
        self.subnet[datapath.id][subname] = {'ip':ip, 'netmask':netmask, 'mac':mac, 'port':port, 'arp_table':{}, 'network_address':network_address }
        #self.route_table[datapath.id].append( {'dst_ip': network_address, 'netmask': netmask, 'connected': True, 'nexthop': None, 'interface':port} )
        self.set_route_table(datapath.id, port, network_address, netmask, None, True)
        self.set_arp_icmp_packetin(datapath, int(port), ip, priority=3000)
        
        ### conf packet fwd among local network
        self.set_local_subnet_packetin(datapath, subname)
        
        print 'self.subnet=', self.subnet
        print 'self.route=',self.route_table
        return
    
    def set_route_table(self, dpid, interface, dst_ip, netmask, nexthop, connected=False):
        self.route_table[dpid].append({'dst_ip': dst_ip, 'netmask': netmask, 'connected': connected, 'nexthop': nexthop, 'interface':interface})
    
    def set_local_subnet_packetin(self, datapath, subname, priority=2000):
        import netaddr
        ip=netaddr.IPAddress('192.168.0.1')

        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        port=int(self.subnet[datapath.id][subname]['port'])
        network_address=self.subnet[datapath.id][subname]['network_address']
        mac=self.subnet[datapath.id][subname]['mac']
        netmask=self.subnet[datapath.id][subname]['netmask']
        
        
        ### following codes don't work at netmask functionality, but I have no idea....
#         match_icmp_from_local = parser.OFPMatch()
#         match_icmp_from_local.append_field(ofproto.OXM_OF_IN_PORT, 1)
#         match_icmp_from_local.append_field(ofproto.OXM_OF_ETH_TYPE, 0x800)
#         match_icmp_from_local.append_field(ofproto.OXM_OF_IPV4_SRC, self.ipv4_text_to_int('10.0.0.0'), 0xffff0000)#mask=self.ipv4_text_to_int(netmask))
#         match_icmp_from_local.append_field(ofproto.OXM_OF_IP_PROTO, socket.IPPROTO_ICMP)
        
        match_icmp_from_local=parser.OFPMatch(in_port=port, eth_dst=mac, eth_type=0x800, ipv4_src=(network_address, netmask))
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority+1, match_icmp_from_local, actions)
                 
    #def set_arp_icmp_packetin(self, ev, port, ip, priority=10):
    def set_arp_icmp_packetin(self, datapath, port, ip, priority=3000):
        #msg = ev.msg
        #datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match_arp = parser.OFPMatch(in_port=port, eth_type=0x806, arp_tpa=ip)
        match_icmp = parser.OFPMatch(in_port=port, eth_type=0x800, ip_proto=1, ipv4_dst=ip)
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority, match_arp, actions)
        self.add_flow(datapath, priority+1, match_icmp, actions)

    ''' APPS '''
    def _handle_arp(self, ev, subname):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_arp = pkt.get_protocol(arp.arp)
        
        if pkt_arp.opcode == arp.ARP_REPLY: 
            self.subnet[datapath.id][subname]['arp_table'][pkt_arp.src_ip]=pkt_arp.src_mac
            self.logger.info('arp_table: %s ' % json.dumps(self.subnet))  
            return
        
        elif pkt_arp.opcode == arp.ARP_REQUEST:
            #ingest arp_table
            self.subnet[datapath.id][subname]['arp_table'][pkt_arp.src_ip]=pkt_arp.src_mac
            self.logger.info('arp_table: %s ' % json.dumps(self.subnet))  
            
            this_subnet=self.subnet[datapath.id][subname]
            #generating arp packet
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src, src=this_subnet['mac']))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                src_mac=this_subnet['mac'],
                src_ip =this_subnet['ip'],
                dst_mac=pkt_arp.src_mac,
                dst_ip=pkt_arp.src_ip))
            self._send_packet(datapath, in_port, pkt)
            self.logger.info("arp reply is sent: %s-%s -> %s-%s via port=%s" % (this_subnet['mac'], this_subnet['ip'], pkt_arp.src_mac, pkt_arp.src_ip, in_port) )
            return
        else:
            return

    def _handle_icmp(self, ev, subname):
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        in_port = msg.match['in_port']
         
        # ignore icmp of other than icmp_echo_request
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        # make packet object to return
        this_subnet=self.subnet[datapath.id][subname]
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
            dst=pkt_ethernet.src,
            src=this_subnet['mac']))
#             if vid != None:
#             pkt.add_protocol(vlan.vlan(vid=vid, ethertype = 0x0800))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
            src=this_subnet['ip'],
            proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
            code=icmp.ICMP_ECHO_REPLY_CODE,
            csum=0,
            data=pkt_icmp.data))
        self._send_packet(datapath, in_port, pkt)
        self.logger.info("icmp reply is sent: %s-%s via port=%s" % (pkt_ethernet.src, pkt_ipv4.src, in_port) )      

    def send_ping(self, datapath, src_mac, dst_mac, src_ip, dst_ip, outport=1, seq=0):
        ttl = 64

        e = ethernet.ethernet(dst_mac, src_mac, ether.ETH_TYPE_IP)
        iph = ipv4.ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, src_ip, dst_ip)
        echo = icmp.echo(1, seq, data=None)
        icmph = icmp.icmp(8, 0, 0, echo)
        
        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(iph)
        pkt.add_protocol(icmph)
        
        self._send_packet(datapath, outport, pkt)
        self.logger.info("icmp echo req is sent: to %s" % (dst_ip,) )  
        

    def patch_panel(self, port_a, port_b, datapath, priority=1): 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #set match conditions
        match_a = parser.OFPMatch(in_port=port_a)
        match_b = parser.OFPMatch(in_port=port_b)
        
        #set action = output to each port
        out_a = [ parser.OFPActionOutput(port_b, 0) ]
        out_b = [ parser.OFPActionOutput(port_a, 0) ]

        #set instruction for mod-flow
        inst_a = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, out_a) ]
        inst_b = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, out_b) ]
        
        # make mod-flow message
        mod_a = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_a, instructions=inst_a)
        mod_b = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_b, instructions=inst_b)
        
        #send message
        datapath.send_msg(mod_a)
        datapath.send_msg(mod_b)

    def ip_fwd(self, datapath, nw, priority=100):
        '''
        this is for TESTCENTER flow
        nw = {'src_ip':'192.168.1.12', 'in_port':1,
            'fwd_list':[{'fwd_ip':'192.168.0.1', 'gw_mac':'12:34:56:78:9a:cd', 'out_port':1}, {}, {}..]
            }
        usually dst_ip/port is lagopus's ip/port [optional]
        
        [mandatory]
        src_ip, in_port, fwd_ip, out_port, gw_mac
        '''
        #msg = ev.msg
        #datapath = msg.datapath
        nw.setdefault('dst_ip', self.my_nw['ip'])
        nw.setdefault('dst_mac', self.my_nw['mac'])
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # this part needs to be improved

        match = parser.OFPMatch(in_port=nw['in_port'], eth_type=0x800,
                ipv4_dst=nw['dst_ip'],
                ipv4_src=nw['src_ip']
                )
        actions = []
        actions.append(parser.OFPActionSetField( eth_src=nw['dst_mac'] ))
        actions.append(parser.OFPActionSetField( ipv4_src=nw['dst_ip'] ))
        for fwd in nw['fwd_list']:
            actions.append(parser.OFPActionSetField( ipv4_dst=fwd['fwd_ip'] ))
            actions.append(parser.OFPActionSetField( eth_dst=fwd['gw_mac'] ))
            actions.append( parser.OFPActionOutput(fwd['out_port'], 0) )
        self.add_flow(datapath, priority, match, actions)


    def udp_fwd(self, datapath, nw, priority=500):
        '''
        nw = {'src_ip':'10.0.0.3', 'in_port':1,
            'dst_ip'='10.0.0.1', 'dst_port': 9001, 'dst_mac':'00:11:22:33:44:55',
            'fwd_list':[{'fwd_ip':'192.168.0.1', 'fwd_port':6200 ,'gw_mac':'12:34:56:78:9a:cd', 'out_port':1}, {}, {}..]
            }
        usually dst_ip/port is lagopus's ip/port [optional]
        
        param list M:mandatory O:option *:usually specified
        ===========
        priority    O
        
        [match]
        in_port      M
        src_ip       O *
        src_port     O
        src_mac      O
        listen_ip    O
        listen_port  O *
        
        [action]
        out_port    M
        gw_mac      M
        fwd_ip      M
        fwd_port    O *
        '''
        if 'priority' in nw:
            priority=nw['priority']
        
        match_cond = {}
        match_cond['eth_type']=0x800
        match_cond['in_port']=nw['in_port']
        match_cond['ip_proto']=socket.IPPROTO_UDP
        if 'src_ip' in nw:
            match_cond['ipv4_src']=nw['src_ip']
        if 'src_port' in nw:
            match_cond['udp_src']=nw['src_port']
        if 'src_mac' in nw:
            match_cond['eth_src']=nw['src_mac']
        if 'listen_ip' in nw:
            match_cond['ipv4_dst']=nw['listen_ip']
        if 'listen_port' in nw:
            match_cond['udp_dst']=nw['listen_port']
      
        #msg = ev.msg
        #datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
  
        match = parser.OFPMatch(**match_cond)  

        actions = []
        actions.append(parser.OFPActionSetField( eth_src=self.my_nw['mac'] ))
        if 'listen_port' in nw:
            actions.append(parser.OFPActionSetField( ipv4_src=nw['listen_ip'] ))
        for fwd in nw['fwd_list']:
            actions.append(parser.OFPActionSetField( ipv4_dst=fwd['fwd_ip'] ))
            if 'fwd_port' in fwd:
                actions.append(parser.OFPActionSetField( udp_dst=fwd['fwd_port'] ))
            actions.append(parser.OFPActionSetField( eth_dst=fwd['gw_mac'] ))
            actions.append( parser.OFPActionOutput(fwd['out_port'], 0) )
        self.add_flow(datapath, priority, match, actions)

    def udp_dup(self, ev, src_nw, dst_nws, dstip, priority=100):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_nw['port'], eth_type=0x800,
                ip_proto=socket.IPPROTO_UDP, 
                ipv4_dst=dstip)
        actions = []
        
        is_vlan_pushed = False
        if src_nw['vid'] != None:
            is_vlan_pushed = True

        for dst_nw in dst_nws:
            if dst_nw['vid'] == None:
                if is_vlan_pushed == True:
                    actions.append( parser.OFPActionPopVlan(ETH_TYPE_8021Q) )
                else:
                    pass

            else: # dst vlan 
                if is_vlan_pushed == False:
                    field = parser.OFPMatchField.make(ofproto.OXM_OF_VLAN_VID, dst_nw['vid'])
                    actions.append( parser.OFPActionPushVlan(ETH_TYPE_8021Q) )
                    actions.append( parser.OFPActionSetField(field))
                    is_vlan_pushed=True
                else:
                    actions.append( parser.OFPActionSetField( vlan_vid=dst_nw['vid'] ) )

            
            actions.append(parser.OFPActionSetField( ipv4_dst=dst_nw['ip'] ))
            actions.append(parser.OFPActionSetField( ipv4_src=dst_nw['gw_ip'] ))
            actions.append(parser.OFPActionSetField( eth_dst=dst_nw['mac'] ))
            actions.append(parser.OFPActionSetField( eth_src=dst_nw['gw_mac'] ))
            actions.append( parser.OFPActionOutput(dst_nw['port'], 0) )
            self.add_flow(datapath, priority, match, actions)


    def get_subnet(self):
        return self.subnet

    ''' GENERAL '''
    
    def request_arp(self, dpid, out_port, target_ip, my_ip, my_mac):
        #generating arp packet
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP, dst='ff:ff:ff:ff:ff:ff', src=my_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
            src_mac=my_mac,
            src_ip =my_ip,
            dst_mac='00:00:00:00:00:00',
            dst_ip=target_ip))
        dp = self.switches[dpid]
        self._send_packet(dp, out_port, pkt)    
    
    
    def default_pktin(self, datapath, port=None, priority=0):
        #msg = ev.msg
        #datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = None
        if port != None:
            match = parser.OFPMatch(in_port=port)
            prio = priority+1
        else:
            match = parser.OFPMatch()
            prio = priority
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS, actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=prio, match=match, instructions=inst)
        datapath.send_msg(mod)

    def default_drop(self, datapath, port=None, priority=0):
        #msg = ev.msg
        #datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = None
        if port != None:
            match = parser.OFPMatch(in_port=port)
            prio = priority+1
        else:
            match = parser.OFPMatch()
            prio = priority
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS, actions=[])]
        mod = parser.OFPFlowMod(datapath=datapath, priority=prio, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=data)
        datapath.send_msg(out)
        
    def clear_table(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS, actions=[])]
        mod = parser.OFPFlowMod(datapath=datapath,  match=match, instructions=inst, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)        
        datapath.send_msg(mod)

    def ipv4_text_to_int(self, ip_text):
        if ip_text == 0:
            return ip_text
        assert isinstance(ip_text, str)
        return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
    
    def ipv4_to_str(self, ip):
        if isinstance(ip, int):
            return addrconv.ipv4.bin_to_text(struct.pack("!I", ip))
        else:
            return addrconv.ipv4.bin_to_text(ip)

    def is_same_subnet(self, ip1, ip2, mask):
        masked1=self.ipv4_text_to_int(ip1) & self.ipv4_text_to_int(mask)
        masked2=self.ipv4_text_to_int(ip2) & self.ipv4_text_to_int(mask)
        if masked1 == masked2:
            return True
        else:
            return False
    
    def get_network_address_text(self, ip_text, mask_text):
        masked = self.ipv4_text_to_int(ip_text) & self.ipv4_text_to_int(mask_text)
        return self.ipv4_to_str(masked)
        
         

    ''' SANDBOX CODES '''
    # nw = {'ip':'192.168.1.1', 'mac':'aa:bb:cc:dd:ee:ff', 'port': 1, 'gw_mac': '00:bb:cc:11:cc:11'}
    def udp_route(self, ev, src_nw, dst_nw, priority=100):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_nw['port'], eth_type=0x800,
                ip_proto=socket.IPPROTO_UDP, 
                ipv4_dst=dst_nw['ip'],
                ipv4_src=src_nw['ip'])
        #actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
        actions = []
        if dst_nw['vid'] == None and src_nw['vid'] == None:
            pass
        elif dst_nw['vid'] != None and src_nw['vid'] == None:
            field = parser.OFPMatchField.make(ofproto.OXM_OF_VLAN_VID, dst_nw['vid'])
            actions.append( parser.OFPActionPushVlan(ETH_TYPE_8021Q) )
            actions.append( parser.OFPActionSetField(field))
        elif dst_nw['vid'] == None and src_nw['vid'] != None:
            actions.append( parser.OFPActionPopVlan(ETH_TYPE_8021Q) )
        elif dst_nw['vid'] != None and src_nw['vid'] != None:
            pass
        else:
            pass # error!
            
        actions.append(parser.OFPActionSetField( eth_dst=dst_nw['mac'] ))
        actions.append(parser.OFPActionSetField( eth_src=dst_nw['gw_mac'] ))
        actions.append( parser.OFPActionOutput(dst_nw['port'], 0) )
        self.add_flow(datapath, priority, match, actions)
    # nw = {'ip':'192.168.1.1', 'mac':'aa:bb:cc:dd:ee:ff', 'port': 1, 'gw_mac': '00:bb:cc:11:cc:11'}

    def udp_route_nat(self, ev, src_nw, dst_nw, priority=100):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_nw['port'], eth_type=0x800,
                ip_proto=socket.IPPROTO_UDP, 
                ipv4_dst=src_nw['gw_ip'],
                ipv4_src=src_nw['ip'])
        #actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
        actions = []
        if dst_nw['vid'] == None and src_nw['vid'] == None:
            pass
        elif dst_nw['vid'] != None and src_nw['vid'] == None:
            field = parser.OFPMatchField.make(ofproto.OXM_OF_VLAN_VID, dst_nw['vid'])
            actions.append( parser.OFPActionPushVlan(ETH_TYPE_8021Q) )
            actions.append( parser.OFPActionSetField(field))
        elif dst_nw['vid'] == None and src_nw['vid'] != None:
            actions.append( parser.OFPActionPopVlan(ETH_TYPE_8021Q) )
        elif dst_nw['vid'] != None and src_nw['vid'] != None:
            pass
        else:
            pass # error!
            
        actions.append(parser.OFPActionSetField( eth_dst=dst_nw['mac'] ))
        actions.append(parser.OFPActionSetField( eth_src=dst_nw['gw_mac'] ))
        actions.append(parser.OFPActionSetField( ipv4_src=dst_nw['gw_ip'] ))
        actions.append(parser.OFPActionSetField( ipv4_dst=dst_nw['ip'] ))
        actions.append( parser.OFPActionOutput(dst_nw['port'], 0) )
        self.add_flow(datapath, priority, match, actions)

    def patch_panel_arp_oneway(self, inport, outport, in_ip, in_gw_ip, out_ip, out_gw_ip, datapath, in_vid=None, out_vid=None, priority=100):
        '''
        [sandbox codes]
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=inport, eth_type=0x0806, arp_spa=in_ip, arp_tpa=in_gw_ip)
        if in_vid != None:
            match.set_vlan_vid(in_vid)
        action = []
        #action.append( parser.OFPActionSetField( eth_dst = out_ip ))
        #action.append( parser.OFPActionSetField( eth_src = out_gw_ip))
        action.append( parser.OFPActionSetField( arp_tpa = out_ip ))
        action.append( parser.OFPActionSetField( arp_spa = out_gw_ip))
        if in_vid != None:
            action.append( parser.OFPActionPopVlan(ETH_TYPE_8021Q) )
        if out_vid != None:
            #pass
            action.append(parser.OFPActionPushVlan(ETH_TYPE_8021Q))
            field = parser.OFPMatchField.make(ofproto.OXM_OF_VLAN_VID, out_vid)
            action.append( parser.OFPActionSetField(field) )
        action.append(parser.OFPActionOutput(outport, 0))
        inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action) ]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def patch_panel_oneway(self, inport, outport, in_ip, in_gw_ip, out_ip, out_gw_ip, datapath, in_vid=None, out_vid=None, priority=1):
        '''
        [sandbox codes]
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=inport, eth_type=0x800, ipv4_src=in_ip, ipv4_dst=in_gw_ip)
        if in_vid != None:
            match.set_vlan_vid(in_vid)
        
        action = []
        if in_vid != None:
            action.append( parser.OFPActionPopVlan(ETH_TYPE_8021Q) )
        if out_vid != None:
            #pass
            action.append(parser.OFPActionPushVlan(ETH_TYPE_8021Q))
            field = parser.OFPMatchField.make(ofproto.OXM_OF_VLAN_VID, out_vid)
            action.append( parser.OFPActionSetField(field) )
        action.append( parser.OFPActionSetField( ipv4_dst = out_ip ))
        action.append( parser.OFPActionSetField(ipv4_src= out_gw_ip))
        action.append(parser.OFPActionOutput(outport, 0))
        inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action) ]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

class PPanelController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PPanelController, self).__init__(req, link, data, **config)
        self.ppanel_app = data[ppanel_instance_name]
    
    @route('ppanel_app', '/stat/subnet/', methods=['GET'], requirements={})
    def list_subnet(self, req, **kwargs):
        sw = self.ppanel_app
        subnet = sw.get_subnet()
        return Response(content_type='application/json', body=json.dumps(subnet, indent=2))

    @route('ppanel_app', '/stat/route_table/', methods=['GET'], requirements={})
    def list_route_table(self, req, **kwargs):
        sw = self.ppanel_app
        return Response(content_type='application/json', body=json.dumps(sw.route_table, indent=2))
    
    @route('ppanel_app', '/stat/route_table/{dpid}/', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def set_route(self, req, **kwargs):
        '''usage:
        curl -X PUT -d '{"interface":"1", "dst_ip":"10.0.20.100", "netmask":"255.255.255.0", "nexthop":"10.0.0.1"}' http://127.0.0.1:8080//stat/route_table/0000000000000001
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        body_args = eval(req.body)
        interface = body_args['interface']
        dst_ip = body_args['dst_ip']
        netmask = body_args['netmask']
        nexthop = body_args['nexthop']
        
        sw.set_route_table(dpid, interface, dst_ip, netmask, nexthop)
        return Response(content_type='application/json', body=json.dumps(sw.route_table[dpid], indent=2))
 
    @route('ppanel_app', '/test/request_arp/{dpid}/{ip}/{port}', methods=['GET'],
            requirements={'dpid':dpid_lib.DPID_PATTERN, 'ip':r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' ,'port':r'[0-9]+'})
    def reqest_arp(self, req, **kwargs):
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        ip = kwargs['ip']
        port = int(kwargs['port'])
        
        sw.request_arp(dpid, port, ip, kita_lago_ip, kita_lago_mac)
        return Response(content_type='application/json', body=json.dumps([dpid, ip, port]))

    @route('ppanel_app', '/conf/nw/{dpid}', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def conf_switch(self, req, **kwargs):
        '''usage:
        curl -X PUT -d '{"mac":"90:e2:ba:92:e2:cc", "ip":"10.0.0.100", "mask":"255.255.255.0", "gw":"10.0.0.1"}' http://127.0.0.1:8080/conf/nw/0000000000000001
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        nw_ = eval(req.body)
        sw.my_nw['ip'] = nw_['ip']
        sw.my_nw['mac'] = nw_['mac']
        #sw.my_nw['mask'] = nw_['mask']
        #sw.my_nw['gw'] = nw_['gw']
        sw.my_nw['port'] = 1
        
        sw.set_arp_icmp_packetin(sw.switches[dpid], sw.my_nw['port'], sw.my_nw['ip'])
        sw.default_drop(sw.switches[dpid], sw.my_nw['port'] )
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'}))

    @route('ppanel_app', '/conf/clear_table/{dpid}', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def clearall_table(self, req, **kwargs):
        '''usage:
        curl -X PUT http://127.0.0.1:8080/conf/clear_table/0000000000000001
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        sw.clear_table(sw.switches[dpid])
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'}))
    
    
    @route('ppanel_app', '/conf/add_ip_fwd/{dpid}', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def add_ip_fwd(self, req, **kwargs):
        '''usage
        curl -X PUT \
         -d 'nw = {'src_ip':'192.168.1.12', 'in_port':1,
            'fwd_list':[{'fwd_ip':'192.168.0.1', 'gw_mac':'12:34:56:78:9a:cd', 'out_port':1}, {}, {}..]
            }
         http://127.0.0.1:8080/conf/add_ip_fwd/0000000000000001
        
        src_ip, in_port, [(gw_mac, out_port,fwd_ip)]
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])        
        nw_ = eval(req.body)
        sw.ip_fwd(sw.switches[dpid], nw_, priority=100)
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'}))   
    
    @route('ppanel_app', '/conf/add_udp_fwd/{dpid}', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def add_udp_fwd(self, req, **kwargs):
        '''usage
        curl -X PUT \
         -d '{"src_ip":"192.168.0.10", "dst_port":6000, "in_port":1, "gw_mac":"90:e2:ba:92:e2:ff", "ip" : "10.0.0.100"}' \
         http://127.0.0.1:8080/conf/add_udp_fwd/0000000000000001
        
                src_ip, in_port, gw_mac, out_port,
        fwd_ip,  dst_port
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])        
        nw_ = eval(req.body)
        sw.udp_fwd(sw.switches[dpid], nw_, priority=500)
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'}))
        
    @route('ppanel_app', '/conf/add_udp_fwd2/{dpid}', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def add_udp_fwd2(self, req, **kwargs):
        '''usage
        curl -X PUT \
         -d '
         {
            "priority":500, "in_port":1 ,"src_ip":"192.168.0.1", "listen_port":6200,
            "fwd_list":[ {"out_port":1, "fwd_ip":"192.168.0.2", "fwd_port":6201, "gw_mac":"12:34:56:78:9a:cd"},{}...]
         }
         '
         http://127.0.0.1:8080/conf/add_udp_fwd2/0000000000000001
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])        
        nw_ = eval(req.body)
        nw_.setdefault('priority', 300)
        sw.udp_fwd(sw.switches[dpid], nw_)
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'})) 
    
    @route('ppanel_app', '/stat/flow_table/{dpid}', methods=['GET'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def list_arp(self, req, **kwargs):
        '''
        curl -X GET http://127.0.0.1:8080/stat/flow_table/0000000000000001
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])        
        
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok', 'cmd': 'flow_table', 'dpid': kwargs['dpid']})) 
    
    
    @route('ppanel_app', '/ping/{dpid}/{dst_ip}/{dst_mac}', methods=['GET'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def do_ping(self, req, **kwargs):
        '''
        curl -X GET http://127.0.0.1:8080/ping/0000000000000001/192.168.0.1/
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])  
        dst_ip = kwargs['dst_ip']
        dst_mac = kwargs['dst_mac']
        sw.send_ping(sw.switches[dpid], sw.my_nw['mac'], dst_mac, sw.my_nw['ip'], dst_ip, outport=1)
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok', 'dst': dst_ip, 'dpid': kwargs['dpid']})) 
    
    @route('ppanel_app', '/conf/patch/{dpid}/{port1}/{port2}', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def make_patch(self, req, **kwargs):
        '''usage
        curl -X PUT http://127.0.0.1:8080/conf/patch/0000000000000001/1/2
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        port1=int(kwargs['port1'])
        port2=int(kwargs['port2'])
        sw.patch_panel(port1, port2, sw.switches[dpid])        
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'})) 

    @route('ppanel_app', '/conf/{dpid}/subnet/{subname}', methods=['PUT'], requirements={'dpid':dpid_lib.DPID_PATTERN})
    def do_init_subnet(self, req, **kwargs):
        '''
        body = {'ip':'192.168.123.1', 'netmask':'255.255.255.0', 'mac':'12:34:56:aa:bb:cc', port': '1'}
        '''
        sw = self.ppanel_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        subname = str(kwargs['subname'])
        bdy = eval(req.body)
        ip=bdy['ip']
        netmask=bdy['netmask']
        mac=bdy['mac']
        port=bdy['port']
        sw.init_subnet(sw.switches[dpid], subname, ip, netmask, mac, port)
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'})) 
  
  
    @route('ppanel_app', '/conf/send_arp/', methods=['PUT'], requirements={})
    def send_arp(self, req, **kwargs):
        '''usage
        curl -X PUT \
         -d 'nw = {'dpid':'0000000000000001', 'out_port':'1',
            'target_ip': '192.168.10.1', 'my_ip':'192.168.10.10', 'my_mac':'aa:bb:cc:00:22:33'
             }
         http://127.0.0.1:8080/conf/send_arp/
        
        src_ip, in_port, [(gw_mac, out_port,fwd_ip)]
        '''
        sw = self.ppanel_app
        #dpid = dpid_lib.str_to_dpid(kwargs['dpid'])        
        args = eval(req.body)
        dpid = int(args['dpid'])
        out_port = int(args['out_port'])
        target_ip = args['target_ip']
        my_ip = args['my_ip']
        my_mac = args['my_mac']
        
        #sw.ip_fwd(sw.switches[dpid], nw_, priority=100)
        sw.request_arp(dpid, out_port, target_ip, my_ip, my_mac)
        return Response(content_type='application/json', body=json.dumps({'ret': 'ok'}))   
       
    