from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib.ip import ipv4_to_bin

class PPanel(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(PPanel, self).__init__( *args, **kwargs)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, ev):
        self.logger.info('switch joined')
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        port_a = 2#ofproto.OFPP_LOCAL
        port_b = 1
        self.patch_panel(port_a, port_b, datapath)
        #self.patch_panel(2, 4, datapath)
        
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
        inst_next_table = []
        inst_next_table.append( parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, []) )
        inst_next_table.append( parser.OFPInstructionGotoTable(table_id=13) )
        
        # make mod-flow message
#         mod_a = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_a, instructions=inst_a)
#         mod_b = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_b, instructions=inst_b)
        mod_a = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_a, instructions=inst_next_table)
        mod_b = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_b, instructions=inst_next_table)
        
        #send message
        #datapath.send_msg(mod_a)
        #datapath.send_msg(mod_b)
        
        #### TEST for multitable
        mod_a = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_a, instructions=inst_a, table_id=13)
        mod_b = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_b, instructions=inst_b, table_id=13)
        
        #send message
        #datapath.send_msg(mod_a)
        #datapath.send_msg(mod_b)
        
        
        #### TEST group table
#         buckets=[ parser.OFPBucket(100, ofproto.OFPP_ANY, ofproto.OFPQ_ALL, out_a) ]
#         msg=parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_ALL, 111, buckets )
#         datapath.send_msg(msg)

        self.send_group_mod(datapath)
        
    def send_group_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        port = 1
        max_len = 2000
        actions = [ofp_parser.OFPActionOutput(port, max_len)]

        weight = 100
        watch_port = 0
        watch_group = 0
        buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,
                                        actions)]

        group_id = 1
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)
