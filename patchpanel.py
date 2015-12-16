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
        
        # make mod-flow message
        mod_a = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_a, instructions=inst_a)
        mod_b = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match_b, instructions=inst_b)
        
        #send message
        datapath.send_msg(mod_a)
        datapath.send_msg(mod_b)
