from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

class L2Switch(app_manager.RyuApp):
	def __init__(self, *args, **kwargs):
		super(L2Switch, self).__init__(*args, **kwargs)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		ofp_parser = dp.ofproto_parser
		in_port = msg.match['in_port']
		self.logger.info('pkt_in:%s', in_port)

		actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
		out = ofp_parser.OFPPacketOut(
				datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions)
		dp.send_msg(out)
	
