#include <iostream>
#include <future>

#include "packet_sender.h"
#include "packet_sender_generic.h"

namespace Tins {

	PacketSenderGeneric::PacketSenderGeneric(const NetworkInterface& iface, uint32_t recv_timeout)
		: default_iface(iface), timeout(recv_timeout), sent_pdu(NULL), response_pdu(NULL){
	}

	PacketSenderGeneric::~PacketSenderGeneric()
	{
		//delete spdu;
		//delete rpdu;
	}


	bool PacketSenderGeneric::generic_response_handler(PDU& rpdu)
	{
		if (sent_pdu->matches_response_generic(rpdu))
		{
			response_pdu = rpdu.clone();
			return false;
		}
		return true;
		//else if (running)
		//	return true;
		//else
		//	return false;
	}

	void PacketSenderGeneric::sniff_task(Sniffer* sniffer)
	{
		// Create our handler
		auto handler = std::bind(
			&PacketSenderGeneric::generic_response_handler,
			this,
			std::placeholders::_1);

		sniffer->sniff_loop(handler);
	}

	PDU& PacketSenderGeneric::send_recv(PDU& spdu, const NetworkInterface& iface)
	{
		//wait for previous packet to receive response (TODO: not ideal, plan future change)
		while (sent_pdu) {
			Sleep(1000);
		}
		sent_pdu = &spdu;
		PacketSender sender{ iface };

		//start sniff task
		//TODO: change sniffer config
		Sniffer sniffer{ iface.name(), 500, false };
		std::future<void> fresp(std::async(std::launch::async, &PacketSenderGeneric::sniff_task, this, &sniffer));

		//send packet
		sender.send(*sent_pdu);
		
		//std::cout << "waiting for max " << timeout << "..." << std::endl;
		std::future_status status = fresp.wait_for(std::chrono::seconds(timeout));
	
		//raise exception in case of timeout
		if (status == std::future_status::timeout)
			throw timeout_elapsed();

		else if (status == std::future_status::deferred)
			std::cout << "DEBUG: packet sniffing deffered... shouldn't happen";
		
		PDU& response = *this->response_pdu;
		response_pdu = NULL;
		sent_pdu = NULL;
		return response;
	}

	PDU& PacketSenderGeneric::send_recv(PDU& spdu)
	{
		return PacketSenderGeneric::send_recv(spdu, default_iface);
	}
}