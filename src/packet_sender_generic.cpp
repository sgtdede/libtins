#include <iostream>
#include <future>

#include "packet_sender.h"
#include "packet_sender_generic.h"
#include <ctime>
#include <mutex>

using std::unique_lock;
using std::mutex;


namespace Tins {
	mutex SHARED_SNIFFER_MUTEX;
	
	PacketSenderGeneric::PacketSenderGeneric(const NetworkInterface& iface, uint32_t recv_timeout)
		: default_iface(iface), timeout(recv_timeout), sent_pdu(NULL), response_pdu(NULL){
	}

	bool PacketSenderGeneric::generic_response_handler(PDU& rpdu)
	{
		if (sent_pdu->matches_response_generic(rpdu))
		{
			response_pdu = rpdu.clone();
			return false;
		}
		return true;
	}

	void PacketSenderGeneric::sniff_task(Sniffer* sniffer, bool compute_delay)
	{
		for (auto& rpacket : *sniffer)
		{	
			const PDU& rpdu = const_cast<PDU&>(*rpacket.pdu());
			try 
			{
				//NEED TO SNIFF actual sended packet to get exact timestamp
				if (compute_delay)
				{
					if (*sent_pdu == rpdu)
					{
						real_sent_time = rpacket.timestamp();
					}
				}
				if (sent_pdu->matches_response_generic(rpdu))
				{
					if (compute_delay)
						response_delay = (double)(rpacket.timestamp().operator std::chrono::microseconds().count() - real_sent_time.operator std::chrono::microseconds().count()) / 1000;

					response_pdu = rpdu.clone();
					sniffer->stop_sniff();
					break;
				}
			}
			catch (malformed_packet&) {}
			catch (pdu_not_found&) {}
		}
	}

	PDU& PacketSenderGeneric::send_recv(PDU& spdu, const NetworkInterface& iface, bool promisc, double* rdelay, double* edelay)
	{
		//wait for previous packet to receive response (TODO: not ideal, plan future change)
		while (sent_pdu) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
		sent_pdu = &spdu;
		PacketSender sender{ iface };

		//start sniff task
		SnifferConfiguration config;
		config.set_promisc_mode(promisc);
		config.set_snap_len(65535);
		config.set_timeout(10);
		Sniffer sniffer{ iface.name(), config };
		bool compute_delay = true;
		if (!rdelay)
			compute_delay = false;
		std::future<void> fresp(std::async(std::launch::async, &PacketSenderGeneric::sniff_task, this, &sniffer, compute_delay));

		//send packet
		std::clock_t effective_sent_time = std::clock();
		sender.send(*sent_pdu);
		
		//std::cout << "waiting for max " << timeout << "..." << std::endl;
		std::future_status status = fresp.wait_for(std::chrono::seconds(timeout));
	
		//raise exception in case of timeout
		if (status == std::future_status::timeout)
		{
			sniffer.stop_sniff();
			sent_pdu = NULL;
			throw timeout_elapsed();
		}
		else if (status == std::future_status::deferred)
			std::cout << "DEBUG: packet sniffing deffered... shouldn't happen";
		
		//Treat response packet
		if (edelay)
			*edelay = ((std::clock() - effective_sent_time) / (double)CLOCKS_PER_SEC) * 1000;
		if (rdelay) {
			*rdelay = response_delay;
		}

		PDU& response(*this->response_pdu);

		//Clean
		sent_pdu = NULL;
		response_delay = NULL;
		//response_pdu = NULL;
		
		return response;
	}

	PDU& PacketSenderGeneric::send_recv(PDU& spdu, SharedSender& shared_sender, const NetworkInterface& iface, bool promisc, double* rdelay, double* edelay)
	{	
		//wait for previous packet to receive response (TODO: not ideal, plan future change)
		while (sent_pdu) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
		sent_pdu = spdu.clone();

		//start sniff task
		SnifferConfiguration config;
		config.set_promisc_mode(promisc);
		config.set_snap_len(65535);
		config.set_timeout(10);

		//Critical section
		SHARED_SNIFFER_MUTEX.lock();
		Sniffer sniffer{ iface.name(), config };
		SHARED_SNIFFER_MUTEX.unlock();

		bool compute_delay = true;
		if (!rdelay)
			compute_delay = false;
		std::future<void> fresp(std::async(std::launch::async, &PacketSenderGeneric::sniff_task, this, &sniffer, compute_delay));

		//send packet
		std::clock_t effective_sent_time = std::clock();
		std::cout << "Registering packet to send !" << std::endl;
		shared_sender.register_packet(sent_pdu, NetworkInterface(iface));

		//std::cout << "waiting for max " << timeout << "..." << std::endl;
		std::future_status status = fresp.wait_for(std::chrono::seconds(timeout));

		//raise exception in case of timeout
		if (status == std::future_status::timeout)
		{
			sniffer.stop_sniff();
			sent_pdu = NULL;
			throw timeout_elapsed();
		}
		else if (status == std::future_status::deferred)
			std::cout << "DEBUG: packet sniffing deffered... shouldn't happen";

		//Treat response packet
		if (edelay)
			*edelay = ((std::clock() - effective_sent_time) / (double)CLOCKS_PER_SEC) * 1000;
		if (rdelay) {
			*rdelay = response_delay;
		}

		PDU& response(*this->response_pdu);

		//Clean
		sent_pdu = NULL;
		response_delay = NULL;
		//response_pdu = NULL;

		return response;
	}
	
	PDU& PacketSenderGeneric::send_recv(PDU& spdu, bool promisc, double* rdelay, double* edelay)
	{
		return PacketSenderGeneric::send_recv(spdu, default_iface, promisc, rdelay, edelay);
	}

	PDU& PacketSenderGeneric::send_recv(PDU& spdu, SharedSender& shared_sender, bool promisc, double* rdelay, double* edelay)
	{
		return PacketSenderGeneric::send_recv(spdu, shared_sender, default_iface, promisc, rdelay, edelay);
	}




	////////////////////////////   SHARED_SENDER /////////////////////////////////////////////
	SharedSender::SharedSender() {
		sender = PacketSender();
	}
	void SharedSender::register_packet(PDU* wpacket, NetworkInterface iface)
	{
		std::cout << "Registering new packet to be sent" << std::endl;
		unique_lock<mutex> lock(packet_queue_lock);
		waiting_packets.push(std::pair<PDU*, NetworkInterface>(wpacket, iface));
		packet_queue_cond.notify_one();
	}
	void SharedSender::send_loop()
	{
		std::cout << "Starting sender thread" << std::endl;
		while (true) 
		{
			//Critical area
			unique_lock<mutex> lock(packet_queue_lock);
			while (waiting_packets.empty()) {
				packet_queue_cond.wait(lock);
			}
			std::pair<PDU*, NetworkInterface> packet_iface = waiting_packets.front();
			waiting_packets.pop();
			lock.unlock();

			std::cout << "Sending packet !" << std::endl;
			sender.send(*packet_iface.first, packet_iface.second);
		}
	}

}
