#ifndef TINS_PACKET_SENDER_GENERIC_H
#define TINS_PACKET_SENDER_GENERIC_H

#include "exceptions.h"
#include "network_interface.h"
#include "pdu.h"
#include "sniffer.h"
#include "packet_sender.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <utility>


namespace Tins {
	class SharedSender
	{
	public:
		SharedSender();
		void register_packet(PDU* wpacket, NetworkInterface iface);
		
		/**
		* \brief send packets stored in the given queue throught network interface
		* \param waiting_packets packet (NetworkInterface, PDU) queue to be sent
		*/
		void send_loop();
	private:
		PacketSender sender;
		std::queue<std::pair<PDU*, NetworkInterface>> waiting_packets;
		std::mutex packet_queue_lock;
		std::condition_variable packet_queue_cond;
	};

	class PacketSenderGeneric
	{
	public:
		/**
		* The exception thrown when the timeout is elapsed during response packet sniffing
		*/
		class timeout_elapsed : public exception_base {
		public:
			const char *what() const throw() {
				return "Timeout elapsed";
			}
		};

		typedef std::pair<PDU*, NetworkInterface> packet_iface;

		static const uint32_t DEFAULT_TIMEOUT = 2;
		//constructors
		PacketSenderGeneric(const NetworkInterface& iface = NetworkInterface(), uint32_t recv_timeout = DEFAULT_TIMEOUT);
		
		//destructor
		//~PacketSenderGeneric();

		//methods
		PDU& send_recv(PDU& spdu, SharedSender& shared_sender, bool promisc = false, double* rdelay = NULL, double *edelay = NULL);
		PDU& send_recv(PDU& spdu, bool promisc = false, double* rdelay = NULL, double *edelay = NULL);
		PDU& send_recv(PDU& spdu, SharedSender& shared_sender, const NetworkInterface& iface, bool promisc = false, double* rdelay = NULL, double* edelay = NULL);
		PDU& send_recv(PDU& spdu, const NetworkInterface& iface, bool promisc = false, double* rdelay = NULL, double* edelay = NULL);

	private:
		uint32_t timeout;
		PDU* sent_pdu;
		PDU* response_pdu;
		NetworkInterface default_iface;
		Timestamp real_sent_time;
		double response_delay;
		
		bool generic_response_handler(PDU& rpdu);
		void sniff_task(Sniffer* sniffer, bool compute_delay=true);
	};
}

#endif // TINS_PACKET_SENDER_GENERIC_H