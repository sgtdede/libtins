#ifndef TINS_PACKET_SENDER_GENERIC_H
#define TINS_PACKET_SENDER_GENERIC_H

#include "exceptions.h"
#include "network_interface.h"
#include "pdu.h"
#include "sniffer.h"


namespace Tins {
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

		static const uint32_t DEFAULT_TIMEOUT = 2;
		//constructors
		PacketSenderGeneric(const NetworkInterface& iface = NetworkInterface(), uint32_t recv_timeout = DEFAULT_TIMEOUT);
		
		//destructor
		~PacketSenderGeneric();

		//methods
		PDU& send_recv(PDU& spdu);
		PDU& send_recv(PDU& spdu, const NetworkInterface& iface);

	private:
		uint32_t timeout;
		PDU* sent_pdu;
		PDU* response_pdu;
		NetworkInterface default_iface;
		
		bool generic_response_handler(PDU& rpdu);
		void sniff_task(Sniffer* sniffer);
	};


}

#endif // TINS_PACKET_SENDER_GENERIC_H