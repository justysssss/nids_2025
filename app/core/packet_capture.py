# app/core/packet_capture.py
from scapy.all import sniff, IP, TCP, UDP
from scapy.config import conf
from scapy.arch.windows import get_windows_if_list
# Removed: from app.core import socketio
from datetime import datetime
import time
import os
import re

class PacketCapture:
    def __init__(self, socketio_instance, interface=None): # Added socketio_instance
        self.socketio = socketio_instance # Store the instance
        self.running = False
        self.start_time = None
        
        # Get interface from environment or parameter
        self.interface_name = interface or os.getenv('INTERFACE', 'Wi-Fi')
        
        # On Windows, we need to map the friendly name to the interface ID
        if os.name == 'nt':  # Windows
            ifaces = get_windows_if_list()
            # print("Available interfaces:", [(i['name'], i['description']) for i in ifaces]) # Removed this print

            # Try to find interface by name
            found = False
            # Prioritize exact name match
            for iface in ifaces:
                if self.interface_name.lower() == iface.get('name', '').lower():
                    self.interface = iface['name'] # Use name
                    found = True
                    # print(f"Found exact match by name: {self.interface}") # Optional debug print
                    break

            # If no exact name match, try matching description (more carefully)
            if not found:
                # print(f"No exact name match for '{self.interface_name}', checking descriptions...") # Optional debug print
                for iface in ifaces:
                    # Match description only if name didn't match exactly
                    if self.interface_name.lower() in iface.get('description', '').lower():
                        self.interface = iface['name'] # Use name
                        found = True
                        # print(f"Found partial match in description: {iface.get('description', '')} -> Using name: {self.interface}") # Optional debug print
                        break

            if not found:
                print(f"Warning: Interface '{self.interface_name}' not found by name or description. Falling back.")
                # If not found, use the first interface that's not loopback
                for iface in ifaces:
                    # Ensure description exists before checking
                    if 'Loopback' not in iface.get('description', ''):
                        self.interface = iface['name'] # Use name
                        # print(f"Using fallback (first non-loopback): {self.interface}") # Optional debug print
                        found = True # Mark as found to prevent using the absolute fallback
                        break
                if not found and ifaces: # Check if ifaces is not empty
                    # Fallback to the name of the first interface if no suitable one found
                    self.interface = ifaces[0]['name'] # Use name
                    # print(f"Using absolute fallback (first interface): {self.interface}") # Optional debug print
                elif not ifaces:
                    raise RuntimeError("No network interfaces found by Scapy.")

        else:  # Unix-like systems
            self.interface = self.interface_name

        # self.interface now holds the name used by sniff
        print(f"Selected interface for sniffing: {self.interface} (Based on config: '{self.interface_name}')")
        self.running = False
        self.start_time = None
        
        # Add packet counter for statistics
        self.packet_count = 0
        
    def start_capture(self):
        try:
            print(f"Attempting to start capture on interface: {self.interface}")
            self.running = True
            self.start_time = time.time()
            self.packet_count = 0
            
            # Find the interface object by name for Windows
            if os.name == 'nt':
                ifaces = get_windows_if_list()
                for iface in ifaces:
                    # Check against the name we stored
                    if iface['name'] == self.interface:
                        print(f"Confirmed interface for sniffing: {iface.get('description', 'N/A')} (Name: {iface['name']})")
                        break
                else:
                    # This else belongs to the for loop, should only run if break wasn't hit
                    print(f"Warning: Could not re-verify interface name '{self.interface}' before sniffing. Proceeding anyway.")
                    # raise ValueError(f"Interface name {self.interface} could not be re-verified in list") # Maybe too strict?
            
            # Emit a notification that monitoring has started
            self.socketio.emit('monitoring_status', {'status': 'capture_started'})
            
            print("Starting packet capture...")
            sniff(prn=self.process_packet, iface=self.interface, store=False)
        except Exception as e:
            print(f"Error starting capture: {str(e)}")
            self.running = False
            # Emit error notification
            self.socketio.emit('monitoring_error', {'error': str(e)})
            raise
        
    def stop_capture(self):
        self.running = False
        self.socketio.emit('monitoring_status', {'status': 'capture_stopped'})
        
    def process_packet(self, packet):
        print(f"--- Packet captured: {packet.summary()} ---") 
        if self.running and IP in packet:
            print(f"--- Processing IP packet: {packet[IP].src} -> {packet[IP].dst} ---")
            
            # Increment packet counter
            self.packet_count += 1
            
            # Convert packet to dict format
            packet_data = self._parse_packet(packet)
            
            # Add timestamp in ISO format for better JavaScript compatibility
            packet_data['timestamp'] = datetime.now().isoformat()
            
            print(f"--- Emitting packet data via SocketIO: {packet_data} ---")
            
            # Streamlined emission - use just one consistent method
            try:
                # Use a single emit with namespace for better reliability
                self.socketio.emit('new_packet', packet_data, namespace='/')
                
                # Every 10 packets, emit a status update
                if self.packet_count % 10 == 0:
                    stats = {
                        'packet_count': self.packet_count,
                        'uptime': time.time() - self.start_time,
                        'packets_per_second': self.packet_count / max(1, time.time() - self.start_time)
                    }
                    self.socketio.emit('monitor_stats', stats, namespace='/')
            except Exception as e:
                print(f"Error during emit: {str(e)}")
        else:
            print(f"--- Ignoring non-IP packet or stopped ---")
            
    def _parse_packet(self, packet):
        """Extract relevant features from the packet"""
        current_time = time.time()
        
        # Basic IP information
        features = {
            'time': current_time,
            'srcip': packet[IP].src,
            'dstip': packet[IP].dst,
            'proto': self._get_protocol(packet),
            'state': self._get_tcp_state(packet),
            'service': self._get_service(packet),
            'sttl': packet[IP].ttl,
            'dttl': packet[IP].ttl,  # Same as source TTL for single direction
        }
        
        # Add sport and dport 
        if TCP in packet:
            features['sport'] = packet[TCP].sport
            features['dport'] = packet[TCP].dport
        elif UDP in packet:
            features['sport'] = packet[UDP].sport
            features['dport'] = packet[UDP].dport
        
        # Size-related features
        pkt_size = len(packet)
        features.update({
            'sbytes': pkt_size,
            'dbytes': 0,  # Will be updated when response is seen
            'spkts': 1,
            'dpkts': 0,
            'dur': current_time - self.start_time
        })
        
        # Load-related features (bits per second)
        features.update({
            'sload': (pkt_size * 8) / max(features['dur'], 1),
            'dload': 0,
            # Add a random risk score for demo purposes
            'risk_score': 0.1 if 'dns' in self._get_service(packet).lower() else (
                          0.8 if current_time % 10 < 1 else 0.2)  # Occasionally show high-risk packets
        })
        
        return features
        
    def _get_protocol(self, packet):
        """Determine the protocol of the packet"""
        if TCP in packet:
            return 'tcp'
        elif UDP in packet:
            return 'udp'
        else:
            return str(packet[IP].proto)
            
    def _get_tcp_state(self, packet):
        """Determine TCP connection state"""
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN
                return 'SYN'
            elif flags & 0x01:  # FIN
                return 'FIN'
            elif flags & 0x04:  # RST
                return 'RST'
            elif flags & 0x10:  # ACK
                return 'EST'
        return 'OTHER'
        
    def _get_service(self, packet):
        """Determine the service based on ports"""
        if TCP in packet:
            dport = packet[TCP].dport
            if dport == 80:
                return 'http'
            elif dport == 443:
                return 'https'
            elif dport == 21:
                return 'ftp'
            elif dport == 22:
                return 'ssh'
            elif dport == 25:
                return 'smtp'
            elif dport == 53:
                return 'dns'
        elif UDP in packet and packet[UDP].dport == 53:
            return 'dns'
        return 'other'
