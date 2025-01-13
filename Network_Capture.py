#Salma Naif Al-Mutairi 2210087
#Alanoud Saleh Almakadi 2210596

import sys
import socket
import threading
import time
from collections import defaultdict
import logging
from datetime import datetime
import scapy.all as scapy
import matplotlib.pyplot as plt
import os

# Disable buffering for real-time logging
os.environ["PYTHONUNBUFFERED"] = "1"

# Lock for thread-safe logging and output
print_lock = threading.Lock()

# Set up logging to capture network events
logging.basicConfig(
    filename="network_events.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Data structures to store network metrics and state
throughput_data = defaultdict(int)  # Throughput data by protocol
latency_data = {}  # Latency data for connections
unique_ips = set()  # Set of unique IP addresses
unique_macs = set()  # Set of unique MAC addresses
packet_sizes = []  # List of packet sizes
tcp_connections = defaultdict(int)  # Active TCP connections
protocol_counts = defaultdict(int)  # Packet counts by protocol
exit_flag = threading.Event()  # Event flag to signal threads to stop
client_threads = []  # List of client threads

# Additional structures for packet sizes and real-time connections
packet_sizes_by_protocol = defaultdict(list)  # Packet sizes grouped by protocol
tcp_connections_real_time = set()  # Real-time TCP connections
udp_connections_real_time = set()  # Real-time UDP connections

def calculate_throughput(interval=10):
    """Calculate and log throughput every interval (in seconds)."""
    global time_series_data  # Reference to global time-series data for plotting
    sleep_interval = 0.5  # Interval for periodic checks
    elapsed_time = 0  # Time since the last calculation
    try:
        while not exit_flag.is_set():
            if exit_flag.wait(timeout=sleep_interval):  
                break
            elapsed_time += sleep_interval

            if elapsed_time >= interval:
                current_time = time.time()  # Current timestamp
                with print_lock:  # Lock for thread-safe output
                    print("\n--- Throughput (bps) ---")
                    if throughput_data:
                        for protocol, bytes_count in throughput_data.items():
                            throughput_bps = (bytes_count * 8) / interval  # Calculate throughput in bps
                            print(f"{protocol}: {throughput_bps:.2f} bps")
                            # Log throughput
                            logging.info(f"Throughput: Protocol: {protocol}, Throughput: {throughput_bps:.2f} bps")
                            # Save data for time-series graph
                            time_series_data[protocol].append((current_time, throughput_bps))
                    else:
                        print("No throughput data collected yet.")
                    # Reset throughput data and elapsed time
                    throughput_data.clear()
                    elapsed_time = 0
    except KeyboardInterrupt:
        # Handle program termination
        print("\nExiting program...")
        exit_flag.set()
        sys.exit()

def analyze_packet(packet):
    """Analyze a captured packet and update relevant metrics."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]  # Timestamp for logging

    if scapy.Ether in packet:
        # Extract and log Ethernet data
        source_mac = packet[scapy.Ether].src
        destination_mac = packet[scapy.Ether].dst
        packet_size = len(packet)
        unique_macs.update([source_mac, destination_mac])  # Update unique MAC addresses
        protocol_counts["Ethernet"] += 1  # Count Ethernet packets
        logging.info(
            f"{timestamp} - Ethernet: Source MAC: {source_mac}, Destination MAC: {destination_mac}, Packet Size: {packet_size} bytes"
        )
        update_event_data("Ethernet", source_mac, destination_mac, packet_size, time.time())

    if scapy.IP in packet:
        # Extract and log IP data
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto  # Protocol (e.g., TCP or UDP)
        unique_ips.update([source_ip, destination_ip])  # Update unique IPs
        protocol_counts[protocol] += 1  # Increment protocol count
        packet_sizes_by_protocol[protocol].append(len(packet))  # Save packet size
        logging.info(
            f"{timestamp} - IP: Source IP: {source_ip}, Destination IP: {destination_ip}, Protocol: {protocol}, Packet Size: {len(packet)} bytes"
        )

        if scapy.TCP in packet:
            # Handle TCP packets
            source_port = packet[scapy.TCP].sport
            destination_port = packet[scapy.TCP].dport
            flags = packet[scapy.TCP].flags
            update_event_data("TCP", source_ip, destination_ip, len(packet), time.time())
            logging.info(
                f"{timestamp} - TCP: Source Port: {source_port}, Destination Port: {destination_port}, Packet Size: {len(packet)} bytes, Flags: {flags}"
            )

        elif scapy.UDP in packet:
            # Handle UDP packets
            source_port = packet[scapy.UDP].sport
            destination_port = packet[scapy.UDP].dport
            update_event_data("UDP", source_ip, destination_ip, len(packet), time.time())
            logging.info(
                f"{timestamp} - UDP: Source Port: {source_port}, Destination Port: {destination_port}, Packet Size: {len(packet)} bytes"
            )

def update_event_data(protocol, src_addr, dest_addr, message_size, timestamp):
    """Update throughput, latency, and connection metrics."""
    throughput_data[protocol] += message_size  # Update throughput
    if protocol == "Ethernet":
        unique_macs.update([src_addr, dest_addr])  # Update unique MAC addresses
    else:
        unique_ips.update([src_addr, dest_addr])  # Update unique IP addresses

    if protocol == "TCP":
        tcp_connections_real_time.add((src_addr, dest_addr))  # Track active TCP connections
    elif protocol == "UDP":
        udp_connections_real_time.add((src_addr, dest_addr))  # Track active UDP connections

    # Update latency data
    if protocol in ["TCP", "UDP"]:
        conn_key = (src_addr, dest_addr)
        if conn_key not in latency_data:
            latency_data[conn_key] = {"start": timestamp, "end": None}
        latency_data[conn_key]["end"] = timestamp

def display_metrics():
    """Display real-time network metrics such as unique IPs, MACs, and protocol-specific details."""
    print("\n----- Real-Time Network Metrics -----")
    print(f"Unique IP addresses: {len(unique_ips)}")
    print(f"Unique MAC addresses: {len(unique_macs)}")

    # Display packet counts and average packet sizes by protocol
    for protocol, count in protocol_counts.items():
        avg_packet_size = sum(packet_sizes_by_protocol[protocol]) / len(packet_sizes_by_protocol[protocol]) if packet_sizes_by_protocol[protocol] else 0
        print(f"\nProtocol {protocol}: {count} packets")
        print(f"  Average packet size: {avg_packet_size:.2f} bytes")
    
    # Display active TCP and UDP connections
    print(f"\nActive TCP connections: {len(tcp_connections_real_time)}")
    print(f"Active UDP connections: {len(udp_connections_real_time)}")

    # Calculate and display average latency
    total_latency = 0
    completed_connections = 0
    for conn_key, times in latency_data.items():
        if times["start"] is not None and times["end"] is not None:
            latency = times["end"] - times["start"]
            total_latency += latency
            completed_connections += 1
            logging.info(f"Latency: Connection {conn_key}, Latency: {latency:.4f} seconds")
    avg_latency = total_latency / completed_connections if completed_connections > 0 else 0
    print(f"\nAverage Latency for Completed Connections: {avg_latency:.4f} seconds")
    logging.info(f"Average Latency: {avg_latency:.4f} seconds")  
    print("----- End of Metrics -----\n")

def handle_client(client_socket, address):
    """Handle an individual client connection, process data, and update metrics."""
    print(f"[Connected] New connection from {address}")
    try:
        while not exit_flag.is_set():
            client_socket.settimeout(1)  # Timeout for receiving data
            try:
                data = client_socket.recv(1024)  # Receive data
                if not data:
                    break
                # Update metrics for received data
                update_event_data("TCP", address, address, len(data), time.time())
            except socket.timeout:
                continue
    finally:
        # Close the client connection and remove it from the active connections set
        client_socket.close()
        tcp_connections_real_time.discard(address)
        print(f"[-] Closed connection with {address}")

def start_server(host="0.0.0.0", port=9999):
    """Start a server to listen for incoming client connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))  # Bind to the specified host and port
    server_socket.listen(5)  # Listen for up to 5 connections
    print(f"[Listening] Server is listening on {host}:{port}")

    try:
        # Start the throughput calculation thread
        throughput_thread = threading.Thread(target=calculate_throughput, daemon=True)
        throughput_thread.start()

        while not exit_flag.is_set():
            server_socket.settimeout(1)  # Timeout for accepting new connections
            try:
                # Accept a new client connection
                client_socket, address = server_socket.accept()
                # Handle the client in a separate thread
                client_thread = threading.Thread(target=handle_client, args=(client_socket, address), daemon=True)
                client_thread.start()
                client_threads.append(client_thread)  # Keep track of client threads
            except socket.timeout:
                continue

    except Exception as e:
        print(f"[ERROR] Server error: {e}")
    
    finally:
        # Clean up and close server
        print("[INFO] Shutting down server...")
        for thread in client_threads:
            thread.join()  # Ensure all client threads terminate
        server_socket.close()
        print("[INFO] Server socket closed.")

def start_client(server_address, server_port):
    """Start a client socket to connect to the server."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_address, server_port))  # Connect to the server
    try:
        while not exit_flag.is_set():
            # Send a fixed-size message to the server
            message = "X" * 1024
            client_socket.send(message.encode())
            time.sleep(2)  # Wait before sending the next message
    finally:
        # Close the client connection
        client_socket.close()

def start_capture():
    """Start packet capture using Scapy."""
    # Use a separate thread to sniff packets
    sniffer_thread = threading.Thread(target=lambda: scapy.sniff(prn=analyze_packet, store=False), daemon=True)
    sniffer_thread.start()
    try:
        while sniffer_thread.is_alive() and not exit_flag.is_set():
            if exit_flag.wait(timeout=30):  # Wait for exit signal
                break
            # Display metrics periodically
            display_metrics()
    except KeyboardInterrupt:
        # Stop the capture on interruption
        print("\nStopping capture...")
        exit_flag.set()
    sniffer_thread.join()

# Dictionary to store time-series throughput data for graph plotting
time_series_data = defaultdict(list)

def update_graph(interval=1):  
    """Update and display real-time graphs for throughput, latency, and protocol metrics."""
    while not exit_flag.is_set():
        plt.clf()  # Clear the current figure

        # Plot 1: Throughput Over Time
        plt.subplot(221)
        for protocol, values in time_series_data.items():
            if values:  # Ensure data exists for plotting
                times, throughputs = zip(*values)
                plt.plot(times, throughputs, label=f'{protocol} Throughput')
        plt.title('Throughput Over Time')
        plt.xlabel('Time (s)')
        plt.ylabel('Throughput (bps)')
        plt.legend()

        # Plot 2: Latency Distribution
        plt.subplot(222)
        latencies = [
            times["end"] - times["start"]
            for times in latency_data.values()
            if times["start"] is not None and times["end"] is not None
        ]
        if latencies:
            plt.hist(latencies, bins=10, color='purple', alpha=0.7, edgecolor='black')
            plt.title('Latency Distribution')
            plt.xlabel('Latency (seconds)')
            plt.ylabel('Frequency')
        else:
            plt.text(0.5, 0.5, "No latency data", horizontalalignment='center', verticalalignment='center')

        # Plot 3: Active Connections
        plt.subplot(223)
        active_tcp_connections = len(tcp_connections_real_time)
        active_udp_connections = len(udp_connections_real_time)
        plt.bar(['TCP', 'UDP'], [active_tcp_connections, active_udp_connections], color=['cyan', 'lime'])
        plt.title('Active Connections')
        plt.xlabel('Protocol')
        plt.ylabel('Active Connections')

        
        # Plot 4: Protocol Usage + Unique IPs and MACs
        protocol_usage = {
            "Ethernet": protocol_counts.get("Ethernet", 0),
            "TCP": protocol_counts.get(6, 0),
            "UDP": protocol_counts.get(17, 0),
        }
        plt.subplot(224)
        bar_labels = list(protocol_usage.keys()) + ["Unique IPs", "Unique MACs"]
        bar_values = list(protocol_usage.values()) + [len(unique_ips), len(unique_macs)]
        plt.bar(bar_labels, bar_values, color=['magenta', 'yellow', 'brown', 'blue', 'green'])
        plt.title('Protocol Usage and Unique Devices')
        plt.xlabel('Metric')
        plt.ylabel('Count')

        
        # Adjust layout and render the plots
        plt.tight_layout()
        plt.draw()
        plt.pause(0.1)

if __name__ == "__main__":
    """Main function to start threads and handle graceful shutdown."""
    try:
        plt.ion()  # Enable interactive mode for Matplotlib

        # Create and start threads for graph updates, packet capture, and server
        graph_thread = threading.Thread(target=update_graph, daemon=True)
        capture_thread = threading.Thread(target=start_capture, daemon=True)
        server_thread = threading.Thread(target=start_server, daemon=True)

        graph_thread.start()
        capture_thread.start()
        server_thread.start()

        # Keep the main thread alive until all threads are done
        while any(thread.is_alive() for thread in [graph_thread, capture_thread, server_thread]):
            time.sleep(1)

    except KeyboardInterrupt:
        # Graceful shutdown on keyboard interruption
        print("\n[INFO] Shutdown requested. Finalizing...")
        exit_flag.set()

        graph_thread.join(timeout=0.5)
        capture_thread.join(timeout=0.5)
        server_thread.join(timeout=0.5)
        for thread in client_threads:
            thread.join(timeout=0.5)
        print("[INFO] All threads stopped. Program exiting gracefully.")

    finally:
        # Disable interactive mode and close the graph
        plt.ioff()
        plt.show()
        print("[INFO] Program terminated successfully.")
        sys.exit(0)
