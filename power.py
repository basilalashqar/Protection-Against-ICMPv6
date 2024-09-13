import subprocess
import threading
import os
import signal

def start_bmv2():
    # Start BMv2 switch in a new terminal window using gnome-terminal
    new_terminal_command = [
        "gnome-terminal",
        "--",
        "bash", "-c",
        "sudo simple_switch_grpc -i 0@veth1 -i 1@veth2 -i 2@veth3 -i 3@veth4 -i 4@veth5 -i 5@veth6 -i 6@veth7 -i 7@veth8 p4_nsaf.json --log-console; read -p 'Press enter to close this terminal...'"
    ]
    bmv2_process = subprocess.Popen(new_terminal_command, preexec_fn=os.setsid)
    print(f"BMv2 Switch started with PID {bmv2_process.pid}")
    return bmv2_process

def stop_bmv2(bmv2_process):
    # Stop the BMv2 switch
    os.killpg(os.getpgid(bmv2_process.pid), signal.SIGTERM)
    print(f"BMv2 Switch with PID {bmv2_process.pid} stopped")

def listen_for_stop_command(bmv2_process):
    while True:
        command = input("Type 'stop' to terminate the BMv2 switch: ")
        if command.strip().lower() == "stop":
            stop_bmv2(bmv2_process)
            break

def main():
    # Start the BMv2 switch
    bmv2_process = start_bmv2()

    # Start a thread to listen for the stop command
    listener_thread = threading.Thread(target=listen_for_stop_command, args=(bmv2_process,))
    listener_thread.start()

    # Wait for the listener thread to complete
    listener_thread.join()

if __name__ == '__main__':
    main()

