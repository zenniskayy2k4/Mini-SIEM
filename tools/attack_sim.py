import time
import random
import sys
import os
from rich.console import Console
from rich.progress import track
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from scapy.all import send, IP, TCP

# Add project root to path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

console = Console()

# Fake IPs for Log Injection
IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.99", "45.33.22.11", "185.200.11.2"]
USERS = ["admin", "root", "user", "test", "oracle", "postgres"]


def write_log(message: str) -> None:
    """
    Append a syslog-like line into the log file watched by the SIEM.
    Used for HIDS (Log-based) testing.
    """
    try:
        with open(config.LOG_FILE_TO_WATCH, "a", encoding="utf-8") as f:
            timestamp = time.strftime("%b %d %H:%M:%S")
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        console.print(f"[bold red]Error writing to log file: {e}[/bold red]")


def print_header() -> None:
    title = Text("MINI-SIEM • Attack Log Simulator", style="bold cyan")
    subtitle = (
        "This tool simulates attacks to test the SIEM's detection capabilities.\n"
        "Modes 1-4: Write logs to test HIDS.\n"
        "Mode 5: Sends REAL packets to test NIDS.\n\n"
        f"Target log file: {config.LOG_FILE_TO_WATCH}"
    )
    console.print(Panel(subtitle, title=title, border_style="cyan"))


def print_menu() -> None:
    table = Table(title="Attack Modes", title_style="bold magenta", show_lines=True)
    table.add_column("Key", justify="center", style="bold")
    table.add_column("Mode", style="bold")
    table.add_column("Description", overflow="fold")

    table.add_row(
        "1",
        "SSH Brute Force (Log)",
        "Simulates multiple failed SSH logins from one IP (Trigger: Correlation/Threshold).",
    )
    table.add_row(
        "2",
        "Sudo Privilege Escalation (Log)",
        "Simulates a user attempting to gain root via sudo (Trigger: Signature).",
    )
    table.add_row(
        "3",
        "ML/NLP Anomaly Payload (Log)",
        "Injects a long, high-entropy string (Trigger: Machine Learning Anomaly).",
    )
    table.add_row(
        "4",
        "Mixed Attack Chain (Log)",
        "Combines Brute Force + Sudo Escalation.",
    )
    table.add_row(
        "5",
        "Network TCP SYN Scan (Real Packet)",
        "Sends 50 real TCP SYN packets to localhost (Trigger: NIDS Traffic Analysis).",
    )
    table.add_row(
        "h",
        "Help",
        "Show this menu again.",
    )
    table.add_row(
        "q",
        "Quit",
        "Exit the simulator.",
    )

    console.print(table)


def sim_brute_force() -> None:
    target_ip = random.choice(IPS)
    console.print(
        Panel(
            f"Simulating SSH brute-force style failures\nSource IP: [bold]{target_ip}[/bold]",
            title="[bold red]SSH Brute Force (Log Sim)[/bold red]",
            border_style="red",
        )
    )

    for _ in track(range(20), description="Writing failed attempts..."):
        user = random.choice(USERS)
        msg = (
            "srv sshd[123]: Failed password for "
            f"{user} from {target_ip} port {random.randint(1000, 65535)} ssh2"
        )
        write_log(msg)
        time.sleep(random.uniform(0.05, 0.15))


def sim_sudo_abuse() -> None:
    console.print(
        Panel(
            "Simulating a privilege escalation indicator via sudo log entry",
            title="[bold yellow]Sudo Escalation (Log Sim)[/bold yellow]",
            border_style="yellow",
        )
    )
    msg = "srv sudo:   hacker : TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/usr/bin/su"
    write_log(msg)
    console.print("[green]Log entry written.[/green]")


def sim_anomaly() -> None:
    console.print(
        Panel(
            "Injecting a high-entropy / long payload to emulate abnormal log content",
            title="[bold magenta]Anomaly Payload (Log Sim)[/bold magenta]",
            border_style="magenta",
        )
    )
    payload = "".join(chr(random.randint(33, 126)) for _ in range(300))
    msg = f"srv nginx: Error processing request: {payload}"
    write_log(msg)
    console.print("[green]Anomaly log entry written.[/green]")


def sim_network_scan() -> None:
    """
    Sends real packets using Scapy to trigger the Network Monitor.
    """
    target_ip = "127.0.0.1"  # Target Localhost
    port = 80
    packet_count = 50

    console.print(
        Panel(
            f"Sending {packet_count} TCP SYN packets to {target_ip}:{port}\n"
            "This requires Administrator/Root privileges to work correctly.",
            title="[bold red]Network Port Scan (Real Packets)[/bold red]",
            border_style="red",
        )
    )
    
    try:
        # Create packet: IP -> TCP (SYN flag)
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Send packets (verbose=0 hides scapy's default output)
        console.print(f"[yellow]Sending packets...[/yellow]")
        send(pkt, count=packet_count, verbose=0)
        
        console.print(f"[bold green]✔ Sent {packet_count} SYN packets successfully.[/bold green]")
        console.print("[dim]Check the Dashboard/Console for 'Network Port Scanning' alert.[/dim]")
        
    except PermissionError:
        console.print("[bold red]❌ PERMISSION DENIED:[/bold red] You must run this script as Administrator/Root (sudo) to send packets.")
    except Exception as e:
        console.print(f"[bold red]❌ Error sending packets:[/bold red] {e}")


def main() -> None:
    print_header()
    print_menu()

    try:
        while True:
            mode = Prompt.ask(
                "Select Attack Mode",
                choices=["1", "2", "3", "4", "5", "h", "q"],
                default="1",
                show_choices=False,
            )

            if mode == "1":
                sim_brute_force()
            elif mode == "2":
                sim_sudo_abuse()
            elif mode == "3":
                sim_anomaly()
            elif mode == "4":
                sim_brute_force()
                time.sleep(1)
                sim_sudo_abuse()
            elif mode == "5":
                sim_network_scan()
            elif mode == "h":
                print_menu()
            elif mode == "q":
                console.print("[bold]Exiting Simulator. Bye![/bold]")
                break

            time.sleep(0.5)

    except KeyboardInterrupt:
        console.print("\n[bold]Simulator Stopped.[/bold]")


if __name__ == "__main__":
    main()