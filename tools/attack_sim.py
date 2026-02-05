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

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

console = Console()

IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.99", "45.33.22.11", "185.200.11.2"]
USERS = ["admin", "root", "user", "test", "oracle", "postgres"]


def write_log(message: str) -> None:
    """
    Append a syslog-like line into the log file watched by the SIEM.
    This is used purely to generate test events for detection pipelines.
    """
    with open(config.LOG_FILE_TO_WATCH, "a", encoding="utf-8") as f:
        timestamp = time.strftime("%b %d %H:%M:%S")
        f.write(f"{timestamp} {message}\n")


def print_header() -> None:
    title = Text("MINI-SIEM • Attack Log Simulator", style="bold cyan")
    subtitle = (
        "This tool only SIMULATES attack-like events by writing crafted log lines.\n"
        "It does NOT perform real exploitation or network attacks.\n\n"
        f"Target log file: {config.LOG_FILE_TO_WATCH}"
    )
    console.print(Panel(subtitle, title=title, border_style="cyan"))


def print_menu() -> None:
    table = Table(title="Attack Modes", title_style="bold magenta", show_lines=True)
    table.add_column("Key", justify="center", style="bold")
    table.add_column("Mode", style="bold")
    table.add_column("What it writes to the log (simulation)", overflow="fold")

    table.add_row(
        "1",
        "SSH Brute Force",
        "Multiple 'Failed password' lines from one IP, simulating password guessing attempts.",
    )
    table.add_row(
        "2",
        "Sudo Privilege Escalation",
        "A 'sudo' execution line indicating a user attempting to run privileged commands.",
    )
    table.add_row(
        "3",
        "ML/NLP Anomaly Payload",
        "A long, high-entropy payload to trigger anomaly-based detection.",
    )
    table.add_row(
        "4",
        "Mixed Attack (1 → 2)",
        "Runs brute force first, then sudo escalation to simulate an attack chain.",
    )
    table.add_row(
        "h",
        "Help / Show Menu",
        "Print this menu again.",
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
            title="[bold red]SSH Brute Force (Simulation)[/bold red]",
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
        time.sleep(random.uniform(0.10, 0.30))


def sim_sudo_abuse() -> None:
    console.print(
        Panel(
            "Simulating a privilege escalation indicator via sudo log entry",
            title="[bold yellow]Sudo Escalation (Simulation)[/bold yellow]",
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
            title="[bold magenta]Anomaly Payload (Simulation)[/bold magenta]",
            border_style="magenta",
        )
    )
    payload = "".join(chr(random.randint(33, 126)) for _ in range(300))
    msg = f"srv nginx: Error processing request: {payload}"
    write_log(msg)
    console.print("[green]Anomaly log entry written.[/green]")


def main() -> None:
    print_header()
    print_menu()

    try:
        while True:
            mode = Prompt.ask(
                "Select a mode",
                choices=["1", "2", "3", "4", "h", "q"],
                default="1",
                show_choices=True,
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
            elif mode == "h":
                print_menu()
            elif mode == "q":
                console.print("[bold]Bye.[/bold]")
                break

            time.sleep(0.8)

    except KeyboardInterrupt:
        console.print("\n[bold]Stopped.[/bold]")


if __name__ == "__main__":
    main()