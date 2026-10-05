import time
import os

from process_monitor import get_processes
from security_engine import get_process_details, calculate_risk


def clear_screen():
    os.system("clear")


def display_processes(processes):
    print("=" * 115)
    print("                         🏙️ LINUXCITY — SECURITY MONITOR")
    print("=" * 115)

    print(
        f"{'PID':<8}"
        f"{'NAME':<20}"
        f"{'USER':<15}"
        f"{'CPU':<8}"
        f"{'MEM':<8}"
        f"{'RISK':<8}"
        f"{'SEVERITY':<12}"
    )

    print("-" * 115)

    for process in processes:

        details = get_process_details(process["pid"])

        if not details:
            continue

        risk = calculate_risk(details)

        print(
            f"{details['pid']:<8}"
            f"{details['name'][:19]:<20}"
            f"{details['username'][:14]:<15}"
            f"{details['cpu_percent']:<8.1f}"
            f"{details['memory_percent']:<8.1f}"
            f"{risk['score']:<8}"
            f"{risk['severity']:<12}"
        )


def main():

    while True:

        try:
            clear_screen()

            processes = get_processes()

            display_processes(processes)

            print("\nRefreshing every 3 seconds...")
            print("Press Ctrl+C to stop.")

            time.sleep(3)

        except KeyboardInterrupt:

            print("\n\nLinuxCity stopped.")
            break


if __name__ == "__main__":
    main()
