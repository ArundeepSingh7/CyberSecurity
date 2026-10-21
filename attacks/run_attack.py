"""
For educational use against your own local test environment only.
CLI entry point: python -m attacks.run_attack --type portscan|dos|ddos|bruteforce|webattack|bot --duration 10
"""
import argparse
import sys

_CHOICES = ("portscan", "dos", "ddos", "bruteforce", "webattack", "bot")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cyber IDS attack simulator — localhost only, educational use."
    )
    parser.add_argument(
        "--type",
        choices=_CHOICES,
        required=True,
        help="Attack type to simulate.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Duration in seconds (default: 10).",
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target host — must be 127.0.0.1 / localhost.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Target port (default: 5000).",
    )
    args = parser.parse_args()

    print("=" * 60)
    print(f"  Cyber IDS Attack Simulator")
    print(f"  Type: {args.type.upper()}  |  Duration: {args.duration}s")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  For educational / demo use ONLY against localhost.")
    print(f"  Telemetry is sent to IDS at http://127.0.0.1:8000")
    print("=" * 60)

    if args.type == "portscan":
        from attacks.port_scan_attack import PortScanAttack
        attack = PortScanAttack(target=args.target, port=args.port, duration=args.duration)
    elif args.type == "dos":
        from attacks.dos_attack import DoSAttack
        attack = DoSAttack(target=args.target, port=args.port, duration=args.duration)
    elif args.type == "ddos":
        from attacks.ddos_attack import DDoSAttack
        attack = DDoSAttack(target=args.target, port=args.port, duration=args.duration)
    elif args.type == "bruteforce":
        from attacks.bruteforce_attack import BruteForceAttack
        attack = BruteForceAttack(target=args.target, port=args.port, duration=args.duration)
    elif args.type == "webattack":
        from attacks.web_attack import WebAttack
        attack = WebAttack(target=args.target, port=args.port, duration=args.duration)
    elif args.type == "bot":
        from attacks.bot_attack import BotAttack
        attack = BotAttack(target=args.target, port=args.port, duration=args.duration)
    else:
        print(f"Unknown attack type: {args.type}")
        sys.exit(1)

    print(f"\n[run_attack] Attack started: {attack}\n")
    attack.run()
    print("\n[run_attack] Attack finished — check Live Monitor dashboard for alerts.")


if __name__ == "__main__":
    main()
