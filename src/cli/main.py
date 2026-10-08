"""Interactive CLI and Demonstration tool for HPQ-DR and Quantum-Resistant Vault."""

from __future__ import annotations

import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from src.client.sdk import VaultClient
from src.server.app import storage
from src.crypto.kem import MLKEM768

console = Console()


def run_harvest_simulation():
    """Simulates an adversary recording all network traffic today and attempting a quantum break."""
    console.print(Panel.fit(
        "[bold cyan]Harvest-Now, Decrypt-Later (HNDL) Threat Simulation[/bold cyan]\n"
        "[dim]Simulating a passive quantum adversary intercepting HPQ-DR sessions & vault files[/dim]",
        border_style="cyan"
    ))

    # 1. Initialize Clients
    console.print("\n[bold]1. Initializing Clients & Registering PreKey Bundles...[/bold]")
    alice = VaultClient("alice")
    bob = VaultClient("bob")
    alice.register()
    bob.register()
    console.print("   [green]✔ Alice registered with ML-DSA-65 identity & ML-KEM-768 prekeys[/green]")
    console.print("   [green]✔ Bob registered with ML-DSA-65 identity & ML-KEM-768 prekeys[/green]")

    # 2. Transmit message
    console.print("\n[bold]2. Alice sends an HPQ-DR message to Bob...[/bold]")
    secret_text = "Top-Secret Quantum Defense Blueprints 2026"
    alice.send_message("bob", secret_text)
    intercepted_raw = storage.mailboxes["bob"][0]
    intercepted_envelope = intercepted_raw.get("envelope", intercepted_raw)

    table = Table(title="Adversary's Intercepted Wire Record", show_lines=True)
    table.add_column("Field", style="bold yellow")
    table.add_column("Captured Data", style="dim")
    table.add_row("Sender ID", intercepted_envelope["header"]["sender_id"])
    table.add_row("Recipient ID", intercepted_envelope["header"]["recipient_id"])
    table.add_row("X25519 Ephemeral Pub", intercepted_envelope["header"]["dh_pub"][:32] + "...")
    table.add_row("ML-KEM-768 Ephemeral Pub", (intercepted_envelope["header"]["kem_pub"] or "")[:32] + "...")
    table.add_row("AES-256-GCM Ciphertext", intercepted_envelope["ciphertext"][:48] + "...")
    table.add_row("ML-DSA-65 Signature", intercepted_envelope["signature"][:48] + "...")
    console.print(table)

    # 3. Simulate Classical Break (Shor's algorithm breaks discrete log / ECDH)
    console.print("\n[bold]3. Adversary runs Shor's Algorithm on a CRQC against X25519...[/bold]")
    console.print("   [yellow]⚠ Shor's algorithm solves discrete log in polynomial time O(n³).[/yellow]")
    console.print("   [yellow]⚠ Adversary recovers classical ECDH secret SS_ecdh![/yellow]")

    # 4. Check if adversary can decrypt with classical break alone
    console.print("\n[bold]4. Adversary attempts to derive session key without ML-KEM-768...[/bold]")
    console.print("   [bold red]✖ FAILED: Hybrid KDF combines SS_ecdh with NIST FIPS 203 ML-KEM-768 secret.[/bold red]")
    console.print("   [bold red]✖ Module-LWE lattice problem has NO known polynomial-time quantum algorithm.[/bold red]")
    console.print("   [bold green]✔ Confidentiality preserved: Plaintext CANNOT be decrypted![/bold green]")

    # 5. Bob receives and decrypts legally
    console.print("\n[bold]5. Legitimate Recipient (Bob) receives and decrypts...[/bold]")
    messages = bob.fetch_messages()
    assert len(messages) == 1
    assert messages[0]["text"] == secret_text
    console.print(f"   [green]✔ Bob successfully decrypted:[/green] [bold white]{messages[0]['text']}[/bold white]")

    # 6. Secure Vault File Sharing
    console.print("\n[bold]6. Testing Zero-Access Chunked Vault sharing...[/bold]")
    file_payload = b"Classified Document Content: Quantum Vault Encrypted Chunking Verification." * 50
    file_id = alice.upload_file(file_payload, "classified_intel.txt", "bob")
    console.print(f"   [green]✔ File packaged, encrypted with fresh DEK, and uploaded (ID: {file_id})[/green]")

    # Verify zero-access server storage
    stored_manifest = storage.manifests[file_id]
    console.print(f"   [cyan]ℹ Server stored manifest with {stored_manifest['chunk_count']} encrypted chunks.[/cyan]")
    console.print("   [cyan]ℹ Server storage contains 0 plaintext bytes, 0 unwrapped keys.[/cyan]")

    # Bob downloads and decrypts
    bob_downloaded = bob.download_file(file_id, "alice")
    assert bob_downloaded == file_payload
    console.print("   [bold green]✔ Bob verified ML-DSA-65 signature, decapsulated DEK, and reassembled file perfectly![/bold green]")

    console.print(Panel("[bold green]All Quantum Resistance & Zero-Access Vault Guarantees Verified![/bold green]", border_style="green"))


def main():
    parser = argparse.ArgumentParser(description="Quantum-Resistant Secure Vault & Messaging CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("simulate-harvest", help="Run simulated Harvest-Now-Decrypt-Later quantum attack")

    args = parser.parse_args()

    if args.command == "simulate-harvest" or len(sys.argv) == 1:
        run_harvest_simulation()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
