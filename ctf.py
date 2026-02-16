#!/usr/bin/env python3
import subprocess
import requests
import sys
import shlex
import re

# Import rich for beautiful terminal formatting and Markdown rendering
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
except ImportError:
    print("[!] The 'rich' library is required for enhanced readability.")
    print("[!] Please install it using: pip install rich")
    sys.exit(1)

OLLAMA_API = "http://localhost:11434/api/generate"
MODEL = "ctf-scanner"
console = Console()

def check_scan_results(scan_output):
    """Check if scan found anything useful"""
    if not scan_output or len(scan_output.strip()) < 50:
        return False, "Scan produced no output"
    
    # Check if host appears down
    if "Host seems down" in scan_output or "0 hosts up" in scan_output:
        return False, "Host appears down (try -Pn flag)"
    
    # Check if any ports were found
    open_ports = re.findall(r'(\d+)/tcp\s+open', scan_output)
    if not open_ports:
        # Check for closed/filtered
        if "filtered" in scan_output.lower() or "closed" in scan_output.lower():
            return False, "No open ports found (all ports closed/filtered)"
        return False, "No ports detected in scan output"
    
    return True, f"Found {len(open_ports)} open port(s): {', '.join(open_ports)}"

def run_nmap(target, options):
    """Run nmap scan with specified options"""
    cmd = ['nmap'] + options + [target]
    console.print(f"\n[bold blue][*] Running:[/bold blue] {' '.join(cmd)}")
    
    # Using rich's built-in status spinner for cleaner terminal output
    with console.status("[bold yellow]Scanning (this may take a while)...", spinner="dots"):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.returncode != 0:
                console.print(f"[bold red]✗ Scan failed with return code {result.returncode}[/bold red]")
                if result.stderr:
                    console.print(f"[dim red]Error: {result.stderr}[/dim red]")
                return None, "Scan failed"
            
            # Validate scan results
            is_valid, message = check_scan_results(result.stdout)
            
            if is_valid:
                console.print(f"[bold green]✓ Scan complete! {message}[/bold green]")
                return result.stdout, None
            else:
                console.print(f"[bold yellow]⚠ Scan completed but: {message}[/bold yellow]")
                return result.stdout, message
                
        except subprocess.TimeoutExpired:
            console.print("[bold red]✗ Scan timed out after 1 hour[/bold red]")
            return None, "Timeout"
        except Exception as e:
            console.print(f"[bold red]✗ Error: {e}[/bold red]")
            return None, str(e)

def analyze_scan(scan_results, target):
    """Analyze scan with AI"""
    prompt = f"""Target: {target}

Nmap Scan Results:
{scan_results}

Analyze this scan thoroughly:
1. List all open ports with services and versions
2. Identify vulnerabilities and misconfigurations
3. Provide specific enumeration commands for EACH service found
4. Prioritize by exploitability (quick wins first)
5. Note any unusual or high-value ports
6. Suggest specific exploits if versions are vulnerable

Be comprehensive and actionable. Format with clear markdown headings.
"""
    
    payload = {
        'model': MODEL,
        'prompt': prompt,
        'stream': False,
        'options': {
            'num_ctx': 8192,
            'temperature': 0.7
        }
    }
    
    with console.status("[bold yellow]Analyzing with AI (30-90 seconds)...", spinner="dots"):
        try:
            response = requests.post(OLLAMA_API, json=payload, timeout=300)
            if response.status_code == 200:
                console.print("[bold green]✓ Analysis complete![/bold green]\n")
                return response.json()['response']
            else:
                return f"Error: {response.status_code}"
        except Exception as e:
            return f"Error: {e}"

def save_results(target, scan_results, analysis):
    """Save results to markdown file"""
    safe_target = target.replace(".", "_").replace("/", "_")
    filename = f'analysis_{safe_target}.md'
    
    with open(filename, 'w') as f:
        f.write(f"# CTF Enumeration: {target}\n\n---\n\n")
        f.write(analysis)
        f.write("\n\n---\n\n## Raw Nmap Scan\n\n```text\n")
        f.write(scan_results)
        f.write("\n```\n")
        
    return filename

def print_banner():
    """Print stylized banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                   CTF ENUMERATION SCANNER                         ║
║                 Powered by Ollama + qwen3:8b                      ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")

def main():
    print_banner()
    
    # Get target
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = console.input("[bold green]Target IP/hostname:[/bold green] ").strip()
    
    if not target:
        console.print("[bold red]Error: No target specified[/bold red]")
        return
    
    # Ask for scan options
    console.print("\n[bold cyan]Select scan mode:[/bold cyan]")
    console.print("  1. Quick scan (-Pn -sV -sC, top 1000 ports, ~1-2 min)")
    console.print("  2. [bold yellow]CTF Full Scan[/bold yellow] (-Pn -sV -sC -p-, all ports, ~10-20 min) [RECOMMENDED]")
    console.print("  3. Aggressive (-Pn -A -T4, includes OS detection)")
    console.print("  4. Specific ports (-Pn -sV -sC -p <your ports>)")
    console.print("  5. Custom flags (manual entry)")
    
    choice = str(console.input("\n[bold green]Choose [2]:[/bold green] ").strip() or "2")
    
    # Build nmap options
    if choice == "1":
        options = ['-Pn', '-sV', '-sC', '-T4']
    elif choice == "2":
        options = ['-Pn', '-sV', '-sC', '-p-', '-T4']
        console.print("[bold yellow]⚠ Scanning all 65,535 ports. This will take 10-20 minutes.[/bold yellow]")
    elif choice == "3":
        options = ['-Pn', '-A', '-T4']
    elif choice == "4":
        ports = console.input("[bold cyan]Enter ports (e.g., 22,80,443 or 1-1000):[/bold cyan] ").strip()
        if not ports:
            ports = "1-10000"  # Default to first 10k ports
        options = ['-Pn', '-sV', '-sC', f'-p{ports}', '-T4']
    elif choice == "5":
        console.print("\n[bold cyan]Enter custom nmap flags (space-separated).[/bold cyan]")
        console.print("[dim]Tip: Always include -Pn for CTF boxes[/dim]")
        custom_flags = console.input("[bold green]Flags:[/bold green] ").strip()
        if custom_flags:
            options = shlex.split(custom_flags)
            # Auto-add -Pn if not present
            if '-Pn' not in options:
                options.insert(0, '-Pn')
        else:
            options = ['-Pn', '-sV', '-sC']
    else:
        console.print("[bold red]Invalid choice, using CTF Full Scan[/bold red]")
        options = ['-Pn', '-sV', '-sC', '-p-', '-T4']
    
    # Remove duplicates
    options = list(dict.fromkeys(options))
    
    # Run scan
    scan_results, error = run_nmap(target, options)
    
    # Check if scan was successful
    if not scan_results or error:
        console.print("\n[bold red]═══════════════════════════════════════════[/bold red]")
        console.print("[bold red]        SCAN FAILED - NO ANALYSIS        [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════[/bold red]\n")
        
        if scan_results:
            console.print("[bold yellow]Scan output:[/bold yellow]")
            console.print(f"[dim]{scan_results[:500]}...[/dim]\n")
        
        console.print("[bold cyan]Troubleshooting suggestions:[/bold cyan]")
        console.print("  • Check VPN connection: [dim]ip a | grep tun[/dim]")
        console.print("  • Try manual nmap: [dim]nmap -Pn -p 22 TARGET[/dim]")
        console.print("  • Test connectivity: [dim]ping TARGET[/dim]")
        console.print("  • Verify correct IP address")
        console.print("  • Try slower scan: [dim]nmap -Pn -sV -sC -T2 TARGET[/dim]")
        
        # Ask if user wants to proceed anyway
        if scan_results and "No open ports" not in str(error):
            proceed = console.input("\n[bold yellow]Proceed with AI analysis anyway? (y/n):[/bold yellow] ").strip().lower()
            if proceed != 'y':
                return
        else:
            return
    
    # Analyze with AI
    console.print("\n" + "─" * 70)
    console.print(" SCAN SUCCESSFUL - Starting AI Analysis")
    console.print("─" * 70 + "\n")
    
    analysis = analyze_scan(scan_results, target)
    
    if analysis.startswith("Error:"):
        console.print(f"\n[bold red]{analysis}[/bold red]")
        return

    # Display the final AI Analysis wrapped in a bordered Markdown panel
    console.print(Panel(
        Markdown(analysis), 
        title=f"[bold cyan]AI Analysis for {target}[/bold cyan]", 
        border_style="cyan",
        expand=False
    ))
    
    # Save
    filename = save_results(target, scan_results, analysis)
    console.print(f"\n[bold green]✓ Results saved to:[/bold green] [bold white]{filename}[/bold white]\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold red][!] Interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red][!] Error: {e}[/bold red]")
        sys.exit(1)
