import sys
from nmap_wrapper import NmapWrapper
import gobuster_wrapper


def main():
    target = sys.argv[1]
    run_nmap = 0
    run_gobuster = 1
    http_port = 80


    # Basic TCP SYN scan with verbose output
    if run_nmap == 1:
        print("Starting nmap scan with progress display...")
        nmap = NmapWrapper()
        nmap_result = nmap.run_scan(
            ip_address=target,
            additional_args=["-sS", "-v", "-p", "1-1000"],  # -v for verbose output
            show_progress=True
        )

        print("\n" + "=" * 50)
        if nmap_result['success']:
            print("Scan completed successfully!")
        else:
            print("Scan failed:", nmap_result.get('error', nmap_result.get('stderr')))
        print("\n" + "=" * 50)

    if run_gobuster == 1:
        gobuster_wrapper.run_gobuster(target, http_port)


if __name__ == "__main__":
    main()