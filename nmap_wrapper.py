import subprocess
import threading
import time
from gobuster_wrapper import GobusterWrapper, run_gobuster


class NmapWrapper:
    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path
        self.ip_address = ''

    def run_scan(self, ip_address, additional_args=None, timeout=None, show_progress=True):
        """
        Run nmap scan

        Args:
            ip_address: IP Address to scan
            additional_args: Additional nmap options
            timeout: Timeout in seconds
            show_progress: Whether to show real-time output
        """
        self.ip_address = ip_address
        cmd = [self.nmap_path, str(ip_address)]

        if additional_args:
            cmd.extend(additional_args)

        try:
            if show_progress:
                return self._run_with_progress(cmd, timeout)
            else:
                return self._run_without_progress(cmd, timeout)

        except subprocess.TimeoutExpired:
            return {'error': 'Process timed out', 'success': False}
        except Exception as e:
            return {'error': str(e), 'success': False}

    def _run_with_progress(self, cmd, timeout):
        """Run scan with real-time output display"""
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        stdout_lines = []
        stderr_lines = []

        def read_stdout():
            import re
            # Pattern to match the specific ports
            port_pattern = r'port\s\b(80|8000|8080|443)/tcp\b'

            for line in iter(process.stdout.readline, ''):
                print(f"[SCAN] {line.strip()}")
                stdout_lines.append(line)

                # Check for target ports
                port = re.match(port_pattern, line)
                if port:
                    my_function(port)
                    run_gobuster(self.ip_address, port)
                    # self.run_gobuster = 1
                    # self.http_port = match

            process.stdout.close()

        def read_stderr():
            for line in iter(process.stderr.readline, ''):
                print(f"[ERROR] {line.strip()}")
                stderr_lines.append(line)
            process.stderr.close()

        # Start threads to read output
        stdout_thread = threading.Thread(target=read_stdout)
        stderr_thread = threading.Thread(target=read_stderr)

        stdout_thread.daemon = True
        stderr_thread.daemon = True

        stdout_thread.start()
        stderr_thread.start()

        # Wait for process completion
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            return {'error': 'Process timed out', 'success': False}

        # Wait for threads to finish reading
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)

        return {
            'stdout': ''.join(stdout_lines),
            'stderr': ''.join(stderr_lines),
            'returncode': process.returncode,
            'success': process.returncode == 0
        }

    def _run_without_progress(self, cmd, timeout):
        """Run scan without progress display"""
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )

        stdout, stderr = process.communicate(timeout=timeout)
        return {
            'stdout': stdout,
            'stderr': stderr,
            'returncode': process.returncode,
            'success': process.returncode == 0
        }


# Example usage
def my_function(port):
    """Function to call when target ports are found"""
    print(f"🎯 TARGET PORT DETECTED: {port}")
    # Add your custom logic here

def gobuster_scan(url:str, port:str) -> None:
    gobuster = GobusterWrapper()
    print("Starting gobuster directory enumeration with progress display...")

    # Directory enumeration scan
    result = gobuster.run_scan(
        url=f"{url}:{port}",
        wordlist="/usr/share/wordlists/dirb/common.txt",
        additional_args=["-t", "50", "-x", "php,html,txt", "--no-error"],
        show_progress=True
    )

    print("\n" + "=" * 50)
    if result['success']:
        print("Scan completed successfully!")
    else:
        print("Scan failed:", result.get('error', result.get('stderr')))

if __name__ == "__main__":
    nmap = NmapWrapper()

    print("Starting nmap scan with progress display...")

    # Basic TCP SYN scan with verbose output
    result = nmap.run_scan(
        ip_address="192.168.69.7",
        additional_args=["-sS", "-v", "-p", "1-1000"],  # -v for verbose output
        show_progress=True
    )

    print("\n" + "=" * 50)
    if result['success']:
        print("Scan completed successfully!")
    else:
        print("Scan failed:", result.get('error', result.get('stderr')))