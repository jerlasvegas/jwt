import subprocess
import threading
import re

# Example function to call when findings are discovered



class GobusterWrapper:
    def __init__(self, gobuster_path="gobuster"):
        self.gobuster_path = gobuster_path



    def run_scan(self, url, wordlist, additional_args=None, timeout=None, show_progress=False):
        """
        Run gobuster directory/file enumeration scan

        Args:
            url: Target URL to scan
            wordlist: Path to wordlist file
            additional_args: Additional gobuster options
            timeout: Timeout in seconds
            show_progress: Whether to show real-time output
        """
        cmd = [self.gobuster_path, "dir", "-u", str(url), "-w", str(wordlist)]

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

    def run_vhost_scan(self, url, wordlist, additional_args=None, timeout=None, show_progress=True):
        """
        Run gobuster vhost enumeration scan

        Args:
            url: Target URL to scan
            wordlist: Path to wordlist file for subdomains
            additional_args: Additional gobuster options
            timeout: Timeout in seconds
            show_progress: Whether to show real-time output
        """
        cmd = [self.gobuster_path, "vhost", "-u", str(url), "-w", str(wordlist)]

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
        print("Starting gobuster directory enumeration with progress display...")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=None
        )

        stdout_lines = []
        stderr_lines = []

        def my_function(url, status_code):
            """Function to call when directories/files are found"""
            print(f"🎯 FINDING DETECTED: {url} (Status: {status_code})")

            # You can add custom logic here based on status codes
            if status_code == "200":
                print(f"   ✅ Found accessible resource: {url}")
                print(f"ZOMG Tehy 4re s000 p0wn3ed  jajajja {url}")
            elif status_code == "403":
                print(f"   🔒 Found forbidden resource: {url}")
            elif status_code == "301" or status_code == "302":
                print(f"   🔄 Found redirect: {url}")

        def read_stdout():
            # Pattern to match found directories/files
            found_pattern = r'(\S*)\s+\(Status:\s*(\d+)\)'

            for line in iter(process.stdout.readline, ''):
                if "Progress:" not in line:
                    print(f"[GOBUSTER] {line.strip()}")
                    match = re.match(found_pattern, line)
                    if match:
                        url = match.group(1)
                        status = match.group(2)
                        print(f"S")
                        my_function(url, status)
                stdout_lines.append(line)

                #Check for interesting findings
                matches = re.findall(found_pattern, line)
                for match in matches:
                    url, status = match
                    my_function(url, status)

            process.stdout.close()

        def read_stderr():
            for line in iter(process.stderr.readline, ''):
                if line.strip():  # Only print non-empty lines
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
        print("Starting gobuster directory enumeration without progress display...")
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


def run_gobuster(url, http_port):
    """ This is the entry point to run go buster
        include gobuster_wrapper and run this function"""
    gobuster = GobusterWrapper()

    # Directory enumeration scan
    result = gobuster.run_scan(
        url=f"{url}:{http_port}",
        #wordlist="/usr/share/wordlists/dirb/common.txt",
        wordlist="/usr/share/dirb/wordlists/small.txt",
        additional_args=["-t", "50", "-x", "php,html,txt", "--no-error"],
        show_progress=True
    )

    print("\n" + "=" * 50)
    if result['success']:
        print("Scan completed successfully!")
    else:
        print("Scan failed:", result.get('error', result.get('stderr')))

#
# # Example usage
# if __name__ == "__main__":
#     gobuster = GobusterWrapper()
#
#     print("Starting gobuster directory enumeration with progress display...")
#
#     # Directory enumeration scan
#     result = gobuster.run_scan(
#         url="http://example.com",
#         wordlist="/usr/share/wordlists/dirb/common.txt",
#         additional_args=["-t", "50", "-x", "php,html,txt", "--no-error"],
#         show_progress=True
#     )
#
#     print("\n" + "=" * 50)
#     if result['success']:
#         print("Scan completed successfully!")
#     else:
#         print("Scan failed:", result.get('error', result.get('stderr')))
#
#     # Example vhost enumeration
#     print("\nStarting vhost enumeration...")
#     vhost_result = gobuster.run_vhost_scan(
#         url="http://example.com",
#         wordlist="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
#         additional_args=["-t", "50"],
#         show_progress=True
#     )
#
#     print("\n" + "=" * 50)
#     if vhost_result['success']:
#         print("Vhost scan completed successfully!")
#     else:
#         print("Vhost scan failed:", vhost_result.get('error', vhost_result.get('stderr')))