import subprocess
import json
import time


class HashcatWrapper:
    def __init__(self, hashcat_path="hashcat6"):
        self.hashcat_path = hashcat_path

    def run_attack(self, hash_file, attack_mode, target, hash_mode=0,
                   additional_args=None, timeout=None):
        """
        Run hashcat attack

        Args:
            hash_file: Path to hash file
            attack_mode: Attack mode (0=straight, 1=combination, 3=brute-force, etc.)
            target: Wordlist file or mask for attack
            hash_mode: Hash type mode
            additional_args: List of additional arguments
            timeout: Timeout in seconds
        """
        cmd = [
            self.hashcat_path,
            "-a", str(attack_mode),
            "-m", str(hash_mode),
            hash_file,
            target
        ]

        if additional_args:
            cmd.extend(additional_args)

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            stdout, stderr = process.communicate(timeout=timeout)
            return {
                'stdout': stdout,
                'stderr': stderr,
                'returncode': process.returncode,
                'success': process.returncode == 0
            }

        except subprocess.TimeoutExpired:
            process.kill()
            return {'error': 'Process timed out', 'success': False}
        except Exception as e:
            return {'error': str(e), 'success': False}

    def get_status(self, session_name):
        """Get status of a running hashcat session"""
        cmd = [self.hashcat_path, "--status", "--session", session_name]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error getting status: {e}"


# Example usage
# hc = HashcatWrapper()

# # Dictionary attack
# result = hc.run_attack(
#     hash_file="hashes.txt",
#     attack_mode=0,  # Straight attack
#     target="wordlist.txt",
#     hash_mode=1000,  # NTLM
#     additional_args=["--force"]
# )
#
# if result['success']:
#     print("Attack completed successfully")
#     print(result['stdout'])
# else:
#     print("Attack failed:", result.get('error', result.get('stderr')))