import time
import os

class LogIngestor:
    """
    Reads logs from files. Supports batch reading and tailing (simulated stream).
    """
    def __init__(self, log_dir):
        self.log_dir = log_dir

    def fetch_logs(self, filename, tail=False):
        """
        Yields raw log lines from a file.
        """
        filepath = os.path.join(self.log_dir, filename)
        if not os.path.exists(filepath):
            return

        with open(filepath, 'r') as f:
            # Move to end if tailing existing file initially
            if tail:
                f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    if tail:
                        time.sleep(0.1)
                        continue
                    else:
                        break
                yield line
