import os
import struct
import logging
from typing import List

# Set up logging
TRACE = 5  # Custom TRACE level
logging.addLevelName(TRACE, "TRACE")

def trace(self, message, *args, **kws):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kws)

logging.Logger.trace = trace

# Function to configure logging
def configure_logging():
    # Get the caller module name and directory
    caller_frame = logging.currentframe().f_back
    module_name = caller_frame.f_globals['__name__']
    module_file = caller_frame.f_globals['__file__']
    module_dir = os.path.basename(os.path.dirname(module_file))
    
    log_file_name = f"{module_dir}_{module_name}.log"

    # Configure logging to file
    logging.basicConfig(
        level=TRACE,
        format='%(asctime)s %(levelname)s:%(message)s',
        handlers=[logging.FileHandler(log_file_name, 'w'), logging.StreamHandler()]
    )

    return logging.getLogger(module_name)
