import duplicity.backend
from duplicity import globals
from duplicity import log
from duplicity import util
from duplicity.errors import BackendException, FatalBackendException

class OpenDriveBackend(duplicity.backend.Backend):
    """
    Backend to access OpenDrive storage services
    Contributed in 2016 by Marc Vollmer <admin@vmtek.de>
    """

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)

    def _list(self):
        """List files in directory"""

    def _query(self, remote_filename):
        """Get the size of the remote file"""

    def _get(self, remote_filename, local_path):
        """Get remote filename, saving it to local_path"""

    def _put(self, source_path, remote_filename=None):
        """Transfer source_path to remote_filename"""

duplicity.backend.register_backend("opendrive", OpenDriveBackend)
