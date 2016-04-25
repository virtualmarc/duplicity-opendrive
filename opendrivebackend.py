import duplicity.backend
from duplicity import globals
from duplicity import log
from duplicity import util
from duplicity.errors import BackendException


class OpenDriveBackend(duplicity.backend.Backend):
    """
    Backend to access OpenDrive storage services
    Contributed in 2016 by Marc Vollmer <admin@vmtek.de>
    """

    def __init__(self, parsed_url):
        duplicity.backend.Backend.__init__(self, parsed_url)
        self.parsed_url = parsed_url
        self.username = parsed_url.username
        self.password = self.get_password()
        self.directory = parsed_url.path
        self.baseurl = "https://dev.opendrive.com/api/v1"

        log.Info("Using OpenDrive Backend with directory ID %s" % self.directory)

    def _list(self):
        """
        Return list of filenames (byte strings) present in backend
        """
        pass

    def get(self, remote_filename, local_path):
        """Retrieve remote_filename and place in local_path"""
        pass

    def put(self, source_path, remote_filename=None):
        """
        Transfer source_path (Path object) to remote_filename (string)

        If remote_filename is None, get the filename from the last
        path component of pathname.
        """
        pass

    def delete(self, filename_list):
        """
        Delete each filename in filename_list, in order if possible.
        """
        pass

    def _query_file_info(self, filename):
        """
        Return metadata about file

        Supported metadata are:
        'size': if >= 0, size of file
                if -1, file is not found
                if None, error querying file
        """
        pass

    def close(self):
        """
        Close the backend, releasing any resources held and
        invalidating any file objects obtained from the backend.
        """
        pass


duplicity.backend.register_backend("opendrive", OpenDriveBackend)
