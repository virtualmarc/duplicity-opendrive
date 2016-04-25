from duplicity import backend
from duplicity import log
from duplicity.errors import BackendException
import urllib2
import json


class OpenDriveBackend(backend.Backend):
    """
    Backend to access OpenDrive storage services
    Contributed in 2016 by Marc Vollmer <admin@vmtek.de>
    """

    def __init__(self, parsed_url):
        backend.Backend.__init__(self, parsed_url)
        self.parsed_url = parsed_url
        self.username = parsed_url.username
        self.password = self.get_password()
        self.directory = parsed_url.path.replace("/", "")
        if self.directory == "":
            self.directory = "0"

        self.baseurl = "https://dev.opendrive.com/api/v1/"

        self.sessionid = None
        self.retry = 0

        log.Info("Using OpenDrive Backend with directory ID %s" % self.directory)

    def __dopostrequest(self, url, postobject):
        """
        Do a Post Request
        :param url: URL to POST to
        :param postobject: Object to POST (will be encoded as JSON)
        :return: Response Object
        """
        postdata = json.dumps(postobject).encode('utf8')

        req = urllib2.Request(url, data=postdata, headers={'content-type': 'application/json'})
        req.get_method = lambda: 'POST'
        return urllib2.urlopen(req)

    def __dogetrequest(self, url):
        """
        Go a Get Request
        :param url: URL to GET
        :return: Response Object
        """
        req = urllib2.Request(url)
        req.get_method = lambda: 'GET'
        return urllib2.urlopen(req)

    def __decodejson(self, data):
        """
        Decode a JSON Object
        :param data: Byte Data
        :return: JSON Object
        """
        strdata = data.decode('utf8')
        return json.loads(strdata)

    def _list(self):
        """
        Return list of filenames (byte strings) present in backend
        """
        try:
            self.login()
            log.Info("Listing files in directory %s" % self.directory)

            listurl = self.baseurl + "folder/list.json/" + self.sessionid + "/" + self.directory

            resp = self.__dogetrequest(listurl)
            status = resp.getcode()
            if status == 401:
                log.Warn("Session expired")
                self.login(forced=True)
            elif status != 200:
                log.FatalError("Failed to list files in directory %s, API Returned Status: %d" % (self.directory, status))
                raise BackendException("Failed to list files in directory %s, API Returned Status: %d" % (self.directory, status))
            else:
                self.retry = 0

            data = resp.read()
            directoryinfo = self.__decodejson(data)
            files = []
            for fileinfo in directoryinfo["Files"]:
                files.append(fileinfo["Name"])
            return files
        except:
            log.FatalError("Error listing files in directory %s" % self.directory)
            raise BackendException("Error listing files in directoy %s" % self.directory)

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

    def login(self, forced=False):
        """
        Login to OpenDrive
        """
        try:
            if not self.sessionid or forced:
                self.close()

                if forced:
                    if self.retry >= 5:
                        log.FatalError("Login Retry Limit of 5 reached")
                        raise BackendException("Login Retry Limit of 5 reached")
                    else:
                        self.retry += 1

                log.Info("Logging in to OpenDrive")

                loginurl = self.baseurl + "session/login.json"
                logindata = {"username": self.username, "passwd": self.password}

                resp = self.__dopostrequest(loginurl, logindata)
                status = resp.getcode()
                if status != 200:
                    log.FatalError("Login failed, API returned Status code: %d" % status)
                    raise BackendException("Error logging in to OpenDrive. API Returned Status %d" % status)

                data = resp.read()
                userinfo = self.__decodejson(data)
                self.sessionid = userinfo["SessionID"]
        except:
            log.FatalError("Failed to login to OpenDrive")
            raise BackendException("Error logging in to OpenDrive")

    def close(self):
        """
        Close the backend, releasing any resources held and
        invalidating any file objects obtained from the backend.
        """
        try:
            if self.sessionid:
                log.Info("Logout")

                logouturl = self.baseurl + "session/logout.json"
                logoutdata = {"session_id": self.sessionid}

                resp = self.__dopostrequest(logouturl, logoutdata)
                status = resp.getcode()
                if status != 200:
                    log.Warn("Logout failed, API Returned Status Code: %d" % status)

                self.sessionid = None
                self.retry = 0
        except:
            log.Warn("Logout failed")


backend.register_backend("opendrive", OpenDriveBackend)
