# -*- coding: utf-8 -*-


import logging
import os
from os.path import join, relpath
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler

logger = logging.getLogger(__name__)


class PathHTTPHandler(SimpleHTTPRequestHandler):

    def __init__(self, http_request, client_address,
                 server, serve_path=os.getcwd()):
        self.serve_path = serve_path
        SimpleHTTPRequestHandler.__init__(
            self, http_request, client_address, server)

    def translate_path(self, path):
        path = SimpleHTTPRequestHandler.translate_path(self, path)
        relpath_ = relpath(path, os.getcwd())
        abspath_ = join(self.serve_path, relpath_)
        return abspath_

    def log_message(self, format, *args):
        logger.debug('%s - - [%s] %s\n',
                     self.client_address[0],
                     self.log_date_time_string(),
                     format % args)
