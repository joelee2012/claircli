# -*- coding: utf-8 -*-
import logging
import os
from pprint import pformat

from requests import request

logger = logging.getLogger(__name__)


def mkpdirs(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def request_and_check(method, url, **kwargs):
    logger.debug('%s: %s with parameters: %s', method, url, pformat(kwargs))
    resp = request(method, url, **kwargs)
    logger.debug('Response: %s', resp)
    resp.raise_for_status()
    return resp
