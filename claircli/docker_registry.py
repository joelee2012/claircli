# -*- coding: utf-8 -*-

import atexit
import json
import logging
import os
import random
import re
import shutil
import tarfile
import tempfile
import weakref
from collections import defaultdict
from os.path import isfile, join

import docker
from six.moves.BaseHTTPServer import HTTPServer

from .http_handler import PathHTTPHandler, start_http_server
from .utils import mkpdirs, request, request_and_check

DOCKER_HUP_REGISTRY = 'registry-1.docker.io'
logger = logging.getLogger(__name__)


class LocalRegistry(object):
    tmp_folder = tempfile.mkdtemp(prefix='claircli-')
    atexit.register(shutil.rmtree, tmp_folder)

    def __init__(self, ipaddr):
        port = random.randint(10000, 15000)
        self.url = 'http://{}:{}'.format(ipaddr, port)
        start_http_server(port, self.tmp_folder)
        self._client = docker.from_env(timeout=360)

    def get_auth(self, repository):
        return ''

    def get_blobs_url(self, image, layer):
        return '/'.join([self.url, image.repository,
                         'blobs', layer, 'layer.tar'])

    def get_manifest(self, image):
        repo_dir = join(self.tmp_folder, image.repository)
        manifest_json = join(repo_dir, 'manifests', image.tag)
        if not isfile(manifest_json):
            for d in ['blobs', 'manifests']:
                mkpdirs(join(repo_dir, d))
            blobs_dir = join(repo_dir, 'blobs')
            image_tar = join(repo_dir, 'image.tar')
            self.save_image(image, image_tar)
            with tarfile.open(image_tar) as tar:
                tar.extractall(blobs_dir)
            os.remove(image_tar)
            shutil.move(join(blobs_dir, 'manifest.json'), manifest_json)
        with open(manifest_json) as file_:
            return json.load(file_)

    def save_image(self, image, path):
        logger.debug('Saving %s to %s', image, path)
        image = self._client.images.get(image.name)
        with open(path, 'w+b') as file_:
            for chunk in image.save():
                file_.write(chunk)

    def clean_image(self, image):
        shutil.rmtree(join(self.tmp_folder, image.repository))


class RemoteRegistry(object):
    tokens = defaultdict(dict)
    token_pattern = re.compile(r'Bearer realm="(?P<realm>[^"]+)".*'
                               r'service="(?P<service>[^"]+).*')
    insec_regs = set()

    def __init__(self, domain):
        self.domain = domain
        schema = 'http' if domain in self.insec_regs else 'https'
        self.url = '{}://{}/v2/'.format(schema, domain)

    def __str__(self):
        return self.domain

    def get_auth(self, repository):
        if (
                not self.tokens[self.domain].get(repository) and
                self.tokens[self.domain].get('')
        ):
            self.tokens[self.domain][repository] = \
                self.tokens[self.domain].get('')
        elif not self.tokens[self.domain].get(repository):
            resp = request('GET', self.url)
            if resp.status_code not in (200, 401):
                resp.raise_for_status()
            elif resp.status_code == 200:
                self.tokens[self.domain][repository] = ''
            else:
                matcher = self.token_pattern.match(
                    resp.headers['WWW-Authenticate'])
                params = {'service': matcher.group('service'),
                          'client_id': 'claircli',
                          'scope': 'repository:{}:pull'.format(repository)}
                resp = request_and_check('GET', matcher.group('realm'),
                                         params=params)
                self.tokens[self.domain][repository] = \
                    'Bearer ' + resp.json()['token']
        return self.tokens[self.domain].get(repository)

    def get_manifest(self, image):
        url = '{}{image.repository}/manifests/{image.tag}'.format(
            self.url, image=image)
        headers = {'Accept':
                   'application/vnd.docker.distribution.manifest.v2+json,'
                   'application/vnd.docker.distribution.manifest.v1+json,'
                   'application/vnd.docker.distribution.manifest.list.v2+json',
                   'Authorization': self.get_auth(image.repository)}
        resp = request_and_check('GET', url, headers=headers)
        return resp.json()

    def get_blobs_url(self, image, layer):
        return '/'.join(f.strip('/') for f in [
            self.url, image.repository, 'blobs', layer
        ])

    def find_images(self, repository, tag):
        if self.domain == DOCKER_HUP_REGISTRY:
            logger.error('Not support to find images for docker hup')
            raise ValueError('Not support to find images for docker hup')
        resp = request_and_check('GET', self.url + '_catalog',
                                 headers={'Authorization': self.get_auth('')})
        repo_pattern = re.compile(repository or r'.*')
        tag_pattern = re.compile(tag or r'.*')
        for repo in resp.json().get('repositories', []):
            if not repo_pattern.search(repo):
                continue
            headers = {'Authorization': self.get_auth(repository)}
            tag_url = '{}{}/tags/list'.format(self.url, repo)
            resp = request_and_check('GET', tag_url, headers=headers)
            for tag_ in resp.json().get('tags', []):
                if tag_pattern.search(tag_):
                    yield '{}/{}:{}'.format(self.domain, repo, tag_)
