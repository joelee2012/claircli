# -*- coding: utf-8 -*-

import logging
import json
import os
import random
import re
import shutil
import tarfile
from collections import defaultdict
from os.path import join, isfile
from threading import Thread
from functools import partial
import docker
from six.moves.BaseHTTPServer import HTTPServer
from .http_handler import PathHTTPHandler
from .utils import mkpdirs, request_and_check, request

DOCKER_HUP_REGISTRY = 'registry-1.docker.io'
logger = logging.getLogger(__name__)


class LocalRegistry(object):
    tmp_folder = '/tmp/claircli'

    def __init__(self, domain):
        port = random.randint(10000, 15000)
        self.url = 'http://{}:{}'.format(domain, port)
        mkpdirs(self.tmp_folder)
        logger.info('Start http server in local')
        httpd = HTTPServer(('', port), partial(
            PathHTTPHandler, serve_path=self.tmp_folder))
        thread = Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()
        logger.info('Serving at port: %s', port)
        self._client = docker.from_env(timeout=360)

    def get_auth(self, repository):
        return ''

    def get_blobs_url(self, image, layer):
        return '/'.join([self.url, image.repository,
                         'blobs', layer, 'layer.tar'])

    def get_manifest(self, image):
        manifest_json = join(
            self.tmp_folder, image.repository, 'manifests', image.tag)
        if not isfile(manifest_json):
            blobs_dir = join(self.tmp_folder, image.repository, 'blobs')
            manifest_dir = join(self.tmp_folder, image.repository, 'manifests')
            mkpdirs(blobs_dir)
            mkpdirs(manifest_dir)
            image_tar = join(self.tmp_folder, image.repository, 'image.tar')
            self.save_image(image.name, image_tar)
            tar = tarfile.open(image_tar)
            tar.extractall(blobs_dir)
            tar.close()
            shutil.move(join(blobs_dir, 'manifest.json'), manifest_json)
            os.remove(image_tar)
        with open(manifest_json) as file_:
            return json.load(file_)

    def save_image(self, image_name, path):
        logger.debug('Saving image [%s] to %s', image_name, path)
        image = self._client.images.get(image_name)
        with open(path, 'w+b') as file_:
            for chunk in image.save():
                file_.write(chunk)

    def clean_image(self, image):
        shutil.rmtree(join(self.tmp_folder, image.repository))


class RemoteRegistry(object):
    tokens = defaultdict(dict)
    token_url_pattern = re.compile(r'Bearer realm="(?P<realm>[^"]+)".*'
                                   r'service="(?P<service>[^"]+).*')

    def __init__(self, domain):
        self.domain = domain
        self.url = 'https://{}/v2/'.format(self.domain)

    def __str__(self):
        return self.domain

    def get_auth(self, repository):
        if not self.tokens[self.domain].get(repository):
            resp = request('GET', self.url)
            if resp.status_code not in (200, 401):
                resp.raise_for_status()
            elif resp.status_code == 200:
                self.tokens[self.domain][repository] = ''
            else:
                matcher = self.token_url_pattern.match(
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
                   'application/vnd.docker.distribution.manifest.v1+json',
                   'Authorization': self.get_auth(image.repository)}
        resp = request_and_check('GET', url, headers=headers)
        return resp.json()

    def get_blobs_url(self, image, layer):
        return '/'.join([self.url, image.repository, 'blobs', layer])

    def find_images(self, repository=r'', tag=r'^latest$'):
        if self.domain == DOCKER_HUP_REGISTRY:
            logger.error('Not support to find images for docker hup')
            raise ValueError('Not support to find images for docker hup')
        resp = request_and_check('GET', self.url + '_catalog',
                                 headers={'Authorization': self.get_auth('')})
        repo_pattern = re.compile(repository)
        tag_pattern = re.compile(tag)
        for repo in resp.json().get('repositories', []):
            if not repo_pattern.search(repo):
                continue
            headers = {'Authorization': self.get_auth(repository)}
            resp = request_and_check('GET',
                                     '{}{}/tags/list'.format(self.url, repo),
                                     headers=headers)
            tags = resp.json().get('tags', [])
            for tag_ in tags:
                if tag_pattern.search(tag_):
                    yield '{}/{}:{}'.format(self.domain, repo, tag_)
