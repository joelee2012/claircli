# -*- coding: utf-8 -*-

import logging

from docker.auth import INDEX_NAME, resolve_repository_name
from docker.utils import parse_repository_tag

from .docker_registry import DOCKER_HUP_REGISTRY, LocalRegistry, RemoteRegistry

logger = logging.getLogger(__name__)

MANIFEST_LIST_V2 = 'application/vnd.docker.distribution.manifest.list.v2+json'
MANIFEST_V2 = 'application/vnd.docker.distribution.manifest.v2+json'


class Image(object):

    def __init__(self, name, registry=None):
        self.name = name
        self._layers = []
        self._images = []
        self._manifest = None
        reg, repo, tag = self.parse_id(name)
        self.repository = repo
        self.tag = tag or 'latest'
        if reg == INDEX_NAME:
            reg = DOCKER_HUP_REGISTRY
            self.repository = 'library/{}'.format(repo)
        if isinstance(registry, LocalRegistry):
            self.registry = registry
        else:
            self.registry = RemoteRegistry(reg)

    @classmethod
    def parse_id(cls, name):
        reg_repo, tag = parse_repository_tag(name)
        reg, repo = resolve_repository_name(reg_repo)
        return reg, repo, tag

    def __iter__(self):
        return iter(self.layers)

    def __len__(self):
        return len(self.layers)

    def __str__(self):
        return '<Image: {}>'.format(self.name)

    @property
    def manifest(self):
        if not self._manifest:
            self._manifest = self.registry.get_manifest(self)
        return self._manifest

    @property
    def images(self):
        if not self._images:
            images_list = []
            manifest = self.manifest
            if isinstance(self.registry, LocalRegistry):
                pass
            elif manifest['schemaVersion'] == 2 and manifest['mediaType'] \
                    == MANIFEST_LIST_V2:
                for single_manifest in manifest['manifests']:
                    reg, repo, _tag = self.parse_id(self.name)
                    images_list.append(Image('{}/{}@{}'.format(
                        reg, repo, single_manifest['digest'])))
            self._images = images_list
        return self._images

    @property
    def layers(self):
        if not self._layers:
            manifest = self.manifest
            if isinstance(self.registry, LocalRegistry):
                self._layers = [e.replace('/layer.tar', '')
                                for e in manifest[0]['Layers']]
            elif manifest['schemaVersion'] == 1:
                self._layers = [e['blobSum']
                                for e in manifest['fsLayers']][::-1]
            elif manifest['schemaVersion'] == 2 and manifest['mediaType'] \
                    == MANIFEST_V2:
                self._layers = [e['digest'] for e in manifest['layers']]
            elif manifest['schemaVersion'] == 2 and manifest['mediaType'] \
                    == MANIFEST_LIST_V2:
                self._layers = []
            else:
                raise ValueError(
                    'Wrong schemaVersion [%s]' % manifest['schemaVersion'])
        return self._layers

    def clean(self):
        if isinstance(self.registry, LocalRegistry):
            self.registry.clean_image(self)
