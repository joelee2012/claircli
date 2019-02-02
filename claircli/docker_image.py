# -*- coding: utf-8 -*-

import logging
from docker.utils import parse_repository_tag
from docker.auth import resolve_repository_name, INDEX_NAME
from .docker_registry import LocalRegistry, RemoteRegistry, DOCKER_HUP_REGISTRY


logger = logging.getLogger(__name__)


class Image(object):

    def __init__(self, name, registry=None):
        self.name = name
        self._layers = []
        repo, tag = parse_repository_tag(name)
        reg_domain, repo_name = resolve_repository_name(repo)
        self.repository = repo_name
        self.tag = tag or 'latest'
        if reg_domain == INDEX_NAME:
            reg_domain = DOCKER_HUP_REGISTRY
            self.repository = 'library/{}'.format(repo_name)
        if isinstance(registry, LocalRegistry):
            self.registry = registry
        else:
            self.registry = RemoteRegistry(reg_domain)

    def __iter__(self):
        return iter(self.layers)

    def __len__(self):
        return len(self.layers)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Image: {}>'.format(self.name)

    @property
    def manifest(self):
        return self.registry.get_manifest(self)

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
            elif manifest['schemaVersion'] == 2:
                self._layers = [e['digest'] for e in manifest['layers']]
            else:
                raise ValueError(
                    'Wrong schemaVersion [%s]' % manifest['schemaVersion'])
        return self._layers

    def clean(self):
        if isinstance(self.registry, LocalRegistry):
            self.registry.clean_image(self)
