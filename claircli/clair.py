# -*- coding: utf-8 -*-


import logging
from pprint import pformat
from .report import Report
from .utils import request_and_check, request

logger = logging.getLogger(__name__)


class Clair(object):

    def __init__(self, url):
        self.url = url
        self._v1_analyze_url = '{}/v1/layers'.format(url)

    def _make_layer_data(self, layer, parent, image):
        data = {'Layer': {
            'Format': 'Docker',
            'Name': layer,
            'ParentName': parent,
            'Headers': {}}}
        data['Layer']['Path'] = image.registry.get_blobs_url(image, layer)
        data['Layer']['Headers']['Authorization'] = image.registry.get_auth(
            image.repository)
        return data

    def analyze_image(self, image):
        logger.info('Analyze image %s', image.name)
        layers = image.layers
        logger.info('Remove old analysis data for %s from clair',
                    image.name)
        request('DELETE', '{}/{}'.format(self._v1_analyze_url, layers[0]))
        layers_length = len(layers)
        parent = ''
        for index, layer in enumerate(layers, start=1):
            logger.info('Push layer [%s/%s]: %s', index, layers_length, layer)
            layer_data = self._make_layer_data(layer, parent, image)
            parent = layer
            logger.debug('Layer data: %s', pformat(layer_data))
            request_and_check('POST', self._v1_analyze_url, json=layer_data)
        return layers

    def get_report(self, image):
        logger.info('Fetch vulnerabilities for %s', image.name)
        report_url = '{}/{}?features&vulnerabilities'.format(
            self._v1_analyze_url, image.layers[-1])
        resp = request_and_check('GET', report_url)
        vulnerabilities = resp.json()
        features = vulnerabilities.get('Layer', {}).get('Features')
        if features:
            vulnerabilities['ImageName'] = image.name
            return Report(vulnerabilities)
        logger.warning('Could not fetch vulnerabilities. '
                       'No features have been detected in '
                       'the image. This usually means that '
                       'the image is not supported by Clair')
        return None
