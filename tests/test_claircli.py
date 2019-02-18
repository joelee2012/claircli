import unittest
import logging
import json
from claircli.docker_image import Image
from claircli.docker_registry import LocalRegistry, RemoteRegistry
from claircli.clair import Clair
from claircli.cli import ClairCli
from claircli.report import Report
from mock import patch
from os.path import isdir, isfile
from requests import get as req_get
import os
import responses
from argparse import Namespace
import shutil
from six.moves.urllib.parse import urlencode, quote
from collections import defaultdict

logger = logging.getLogger(__name__)


class ClairCmdTestBase(unittest.TestCase):

    def setUp(self):
        self.name = 'registry.example.com/org/image-name:version'
        self.registry = 'registry.example.com'
        self.repository = 'org/image-name'
        self.tag = 'version'
        self.unauth_headers = {
            'WWW-Authenticate': 'Bearer realm="https://{registry}/v2/token",service="{registry}"'.format(registry=self.registry)}
        self.clair_url = 'http://mock_clair:6060'
        self.registry_url = 'https://registry.example.com/v2/'
        token_url_params = {'service': self.registry,
                            'client_id': 'claircli',
                            'scope': 'repository:{}:pull'.format(self.repository)}
        self.registry_token_url = 'https://registry.example.com/v2/token?' + urlencode(token_url_params)
        self.image_manifest_url = 'https://registry.example.com/v2/org/image-name/manifests/version'
        responses.add(responses.GET, self.registry_url,
                      json={'message': 'authentication required'}, status=401, headers=self.unauth_headers)
        responses.add(responses.GET, self.registry_token_url, json = {'token': 'test-token'}, status = 200)
        with open('tests/test_data/manifest.v2.json') as f:
            self.manifest=json.load(f)
        responses.add(responses.GET, self.image_manifest_url,
                      json = self.manifest, status = 200)
        self.v1_analyze_url='%s/v1/layers' % self.clair_url
        self.layers=[e['digest'] for e in self.manifest['layers']]
        responses.add(responses.DELETE, '%s/%s' %
                      (self.v1_analyze_url, self.layers[0]))
        responses.add(responses.POST, self.v1_analyze_url)
        with open('tests/test_data/origin_vulnerabilities.json') as f:
            self.origin_data=json.load(f)
        responses.add(responses.GET, '%s/%s?features&vulnerabilities' %
                      (self.v1_analyze_url, self.layers[-1]), json = self.origin_data)
        _, self.html=Report.get_report_path(self.name, '.html')

    def tearDown(self):
        RemoteRegistry.tokens = defaultdict(dict)
        if isfile(self.html):
            os.remove(self.html)

    def assert_called_with_url(self):
        self.assertEqual(responses.calls[0].request.url, self.registry_url)
        self.assertEqual(
            responses.calls[1].request.url, self.registry_token_url)
        self.assertEqual(
            responses.calls[2].request.url, self.image_manifest_url)


def mock_docker_client(mock_docker):
    mock_client = mock_docker.return_value
    mock_image = mock_client.images.get.return_value
    mock_image.save.return_value = open('tests/test_data/manifest.tar', 'r+b')
    return mock_docker


class TestImage(ClairCmdTestBase):

    def test_parse_image(self):
        with open('tests/test_data/images.json') as f:
            images = json.load(f)
        for i in images:
            image = Image(i['name'])
            self.assertEqual(str(image), i['name'])
            self.assertEqual(image.repository, i['repository'])
            self.assertEqual(image.tag, i['tag'])
            self.assertEqual(str(image.registry), i['registry'])

    @responses.activate
    def test_manifest(self):
        image = Image(self.name)
        self.assertEqual(image.manifest, self.manifest)
        self.assert_called_with_url()


    @patch('docker.from_env')
    def test_manifest_local(self, mock_docker):
        mock_docker_client(mock_docker)
        registry = LocalRegistry('localhost')
        image = Image(self.name, registry)
        with open('tests/test_data/manifest.json') as file_:
            manifest = json.load(file_)
        self.assertEqual(image.manifest, manifest)


    @patch('docker.from_env')
    def test_layers_local(self, mock_docker):
        mock_docker_client(mock_docker)
        registry = LocalRegistry('localhost')
        image = Image(self.name, registry)
        with open('tests/test_data/manifest.json') as file_:
            manifest = json.load(file_)
        self.assertEqual(image.layers, [e.replace(
            '/layer.tar', '') for e in manifest[0]['Layers']])

    @responses.activate
    def test_layers_v1(self):
        with open('tests/test_data/manifest.v1.json') as f:
            manifest = json.load(f)
        responses.replace(responses.GET, self.image_manifest_url,
                          json=manifest, status=200)
        image = Image(self.name)
        self.assertEqual(image.layers, [e['blobSum']
                                        for e in manifest['fsLayers']][::-1])
        self.assert_called_with_url()

    @responses.activate
    def test_layers_v2(self):
        image = Image(self.name)
        self.assertEqual(image.layers,
                         [e['digest'] for e in self.manifest['layers']])
        self.assert_called_with_url()


class TestClair(ClairCmdTestBase):

    @responses.activate
    def test_analyze_remote_image(self):
        clair = Clair(self.clair_url)
        image = Image(self.name)
        layers = clair.analyze_image(image)
        self.assertEqual(layers, self.layers)
        self.assert_called_with_url()
        for index, layer in enumerate(self.layers, start=4):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
            self.assertEqual(req_body['Layer']['Path'], image.registry.get_blobs_url(image, layer))

    @patch('docker.from_env')
    @responses.activate
    def test_analyze_local_image(self, mock_docker):
        mock_docker_client(mock_docker)
        clair = Clair(self.clair_url)
        registry = LocalRegistry('localhost')
        image = Image(self.name, registry)
        responses.add(responses.DELETE, '%s/%s' %
                      (self.v1_analyze_url, image.layers[0]))
        layers = clair.analyze_image(image)
        self.assertEqual(layers, image.layers)
        for index, layer in enumerate(layers, start=1):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
            self.assertEqual(req_body['Layer']['Path'], image.registry.get_blobs_url(image, layer))

class TestClairCli(ClairCmdTestBase):

    def test_read_white_list(self):
        white_list = ClairCli.read_white_list('tests/test_data/example-whitelist.yaml')
        # self.assertEqual(white_list.get('common'), {'CVE-2017-6055': 'XML', 'CVE-2017-5586': 'OpenText'})
        self.assertEqual(white_list.get('alpine'), {'CVE-2017-6055': 'XML', 'CVE-2017-5586': 'OpenText', 'CVE-2017-3261': 'SE'})
        self.assertEqual(white_list.get('ubuntu'), {'CVE-2017-6055': 'XML', 'CVE-2017-5586': 'OpenText', 'CVE-2017-5230': 'XSX'})

    @responses.activate
    def test_batch_analyze_remote_images(self):
        with patch('sys.argv', ['claircli.py', 'batch-analyze', '-c', self.clair_url, self.name]):
            cli = ClairCli()
            cli.run()
        self.assert_called_with_url()
        for index, layer in enumerate(self.layers, start=4):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
        self.assertTrue(isfile(self.html))

    @patch('docker.from_env')
    @responses.activate
    def test_batch_analyze_local_images(self, mock_docker):
        mock_docker_client(mock_docker)
        with open('tests/test_data/manifest.json') as file_:
            manifest = json.load(file_)
        layers = [e.replace('/layer.tar', '') for e in manifest[0]['Layers']]
        responses.add(responses.DELETE, '%s/%s' % (self.v1_analyze_url, layers[0]))
        responses.add(responses.GET, '%s/%s?features&vulnerabilities' %
                      (self.v1_analyze_url, layers[-1]), json=self.origin_data)
        with patch('sys.argv', ['claircli.py', 'batch-analyze', '-l', 'localhost', '-c', self.clair_url, self.name]):
            cli = ClairCli()
            cli.run()
        for index, layer in enumerate(layers, start=1):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
        self.assertTrue(isfile(self.html))
