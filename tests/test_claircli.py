import json
import logging
import os
import shutil
import unittest
from argparse import Namespace
from collections import defaultdict
from os.path import isdir, isfile

import responses
from requests import get as req_get
from six.moves.urllib.parse import quote, urlencode

from claircli.clair import Clair
from claircli.cli import ClairCli
from claircli.docker_image import Image
from claircli.docker_registry import LocalRegistry, RemoteRegistry
from claircli.report import Report, WhiteList
try:
    from unittest.mock import patch
except:
    from mock import patch

logger = logging.getLogger(__name__)


class ClairCmdTestBase(unittest.TestCase):

    def setUp(self):
        self.name = 'registry.example.com/org/image-name:version'
        self.reg = 'registry.example.com'
        self.repo = 'org/image-name'
        self.tag = 'version'
        self.reg_url = 'https://%s/v2/' % self.reg
        self.token_url = self.reg_url + 'token'
        auth = 'Bearer realm="%s",service="%s"' % (self.token_url, self.reg)
        self.headers = {'WWW-Authenticate': auth}
        self.clair_url = 'http://mock_clair:6060'
        params = {'service': self.reg,
                  'client_id': 'claircli',
                  'scope': 'repository:%s:pull' % self.repo}
        self.token_url = self.token_url + '?' + urlencode(params)
        self.manifest_url = self.reg_url + 'org/image-name/manifests/version'
        responses.add(responses.GET, self.reg_url,
                      json={'message': 'authentication required'},
                      status=401, headers=self.headers)
        responses.add(responses.GET, self.token_url,
                      json={'token': 'test-token'}, status=200)
        with open('tests/test_data/manifest.v2.json') as f:
            self.manifest = json.load(f)
        responses.add(responses.GET, self.manifest_url,
                      json=self.manifest, status=200)
        self.v1_analyze_url = '%s/v1/layers' % self.clair_url
        self.layers = [e['digest'] for e in self.manifest['layers']]
        responses.add(responses.DELETE, '%s/%s' %
                      (self.v1_analyze_url, self.layers[0]))
        responses.add(responses.POST, self.v1_analyze_url)
        with open('tests/test_data/origin_vulnerabilities.json') as f:
            self.origin_data = json.load(f)
        responses.add(responses.GET, '%s/%s?features&vulnerabilities' %
                      (self.v1_analyze_url, self.layers[-1]),
                      json=self.origin_data)
        self.html = Report.get_report_path(self.name, '.html')

    def tearDown(self):
        RemoteRegistry.tokens = defaultdict(dict)
        # if isfile(self.html):
        #     os.remove(self.html)

    def assert_called_with_url(self):
        self.assertEqual(responses.calls[0].request.url, self.reg_url)
        self.assertEqual(
            responses.calls[1].request.url, self.token_url)
        self.assertEqual(
            responses.calls[2].request.url, self.manifest_url)


def mock_docker_client(mock_docker):
    mock_client = mock_docker.return_value
    mock_image = mock_client.images.get.return_value
    mock_image.save.return_value = open('tests/test_data/manifest.tar', 'r+b')
    return mock_docker


class TestImage(ClairCmdTestBase):

    def test_parse_image(self):
        with open('tests/test_data/images.json') as f:
            images = json.load(f)
        for expected in images:
            image = Image(expected['name'])
            self.assertEqual(image.name, expected['name'])
            self.assertEqual(image.repository, expected['repository'])
            self.assertEqual(image.tag, expected['tag'])
            self.assertEqual(str(image.registry), expected['registry'])

    @responses.activate
    def test_manifest(self):
        image = Image(self.name)
        self.assertEqual(image.manifest, self.manifest)
        self.assert_called_with_url()

    @responses.activate
    def test_list_manifest(self):
        with open('tests/test_data/manifest.list.v2.json') as f:
            list_manifest = json.load(f)
        responses.replace(responses.GET, self.manifest_url,
                          json=list_manifest, status=200)
        image = Image(self.name)
        self.assertEqual(image.manifest, list_manifest)
        self.assert_called_with_url()

    @responses.activate
    def test_unsupported_manifest(self):
        with open('tests/test_data/manifest.unsupported.json') as f:
            manifest = json.load(f)
        responses.replace(responses.GET, self.manifest_url,
                          json=manifest, status=200)
        with self.assertRaises(ValueError):
            image = Image(self.name)
            image.layers

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
        responses.replace(responses.GET, self.manifest_url,
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

    @responses.activate
    def test_layers_list_v2(self):
        list_image_manifest_url = self.reg_url + \
            'org/image-name/manifests/sha256:d0fec089e611891a03f3282f10115bb186ed46093c3f083eceb250cee64b63eb'

        with open('tests/test_data/manifest.list.v2.json') as f:
            list_manifest = json.load(f)
        with open('tests/test_data/manifest.list.v2-image.json') as f:
            list_image_manifest = json.load(f)
        responses.replace(responses.GET, self.manifest_url,
                          json=list_manifest, status=200)
        responses.add(responses.GET, list_image_manifest_url,
                      json=list_image_manifest, status=200)
        image = Image(self.name)
        self.assertEqual(image.images[0].layers, [e['digest']
                         for e in list_image_manifest['layers']])
        self.assertEqual(image.layers, [])
        self.assert_called_with_url()
        self.assertEqual(
            responses.calls[3].request.url, list_image_manifest_url)


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
            self.assertEqual(req_body['Layer']['Path'],
                             image.registry.get_blobs_url(image, layer))

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
            self.assertEqual(req_body['Layer']['Path'],
                             image.registry.get_blobs_url(image, layer))


class TestClairCli(ClairCmdTestBase):

    def test_read_white_list(self):
        white_list = WhiteList('tests/test_data/example-whitelist.yaml')
        self.assertEqual(white_list.get('common'), {
                         'CVE-2017-6055': 'XML',
                         'CVE-2017-5586': 'OpenText'})
        self.assertEqual(white_list.get('alpine'), {
                         'CVE-2017-6055': 'XML',
                         'CVE-2017-5586': 'OpenText',
                         'CVE-2017-3261': 'SE'})
        self.assertEqual(white_list.get('ubuntu'), {
                         'CVE-2017-6055': 'XML',
                         'CVE-2017-5586': 'OpenText',
                         'CVE-2017-5230': 'XSX'})
        self.assertEqual(white_list.get('centos'), {
                         'CVE-2017-6055': 'XML',
                         'CVE-2017-5586': 'OpenText'})

    @responses.activate
    def test_analyze_images(self):
        with patch('sys.argv', ['claircli', '-d', '-c',
                                self.clair_url, self.name]):
            cli = ClairCli()
            cli.run()
        self.assert_called_with_url()
        for index, layer in enumerate(self.layers, start=4):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
        self.assertTrue(isfile(self.html))

    @responses.activate
    def test_analyze_images_in_insecure_registry(self):

        reg_url = 'http://%s/v2/' % self.reg
        token_url = reg_url + 'token'
        auth = 'Bearer realm="%s",service="%s"' % (token_url, self.reg)
        headers = {'WWW-Authenticate': auth}
        params = {'service': self.reg,
                  'client_id': 'claircli',
                  'scope': 'repository:%s:pull' % self.repo}
        token_url = token_url + '?' + urlencode(params)
        manifest_url = reg_url + 'org/image-name/manifests/version'
        responses.reset()
        responses.add(responses.GET, reg_url,
                      json={'message': 'authentication required'},
                      status=401, headers=headers)
        responses.add(responses.GET, token_url,
                      json={'token': 'test-token'}, status=200)

        responses.add(responses.GET, manifest_url,
                      json=self.manifest, status=200)
        self.layers = [e['digest'] for e in self.manifest['layers']]
        responses.add(responses.DELETE, '%s/%s' %
                      (self.v1_analyze_url, self.layers[0]))
        responses.add(responses.POST, self.v1_analyze_url)
        responses.add(responses.GET, '%s/%s?features&vulnerabilities' %
                      (self.v1_analyze_url, self.layers[-1]),
                      json=self.origin_data)

        with patch('sys.argv', ['claircli',  '-c',
                                self.clair_url, '-i', self.reg, self.name]):
            cli = ClairCli()
            cli.run()
        for index, url in enumerate([reg_url, token_url, manifest_url]):
            self.assertEqual(responses.calls[index].request.url, url)

        for index, layer in enumerate(self.layers, start=4):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
        self.assertTrue(isfile(self.html))
        self.assertIn(self.reg, RemoteRegistry.insec_regs)

    @responses.activate
    def test_analyze_images_in_secure_registry(self):

        reg_url = 'https://%s/v2/' % self.reg
        token = 'just-some-auth-token-which-is-really-long'
        auth = 'Basic %s' % token
        headers = {'WWW-Authenticate': auth}
        manifest_url = reg_url + 'org/image-name/manifests/version'
        responses.reset()
        responses.add(responses.GET, manifest_url,
                      json=self.manifest, status=200, headers=headers)
        self.layers = [e['digest'] for e in self.manifest['layers']]
        responses.add(responses.DELETE, '%s/%s' %
                      (self.v1_analyze_url, self.layers[0]))
        responses.add(responses.POST, self.v1_analyze_url)
        responses.add(responses.GET, '%s/%s?features&vulnerabilities' %
                      (self.v1_analyze_url, self.layers[-1]),
                      json=self.origin_data)

        with patch('sys.argv', ['claircli',  '-c',
                                self.clair_url,
                                '-k', self.reg + ':' + token,
                                # Include a check for ignored arguments
                                '-k', '1234', '-k', 'ab:', '-k', ':',
                                self.name]):
            cli = ClairCli()
            cli.run()
        for index, url in enumerate([manifest_url, ]):
            self.assertEqual(responses.calls[index].request.url, url)

        for index, layer in enumerate(self.layers, start=2):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
        self.assertTrue(isfile(self.html))
        self.assertEqual(0, len(RemoteRegistry.insec_regs))
        self.assertIn(self.reg, RemoteRegistry.tokens)
        self.assertIn('', RemoteRegistry.tokens[self.reg])
        self.assertEqual(auth, RemoteRegistry.tokens[self.reg][''])
        self.assertIn(self.repo, RemoteRegistry.tokens[self.reg])
        self.assertEqual(auth, RemoteRegistry.tokens[self.reg][self.repo])

    @patch('docker.from_env')
    @responses.activate
    def test_analyze_local_images(self, mock_docker):
        mock_docker_client(mock_docker)
        with open('tests/test_data/manifest.json') as file_:
            manifest = json.load(file_)
        layers = [e.replace('/layer.tar', '') for e in manifest[0]['Layers']]
        responses.add(responses.DELETE, '%s/%s' %
                      (self.v1_analyze_url, layers[0]))
        responses.add(responses.GET, '%s/%s?features&vulnerabilities' %
                      (self.v1_analyze_url, layers[-1]), json=self.origin_data)
        with patch('sys.argv', ['claircli', '-l', 'localhost',
                                '-c', self.clair_url, self.name]):
            cli = ClairCli()
            cli.run()
        for index, layer in enumerate(layers, start=1):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
        self.assertTrue(isfile(self.html))
    

    @responses.activate
    def test_analyze_manifest_list(self):
        list_image_manifest_url = self.reg_url + \
            'org/image-name/manifests/sha256:d0fec089e611891a03f3282f10115bb186ed46093c3f083eceb250cee64b63eb'
        with open('tests/test_data/manifest.list.v2.json') as f:
            list_manifest = json.load(f)
        with open('tests/test_data/manifest.list.v2-image.json') as f:
            list_image_manifest = json.load(f)
        with open('tests/test_data/origin_vulnerabilities_list.json') as f:
            list_origin_data = json.load(f)
        responses.add(responses.GET, '%s/%s?features&vulnerabilities' %
                      (self.v1_analyze_url, list_origin_data['Layer']['Name']),
                      json=list_origin_data)
        responses.replace(responses.GET, self.manifest_url,
                          json=list_manifest, status=200)
        responses.add(responses.GET, list_image_manifest_url,
                      json=list_image_manifest, status=200)
        layers = [e['digest'] for e in list_image_manifest['layers']]
        responses.add(responses.DELETE, '%s/%s' %
                      (self.v1_analyze_url, layers[0]))
        for layer in layers:
            responses.add(responses.GET, '%s/%s' %
                          (self.v1_analyze_url, layer))
        with patch('sys.argv', ['claircli', '-d', '-c',
                                self.clair_url, self.name]):
            cli = ClairCli()
            cli.run()
        image = Image(self.name)
        self.assert_called_with_url()
        for index, layer in enumerate(image.images[0].layers, start=5):
            self.assertEqual(
                responses.calls[index].request.url, self.v1_analyze_url)
            req_body = json.loads(responses.calls[index].request.body)
            self.assertEqual(req_body['Layer']['Name'], layer)
        self.html = Report.get_report_path('{}/{}@{}'.format(self.reg, self.repo, image.manifest['manifests'][0]['digest']), '.html')
        self.assertTrue(isfile(self.html))
