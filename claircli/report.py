# -*- coding: utf-8 -*-
import copy
import json
import logging
import os
import re
from collections import defaultdict
from os.path import abspath, dirname, join
from pprint import pformat

import yaml
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)
SEVERITIES = ['Defcon1', 'Critical', 'High', 'Medium',
              'Low', 'Negligible', 'Unknown']
SEVERITY_INDEX = {key: index for index, key in enumerate(SEVERITIES, start=1)}
WORK_DIR = os.getcwd()


class WhiteList(object):
    def __init__(self, filename):
        self.filename = filename
        with open(filename) as file_:
            self.data = yaml.safe_load(file_)

    def get(self, key, default=None):
        approved = dict(self.data.get('common', {}))
        approved.update(self.data.get(key, {}))
        return approved or default

    def __getitem__(self, key):
        return self.get(key)


class Report(object):
    templates = join(abspath(dirname(__file__)), 'templates')

    def __init__(self, source):
        self.source = source
        self.data = {}

    @property
    def ok(self):
        return [] == self.data.get('Unapproved', [])

    def process_data(self, threshold='Unknown', white_list=None):
        white_list = white_list or {}
        layer_data = self.source.get('Layer')
        namespace = layer_data.get('NamespaceName')
        approved = white_list.get(namespace.split(':')[0], {})
        logger.debug('Approved vulnerablities: %s', pformat(approved))
        data = {
            'ImageName': self.source['ImageName'],
            'NamespaceName': namespace,
            'Unapproved': set(),
            'Approved': set(),
            'Severity': defaultdict(int)}
        vulnerabilities = []

        def is_approved(vulne, feature):
            vname = vulne['Name'].replace(':', '-')
            return (vname in approved and
                    feature['Name'] == approved[vname]) or \
                (SEVERITY_INDEX[vulne['Severity']] > SEVERITY_INDEX[threshold])

        for feature in layer_data.get('Features', []):
            for vulner in feature.get('Vulnerabilities', []):
                if is_approved(vulner, feature):
                    status = 'Approved'
                else:
                    status = 'Unapproved'
                data[status].add(vulner['Name'])
                data['Severity'][vulner['Severity']] += 1
                data['Severity']['Total'] += 1
                temp = {'FeatureName': feature['Name'],
                        'FeatureVersion': feature['Version'],
                        'AddedBy': feature['AddedBy'],
                        'Status': status}
                for key in vulner.keys():
                    temp[key] = vulner[key]
                vulnerabilities.append(temp)
        for status in ['Approved', 'Unapproved']:
            data[status] = list(data[status])
        data['Vulnerabilities'] = sorted(
            vulnerabilities, key=lambda v: SEVERITY_INDEX[v['Severity']])
        self.data = data

    @classmethod
    def get_report_path(cls, image_name, ext):
        report_name = 'clair-' + re.sub(r'/|:', '_', image_name) + ext
        report_path = join(WORK_DIR, report_name)
        return report_path

    def to_html(self):
        html_report = Report.get_report_path(self.source['ImageName'], '.html')
        logger.info('Generate html report for %s', self.source['ImageName'])
        j2_env = Environment(loader=FileSystemLoader(
            self.templates), trim_blocks=True)
        template = j2_env.get_template('html-report.j2')
        template.stream(severities=SEVERITIES,
                        vulnerabilities=self.data).dump(html_report)
        logger.info('Location: %s', html_report)

    def to_json(self):
        json_report = Report.get_report_path(self.source['ImageName'], '.json')
        logger.info('Generate json report for %s', self.source['ImageName'])
        with open(json_report, 'w') as file_:
            json.dump(self.data, file_, indent=2)
        logger.info('Location: %s', json_report)

    def to_xml(self):
        pass

    def to(self, suffix):
        getattr(self, 'to_' + suffix)()

    def to_table(self):
        pass

    def to_console(self):
        for servity in SEVERITIES:
            v_count = self.data['Severity'][servity]
            msg = '{} : {}'.format('{:<10}'.format(servity), v_count)
            if v_count == 0:
                logger.info(msg)
            else:
                logger.warning(msg)
