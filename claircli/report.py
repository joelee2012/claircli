# -*- coding: utf-8 -*-


import json
import logging
import re
import os
from os.path import join, abspath, dirname
from collections import defaultdict
from pprint import pformat
from jinja2 import Environment, FileSystemLoader


logger = logging.getLogger(__name__)
SEVERITIES = ['Defcon1', 'Critical', 'High', 'Medium',
              'Low', 'Negligible', 'Unknown']
SEVERITY_INDEX = {key: index for index, key in enumerate(SEVERITIES, start=1)}
WORK_DIR = os.getcwd()


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
            'Unapproved': [],
            'Approved': [],
            'Severity': defaultdict(int)}
        vulnerabilities = []

        def is_approved(vulne, feature):
            vname = vulne['Name'].replace(':', '-')
            return (vname in approved and feature[
                'Name'] == approved[vname]) or (SEVERITY_INDEX[vulne[
                    'Severity']] > SEVERITY_INDEX[threshold])

        for feature in layer_data.get('Features', []):
            for vulnerability in feature.get('Vulnerabilities', []):
                if is_approved(vulnerability, feature):
                    status = 'Approved'
                else:
                    status = 'Unapproved'
                data[status].append(vulnerability['Name'])
                data['Severity'][vulnerability['Severity']] += 1
                data['Severity']['Total'] += 1
                temp = {'FeatureName': feature['Name'],
                        'FeatureVersion': feature['Version'],
                        'AddedBy': feature['AddedBy'],
                        'Status': status}
                for key in vulnerability.keys():
                    temp[key] = vulnerability[key]
                vulnerabilities.append(temp)
        data['Vulnerabilities'] = sorted(
            vulnerabilities, key=lambda v: SEVERITY_INDEX[v['Severity']])
        self.data = data

    @classmethod
    def get_report_path(cls, image_name, ext):
        report_name = 'clair-' + re.sub(r'/|:', '_', image_name) + ext
        report_path = join(WORK_DIR, report_name)
        return image_name, report_path

    def to_html(self):
        image_name, html_report = Report.get_report_path(
            self.source['ImageName'], '.html')
        logger.info('Generate html report for %s', image_name)
        j2_env = Environment(loader=FileSystemLoader(
            self.templates), trim_blocks=True)
        template = j2_env.get_template('html-report.j2')
        template.stream(severities=SEVERITIES,
                        vulnerabilities=self.data).dump(html_report)
        logger.info('Location: %s', html_report)

    def to_json(self):
        image_name, json_report = Report.get_report_path(
            self.source['ImageName'], '.json')
        logger.info('Generate json report for %s', image_name)
        with open(json_report, 'w') as file_:
            json.dump(self.data, file_)
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
