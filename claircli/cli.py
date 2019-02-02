# -*- coding: utf-8 -*-

import logging
import sys
from argparse import ArgumentParser
from collections import defaultdict
import colorlog
import yaml
from requests import exceptions
from .report import SEVERITIES
from .docker_registry import LocalRegistry, RemoteRegistry
from .docker_image import Image
from .clair import Clair
from .version import __version__

logger = logging.getLogger(__name__)


class ClairCli(object):

    def __init__(self):
        # common options
        parent_parser = ArgumentParser(add_help=False)
        parent_parser.add_argument(
            '-c', '--clair', default='http://localhost:6060',
            help='Clair URL, default: %(default)s')
        parent_parser.add_argument(
            '-w', '--white-list', help='Path to the whitelist file')
        parent_parser.add_argument(
            '-T', '--threshold', choices=SEVERITIES,
            default='Unknown', metavar='THRESHOLD',
            help='CVE severity threshold, default: %(default)s'
                 ', validated values are: {}'.format(SEVERITIES))
        parent_parser.add_argument(
            '-f', '--formats', choices=['html', 'json', 'xml'],
            action='append', default=['html'],
            help='Output report to format, default: %(default)s')
        parent_parser.add_argument('-L', '--log-file', help='Log to file')
        parent_parser.add_argument(
            '-d', '--debug', action='store_true', help='Debug mode')

        parser = ArgumentParser(
            description='Simple command line tool to '
                        'interact with CoreOS Clair')
        parser.add_argument(
            '-V', '--version', action='version', version=__version__)
        subparsers = parser.add_subparsers(
            description='Subcommands of claircli')
        # subcommand batch-analyze
        bparser = subparsers.add_parser(
            'batch-analyze', help='Batch analyze docker images with clair',
            parents=[parent_parser])
        bparser.add_argument(
            '-l', '--local-ip', help='Local ip address')
        bparser.add_argument('images', nargs='+', help='Docker images')
        bparser.set_defaults(func=self.batch_analyze)
        # subcommand fuzzy-analyze
        fparser = subparsers.add_parser(
            'fuzzy-analyze', help='Fuzzy analyze docker images with clair',
            parents=[parent_parser])
        fparser.add_argument(
            '-r', '--repository', required=True, help='Pattern of repository')
        fparser.add_argument(
            '-t', '--tag', default=r'^latest$',
            help='Pattern of tag, default: %(default)s')
        fparser.add_argument('registry', help='Domain of docker registry')
        fparser.set_defaults(func=self.fuzzy_analyze)
        self.args = parser.parse_args()
        self.setup_logging()

    @classmethod
    def read_white_list(cls, filename):
        approved = {}
        if filename is None:
            return approved
        with open(filename) as file_:
            data = yaml.safe_load(file_)
        common = data.get('common', {})
        for key, value in data.items():
            if key == 'common':
                continue
            value.update(common)
            approved[key] = value
        return approved

    def setup_logging(self):
        logger = logging.getLogger('claircli')
        console_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s|%(levelname)s|%(message)s')
        file_formatter = logging.Formatter(
            '%(asctime)s|%(levelname)s| %(message)s')
        stdout = colorlog.StreamHandler(sys.stdout)
        stdout.setFormatter(console_formatter)
        logger.addHandler(stdout)
        logger.setLevel(logging.INFO)
        if self.args.debug:
            logger.setLevel(logging.DEBUG)
        if self.args.log_file:
            handler = logging.FileHandler(self.args.log_file, 'w', delay=True)
            handler.setFormatter(file_formatter)
            logger.addHandler(handler)

    def batch_analyze(self):
        args = self.args
        registry = None
        if args.local_ip:
            registry = LocalRegistry(args.local_ip)
        clair = Clair(args.clair)
        args.white_list = self.read_white_list(args.white_list)
        args.images = (Image(name, registry) for name in args.images)
        stats = defaultdict(list)
        for index, image in enumerate(args.images, start=1):
            logger.info('{:*^60}'.format(index))
            try:
                clair.analyze_image(image)
                report = clair.get_report(image)
                if not report:
                    stats['IMAGES WERE NOT SUPPORTED'].append(image.name)
                    continue
                report.process_data(args.threshold, args.white_list)
                report.to_console()
                for format_ in args.formats:
                    report.to(format_)
                if report.ok:
                    stats['IMAGES WITHOUT DETECTED VULNERABILITIES'].append(
                        image.name)
                else:
                    stats['IMAGES WITH DETECTED VULNERABILITIES'].append(
                        image.name)
            except exceptions.HTTPError as exp:
                if exp.response.status_code in [400, 404] and \
                    ('Not Found for url' in str(exp) or
                     'no such image' in str(exp)):
                    logger.warning('Could not find [%s]', image.name)
                    stats['IMAGES COULD NOT BE FOUND'].append(image.name)
                else:
                    logger.warning('Could not analyze %s: Got response %d '
                                   'from clair with message: %s',
                                   image.name, exp.response.status_code,
                                   exp.response.text)
                    stats['IMAGES COULD NOT BE ANALYZED'].append(
                        image.name)
            except KeyboardInterrupt:
                logger.warning('Keyboard interrupted')
                return 2
            except Exception as exp:
                stats['IMAGES WERE ANALYZED WITH ERROR'].append(image.name)
                logger.warning(str(exp))
            finally:
                image.clean()
        return self.print_stats(stats)

    def print_stats(self, stats):
        total = sum(map(len, stats.values()))
        logger.info('='*60)
        logger.info('{:^60}'.format('CLAIR ANALYSIS REPORT (%d)' % total))
        logger.info('='*60)
        exit_code = 0
        for key, value in stats.items():
            logger.info('%s (%d)', key, len(value))
            if key == 'IMAGES WITHOUT DETECTED VULNERABILITIES':
                for element in value:
                    logger.info(element)
            else:
                for element in value:
                    logger.error(element)
                exit_code = 1
        return exit_code

    def fuzzy_analyze(self):
        self.args.local_ip = None
        args = self.args
        registry = RemoteRegistry(args.registry)
        logger.info('Find images in registry [%s] by [%s] and [%s]',
                    args.registry, args.repository, args.tag)
        self.args.images = registry.find_images(args.repository, args.tag)
        return self.batch_analyze()

    def run(self):
        return self.args.func()


def main():
    cli = ClairCli()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
