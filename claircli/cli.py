# -*- coding: utf-8 -*-

from argparse import ArgumentParser
from collections import defaultdict
import logging
import sys
import argparse
import textwrap

from requests import exceptions
import colorlog
import yaml

from .clair import Clair
from .docker_image import Image
from .docker_registry import LocalRegistry, RemoteRegistry
from .report import SEVERITIES, WhiteList
from .__version__ import __version__


logger = logging.getLogger(__name__)


class ClairCli(object):
    description = textwrap.dedent('''
    Command line tool to interact with CoreOS Clair, analyze docker image with
    clair in different ways''')
    epilog = '''Examples:

    # analyze and output report to html
    # clair is running at http://localhost:6060
    claircli example.reg.com/myimage1:latest example.reg.com/myimage2:latest

    # analyze and output report to html
    # clair is running at https://example.clair.com:6060
    claircli -c https://example.clair.com:6060 example.reg.com/myimage1:latest

    # analyze and output report to html, json
    claircli -f html -f json example.reg.com/myimage1:latest

    # analyze with threshold and white list
    claircli -t High -w white_list_file.yml example.reg.com/myimage1:latest

    # analyze image on local host
    claircli -l <local ip address> myimage1:latest myimage2:latest

    # analyze image on other host foo
    export DOCKER_HOST=tcp://<ip of foo>:<port of docker listen>
    claircli -l <local ip address> myimage1:latest

    # analyze with regular expression, following will match
    # example.reg.com/myimage1:latest
    # and example.reg.com/myimage2:latest
    claircli -r example.reg.com/myimage:latest

    # analyze with regular expression, following will match
    # example.reg.com/myimage1:latest only
    claircli -r example.reg.com/^myimage1$:^latest$
    '''

    def __init__(self):
        # common options
        parser = ArgumentParser(
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self.epilog)
        parser.add_argument(
            '-V', '--version', action='version', version=__version__)
        parser.add_argument(
            '-c', '--clair', default='http://localhost:6060',
            help='clair url, default: %(default)s')
        parser.add_argument(
            '-w', '--white-list', help='path to the whitelist file')
        parser.add_argument(
            '-T', '--threshold', choices=SEVERITIES,
            default='Unknown', metavar='THRESHOLD',
            help='cvd severity threshold, if any servity of vulnerability'
            ' above of threshold, will return non-zero, default: %(default)s'
            ', choices are: {}'.format(SEVERITIES))
        parser.add_argument(
            '-f', '--formats', choices=['html', 'json'],
            action='append', default=['html'],
            help='output report file with give format, default: %(default)s')
        parser.add_argument('-L', '--log-file', help='save log to file')
        parser.add_argument(
            '-d', '--debug', action='store_true', help='print more logs')
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            '-l', '--local-ip', help='ip address of local host')
        group.add_argument(
            '-r', '--regex', action='store_true',
            help='if set, repository and tag of images will be '
            'treated as regular expression')
        parser.add_argument(
            'images', nargs='+', help='docker images or regular expression')
        parser.set_defaults(func=self.analyze_image)
        self.args = parser.parse_args()
        self.setup_logging()

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

    def resolve_images(self, images):
        result = set()
        for pattern in images:
            reg, repo, tag = Image.parse_id(pattern)
            registry = RemoteRegistry(reg)
            for name in registry.find_images(repo, tag):
                result.add(name)
        return result

    def analyze_image(self):
        args = self.args
        registry = None
        if args.local_ip:
            registry = LocalRegistry(args.local_ip)
        elif args.regex:
            args.images = self.resolve_images(args.images)

        clair = Clair(args.clair)
        if args.white_list:
            args.white_list = WhiteList(args.white_list)
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
                    logger.warning('%s was not found', image)
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
        logger.info('=' * 60)
        logger.info('{:^60}'.format(
            'CLAIR ANALYSIS REPORTS: (%d) IN TOTAL' % total))
        logger.info('=' * 60)
        exit_code = 0

        def log_func(func, key, value):
            func('%s (%d)', key, len(value))
            for element in value:
                func(element)

        for key, value in stats.items():
            if key == 'IMAGES WITHOUT DETECTED VULNERABILITIES':
                log_func(logger.info, key, value)
            else:
                log_func(logger.error, key, value)
                exit_code = 1
        return exit_code

    def run(self):
        return self.args.func()


def main():
    cli = ClairCli()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
