#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SourceCodeSniffer: Sniff out dangerous code segments
# Copyright (c) 2017, Austin Scott
#
# Contact information:
# Austin Scott
#


"""
Main application logic and automation functions
"""

__version__ = '0.1'
__lastupdated__ = 'April 11, 2017'

###
# Imports
###
import os
import sys
import time
import re
import ConfigParser

sys.path.insert(0, os.path.abspath('..'))

# from clint.textui import puts, progress, puts
BAR_TEMPLATE = '%s[%s%s] %i/%i - %s\r'
MILL_TEMPLATE = '%s %s %i/%i\r'
DOTS_CHAR = '.'
BAR_FILLED_CHAR = '#'
BAR_EMPTY_CHAR = ' '
MILL_CHARS = ['|', '/', '-', '\\']
# How long to wait before recalculating the ETA
ETA_INTERVAL = 1
# How many intervals (excluding the current one) to calculate the simple moving
# average
ETA_SMA_WINDOW = 9
STREAM = sys.stderr


class Bar(object):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.done()
        return False  # we're not suppressing exceptions

    def __init__(self, label='', width=32, hide=None, empty_char=BAR_EMPTY_CHAR,
                 filled_char=BAR_FILLED_CHAR, expected_size=None, every=1):
        self.label = label
        self.width = width
        self.hide = hide
        # Only show bar in terminals by default (better for piping, logging etc.)
        if hide is None:
            try:
                self.hide = not STREAM.isatty()
            except AttributeError:  # output does not support isatty()
                self.hide = True
        self.empty_char = empty_char
        self.filled_char = filled_char
        self.expected_size = expected_size
        self.every = every
        self.start = time.time()
        self.ittimes = []
        self.eta = 0
        self.etadelta = time.time()
        self.etadisp = self.format_time(self.eta)
        self.last_progress = 0
        if (self.expected_size):
            self.show(0)

    def show(self, progress, count=None):
        if count is not None:
            self.expected_size = count
        if self.expected_size is None:
            raise Exception("expected_size not initialized")
        self.last_progress = progress
        if (time.time() - self.etadelta) > ETA_INTERVAL:
            self.etadelta = time.time()
            self.ittimes = \
                self.ittimes[-ETA_SMA_WINDOW:] + \
                [-(self.start - time.time()) / (progress + 1)]
            self.eta = \
                sum(self.ittimes) / float(len(self.ittimes)) * \
                (self.expected_size - progress)
            self.etadisp = self.format_time(self.eta)
        x = int(self.width * progress / self.expected_size)
        if not self.hide:
            if ((progress % self.every) == 0 or  # True every "every" updates
                    (progress == self.expected_size)):  # And when we're done
                STREAM.write(BAR_TEMPLATE % (
                    self.label, self.filled_char * x,
                    self.empty_char * (self.width - x), progress,
                    self.expected_size, self.etadisp))
                STREAM.flush()

    def done(self):
        self.elapsed = time.time() - self.start
        elapsed_disp = self.format_time(self.elapsed)
        if not self.hide:
            # Print completed bar with elapsed time
            STREAM.write(BAR_TEMPLATE % (
                self.label, self.filled_char * self.width,
                self.empty_char * 0, self.last_progress,
                self.expected_size, elapsed_disp))
            STREAM.write('\n')
            STREAM.flush()

    def format_time(self, seconds):
        return time.strftime('%H:%M:%S', time.gmtime(seconds))


class logger:
    DEBUG = False;
    VERBOSE = False;

    @staticmethod
    def debug(msg):
        if logger.DEBUG == True:
            print(msg)

    @staticmethod
    def verbose(msg):
        if logger.VERBOSE == True:
            print(msg)


class colored:
    @staticmethod
    def red(printString):
        return printString
        # return "\033[0m\033[37m\033[41m" + printString

    @staticmethod
    def white(printString):
        return printString
        # return '\e[1;37m' + printString

    @staticmethod
    def blue(printString):
        return printString
        # return '\033[0;34m' + printString

    @staticmethod
    def green(printString):
        return printString
        # return '\033[0;32m' + printString

    @staticmethod
    def yellow(printString):
        return printString
        # return '\\033[1;33m' + printString

    @staticmethod
    def cyan(printString):
        return printString
        # return '\e[0;36m' + printString

    @staticmethod
    def grey(printString):
        return printString
        # return '\e[0;30m' + printString


class tabled:
    @staticmethod
    def column(colText, colWidth):
        if len(colText) < colWidth:
            return colText + (" " * (colWidth - len(colText)))


class consoleOut:
    @staticmethod
    def echoOut(echoText):
        os.system("echo " + echoText)


class SourceCodeSnifferMain:
    def __init__(self, argv):
        self.argv = argv
        self._start_time = time.clock()
        self._task_start_time = time.clock()
        self._column_width = 60
        self._compare_filename = "REPORT_Baseline_Compare_Results.txt"
        self._config_files = ["Default.ini","ASP.ini", "CSharp.ini"]
        self._ignore_files = (".html", ".js", "robots.txt")
        self._path_to_scan = "."
        self._report_filename = "REPORT.txt"
        self._report_timer_filename = "REPORT_TIMES.txt"
        self._remove_line_words = ['time', 'elapsed', 'Compare', 'BlkIo', 'Variable issues', 'Variable ConOut']
        self._summaryReport = []
        self._summaryReportTimer = []
        self._summaryRiskTotal = 0
        self._summaryRiskCount = 0

        # parse arguments
        self.parse_args()

    def get_version(self):
        return "%s" % (__version__)

    def add_to_summary_report(self, text):
        self._summaryReport.append(text)

    def print_banner(self):
        """
        Prints banner
        """
        print(colored.red("  Source Code Sniffer Version: " + __version__ + " Updated: " + __lastupdated__))

    def usage(self):
        print "\n- Command Line Usage\n\t``# %.65s [options]``\n" % sys.argv[0]
        print "Options\n-------"
        print "====================== =============================================================="
        print "-c --configFiles        specify the config files (default=" + self._config_files + ")"
        print "                        config files should be comma separated"
        print "-p --pathToScan         specify the path to scan (default=" + self._path_to_scan + ")"
        print "                        use the forward slash / for both *nix and windows paths"
        print "-i --ignoreFiles        specify files to not scan (default=" + self._ignore_files + ")"
        print "                        ignored files and file types should be comma separated "
        print "-v --verbose            verbose mode"
        print "-d --debug              show debug output"
        print "-l --log                output to log file"
        print "====================== =============================================================="
        print "Example:"
        print " python SourceCodeSniffer.py -c ASP.ini,CSharp.ini,Default.ini,VBScript.ini -p c:/testpath/test/ -i .html,robots.txt"
    def parse_args(self):
        import getopt
        try:
            opts, args = getopt.getopt(self.argv, "fhvdnc:p:i:",
                                       ["help"])
        except getopt.GetoptError, err:
            print str(err)
            self.usage()
            return 32

        for o, a in opts:
            if o in ("-v", "--verbose"):
                print "verbose"
                logger.VERBOSE = True
            elif o in ("-d", "--debug"):
                print "debug"
                logger.DEBUG = True
            elif o in ("-c", "--configFiles"):
                self._config_files = a.split(',')
            elif o in ("-i", "--ignoreFiles"):
                self._ignore_files = tuple(a.split(','))
            elif o in ("-h", "--help"):
                self.usage()
                sys.exit(0)
                return 0
            elif o in ("-p", "--pathToScan"):
                self._path_to_scan = a
            else:
                assert False, "unknown option"

    def sourceCodeSniffFolder(self):
        # Generate Validation Data Dumps
        print(colored.red("Sniffing for dangerous code..."))
        for root, subdirs, files in os.walk(os.path.normpath(self._path_to_scan)):
            logger().verbose('--\nroot = ' + root)
            for subdir in subdirs:
                logger().verbose('\t- subdirectory ' + subdir)
            for filename in files:
                file_path = os.path.join(root, filename)
                logger().debug('\t- file %s (full path: %s)' % (filename, file_path))
                if not file_path.lower().endswith(self._ignore_files):
                    self.sourceCodeSniffFile(file_path)

    def sourceCodeSniffFile(self, file_path):
        filename_has_been_shown = False
        logger().verbose("\t\t- Sniffing a file: %s" % file_path)
        for each_section in bar(self.config.sections()):
            logger().verbose("\t\t\t- " + each_section.__str__())
            pattern = re.compile(self.config.get(each_section, 'Regex'), re.IGNORECASE)
            for i, line in enumerate(open(file_path)):
                for match in re.finditer(pattern, line):
                    if filename_has_been_shown == False:
                        print file_path
                        filename_has_been_shown = True
                    print('\t-Found %s on line %s: %s' % (self.config.get(each_section, 'Message'), i + 1 , match.groups()))
                    print line
                    logger().verbose(line)

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    def main(self):
        self.print_banner()
        print(colored.red("Using configuration files: " + str(self._config_files)))
        print(colored.red("Recursively sniffing path for dangerous code: " + self._path_to_scan))
        sys.stderr = open("errorlog.txt", 'w')
        # load config
        self.config = ConfigParser.ConfigParser()
        self.config.read(self._config_files)
        # remove previous report
        if os.path.isfile(self._report_filename):
            os.remove(self._report_filename)

        self.sourceCodeSniffFolder()
        sys.exit(0)
        return 0


def bar(it, label='', width=32, hide=None, empty_char=BAR_EMPTY_CHAR, filled_char=BAR_FILLED_CHAR, expected_size=None,
        every=1):
    """Progress iterator. Wrap your iterables with it."""

    count = len(it) if expected_size is None else expected_size

    with Bar(label=label, width=width, hide=hide, empty_char=BAR_EMPTY_CHAR,
             filled_char=BAR_FILLED_CHAR, expected_size=count, every=every) \
            as bar:
        for i, item in enumerate(it):
            yield item
            bar.show(i + 1)


def main(argv=None):
    sourceCodeSnifferMain = SourceCodeSnifferMain(argv if argv else sys.argv[1:])
    return sourceCodeSnifferMain.main()


if __name__ == "__main__":
    sys.exit(main())
