"""A command-line interface to the reports lib."""

import os
import sys
import optparse

if '.' not in sys.path:
    sys.path.insert(0, '.')
    sys.path.insert(0, './libs')
from libs.reports import utils

DEFAULT_DATA_FILE = 'report.pkl'
DEFAULT_DATA_PATH = utils.get_reports_path(filename=DEFAULT_DATA_FILE)

def main():
    parser = optparse.OptionParser()
    parser.set_usage('%prog <report_type> [options]')
    parser.add_option('-o', '--output-file', dest='output_file',
        help='set a specific output file for the report')
    parser.add_option('-s', '--session', dest='session',
        help='set the session name to pull the default report data for that session')
    parser.add_option('-t', '--template-file', dest='template_file',
        help='use a custom template file to create the report')
    parser.add_option('-d', '--data-file', dest='data_file',
        help='input file for data collection (default: %s)' % DEFAULT_DATA_PATH)
    
    opts, args = parser.parse_args()
    
    if len(args) != 1:
        parser.print_usage()
        sys.exit(1)
    
    report_type = args[0]
    try:
        mod = utils.find_exploit_report(report_type)
    except utils.LoadError as e:
        sys.exit('Could not load exploit: %s\n'
            'Make sure the name is correct and you are running from the '
            'CANVAS root.' % e)
    
    if opts.data_file:
        data_file = opts.data_file
    elif opts.session:
        data_file = utils.get_reports_path(opts.session, DEFAULT_DATA_FILE)
    else:
        data_file = DEFAULT_DATA_PATH
    
    if opts.output_file:
        output_file = opts.output_file
    elif opts.session:
        fname = utils.generate_output_filename(module_name)
        output_file = utils.get_reports_path(opts.session, fname)
    else:
        fname = utils.generate_output_filename(module_name)
        output_file = utils.get_reports_path(filename=fname)
    
    print 'generating report ...'
    mod.generate(data_file=data_file, template_file=opts.template_file,
        output_file=output_file)
    
    print 'done. report resides at: %s' % output_file

if __name__ == '__main__':
    main()
