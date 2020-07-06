#!/usr/bin/env python
"""
#===========================================================================
##Script Header
#
# Copyright (c) 2018, 2019, 2020 Cisco Systems, Inc.
#
# Name:
#   est_coap_client.py
#
# Purpose:
#   Emulate a simple EST client running CoAP to perform simple traffic flows
#   when testing an EST server.
#
# Description:
#   Used in conjunction with CUnit to test EST server running CoAP.
#
# Author:
#   John Manuel
#
# References:
#
# Notes and Testbed assumptions:
#   Program is executed on host acting as EST client running over CoAP.
#
# Testbed diagram:
#
# Synopsis:
#   est_coap_client.py <--test testcase_name> <--server server_name>
#                      <--port <socket #> <--inet <4|6>> <--cacert filename>
#                      <--cert filename> <--key filename> <--csr filename>
#                      <--noverify> <--block_size #> <--cipher cipher_name>
#                      <--protocol <1 or 1.2 or None>> <--early> <--base64>
#                      <--noclose> <--value #> <--string string>
#                      <--debug|DEBUG> <--timestamp> <--out filename>
#                      <--output_dir dirname>
# TIMS ID:
#
# Arguments:
#   --test       (Mandatory) Name of the test case matching C-unit test case
#   --cacert     (Mandatory) CA Certificate file name
#   --cert       (Optional) Certificate file name
#   --key        (Optional) Key file name
#   --server     (Optional) Host name/address of the EST server to talk to
#                           [Default is loopback address 127.0.0.1 -or- ::1]
#   --port       (Optional) UDP socket to send traffic out on
#                           [Default is 5684]
#   --inet       (Optional) Which IP stack to expect connection on
#                           Values are 4 & 6 [Default is 4]
#   --csr        (Optional) CSR file name used for enrolls (PEM/base64)
#   --noverify   (Optional) Do not verify enroll/re-enroll payload certificate
#   --block_size (Optional) Default block size to used in messages
#   --cipher     (Optional) OpenSSL ciphers to open socket with
#   --protocol   (Optional) Which DTLS protocol version (Values: 1, 1.2, None)
#   --early      (Optional) Client sends BLOCK2 size for early negotiation
#   --base64     (Optional) Send/Receive payload base64 encoded instead of DER
#   --noclose    (Optional) Do not send a close/notify alert when closing DTLS
#   --value      (Optional) Pass a specific number to be used by subtest
#   --string     (Optional) Pass a specific string to be used by subtest
#   --debug      (Optional) Turn on additional script log messages
#   --DEBUG      (Optional) Same as --debug, keep all intermediate output files
#   --timestamp  (Optional) Log the start/stop times of the callflow
#   --out        (Optional) Name of output cert file
#   --output_dir (Optional) Where output cert/key/pem files are stored
#
# Sample Usage:
#   ./est_coap_client.py --test SIMPLE_ENROLL --port 8202 -debug
#   ./est_coap_client.py --test SERVER_KEYGEN --port 8202 --value 5 --string "long"
#
# Test Script Procedure:
#    Startup UDP/DTLS connection to the EST server
#    Send CoAP/EST messages and wait for responses.
#
# Dependencies:
#    Python MUST be running version 2.7.9 or higher
#    (will NOT work with Python 3.X, currently a work in progress)
#    OpenSSL 1.0.2 MUST be used
#    (will NOT work with OpenSSL 1.1.X, until Python 3.X work is complete)
#    Python environment must include the DTLS library:
#        https://pypi.org/project/Dtls/#description
#
#    LD_LIBRARY_PATH & PATH must point to same supported version of openssl.
#    LD_LIBRARY_PATH must be updated before running the emulator.
#    PATH can either be updated before running the emulator or
#    by using the environment variable 'OPENSSL_PYTHON_BIN'.
#
# Setup:
#    Make sure the certificate/keys are properly setup to communicate
#    with the EST CoAP server. This can be done by using the following
#    command on the same host as this emulator:
#        openssl s_client -connect <hostname>:<socket#> -cert <cert_file.pem>
#          -key <key_file.pem> -CAfile <cacert_file.pem> -dtls1_2
#          (-cert/-key arguments may be omitted)
#    If the DTLS handshake is completed successfully, then the emulator
#    should have no problems establishing connections with the same
#    certs/keys.
#
#    If test cases are developed that need a specific values passed in
#    on the command line. There are 2 generic arguments available.
#        '--value' is used to pass in a number
#        '--string' is used to pass in a string
#    Examples:
#        def Value001(retry_limit):
#         (--value # from command line, will be passed to variable retry_limit)
#        def String001(password):
#         (--string <string> from command line, will be passed to password)
#        def Both001(retry_limit, password):
#         (make sure the number is first, followed by the string)
#         (use both --value & --string on the command line)
#        def Multiple001(auth_string):
#            username, password, auth_method = auth_string.split(':')
#         (for multiple numbers/strings, it can only be passed in one string)
#         (determine a delimiter character, append values, send as one --string)
#         (parse the values out within the test case)
#
# Test Cases:
#  GET_CACERTS          = Get CA Certs Transfer
#  CSR_ATTRS            = CSR Attributes Transfer
#  SIMPLE_ENROLL        = Simple Enroll Transfer
#  SIMPLE_REENROLL      = Re-Enroll Transfer
#  SERVER_KEYGEN        = Server-Side KeyGen Transfer
#  * - REQ_VOUCHER      = BRSKI Request Voucher
#  VOUCHER_STATUS       = BRSKI Voucher Status
#  ENROLL_STATUS        = BRSKI Enroll Status
#  CONTENT_FORMAT       = Simple Enroll (CONTENT-FORMAT with invalid #)
#  ACCEPT               = Simple Enroll (ACCEPT with invalid #)
#  TC5712               = Get CA Certs (Reset during server transmit)
#
#   * - Not Completed
#
#   NOTE: Each testcase can handle both piggyback & separate response
#         message flows. (Refer to section 5.2 of RFC 7252)
#         Since libEST/libCoAP uses piggyback responses, separate responses
#         has NOT been used/tested in the last 2 years of development.
#
# Pass/Fail Criteria:
#
# ToDo:
#   Make sure --cipher option works (medium)
#   Complete EST BSRKI Request Voucher support (low)
#   Test separate response support (low)
#
# End of Header
#===========================================================================

#---------------------------------------------------------------------------
## Design Notes
#
# The following CoAP Fields can be modified:
#  - Version
#  - Type
#  - Token Length
#  - Method Code
#  - Message ID
#  - Options
#  - Payload
#
#    Version
#    -------
#    To change for a single transmitted portion of a message:
#    coap.set_version(#)
#    To change for entire test:
#    coap.VERSION = #
#
#    Type
#    ----
#    To change for a single transmitted portion of a message:
#    coap.set_transaction_type(#)
#    To change for entire test:
#    coap.TRANSACTION_TYPE = #
#
#    Token Length
#    ------------
#    To change for a single transmitted portion of a message:
#    coap.set_token_length(#)
#    To change for entire test:
#    coap.TOKEN_LENGTH = #
#
#    Token
#    -----
#    To change for a single transmitted portion of a message:
#    coap.set_token('ABC')
#    To change for entire test:
#    coap.TOKEN = 'ABC'
#    Note: If you want the correct token length,
#          then make sure that token length is at default:
#      coap.set_token_length(DEFAULT_NUM)
#      coap.TOKEN_LENGTH = DEFAULT_NUM
#    (It WILL work fine, if the token length has been never changed)
#
#    Method Code
#    -----------
#    To change for a single transmitted portion of a message:
#    coap.set_method_code(#)
#    There is NO way to change it for entire test
#    It depends on which EST message is being transmitted/received
#
#    Message ID
#    ----------
#    To reset the value for the remainder of the test:
#    coap.set_message_id(#)
#    To change it's relative value:
#    coap.set_message_id(increment=#)
#    If running for a series of CoAP transmission blocks,
#      EST functions will call:
#    coap.next_message_id()
#
#    Options
#    -------
#    There are several variables use to track/build the options portion
#    of the message
#
#    coap.options_master    = Options dictionary to send in next message
#    coap.options_add       = Options dictionary to add to
#                             'coap.options_master'in next message
#    coap.options_delete    = Options list to remove from
#                             'coap.options_master' in next message
#    coap.options_overwrite = Options dictionary to update
#                             'coap.options_master' for next message
#    coap.options_string    = User built hex string to send in hex message
#
#    Note: These variables are reset after each CoAP message sent
#
#    Notes:
#    Do not set "coap.options_master" if using EST methods:
#      est.build_cacerts
#      est.build_csrattrs
#      est.build_enroll
#      est.build_reenroll
#      est.build_server_keygen
#      est.build_req_voucher
#      est.build_get
#      est.build_post
#    It will get overwritten
#
#    Example (Add Options):
#    coap.options_add = coap.build_options(uri_host='localhost', etag='ABC')
#    coap_msg = est.build_enroll()
#    This will add a 2nd URI-HOST option and ETAG option to the next
#    outgoing CoAP message
#
#    Example (Add Options) [2 of the same options]:
#    coap.options_add = coap.build_options(etag='ABC')
#    coap.options_add = coap.build_options(coap.options_add,
#                                                  etag='123')
#    coap_msg = est.build_enroll()
#    This will add 2 ETAG options to the next outgoing CoAP message
#
#    Example (Delete Options):
#    coap.options_delete = [coap.CONTENT_FORMAT, coap.URI_PORT,]
#    coap_msg = est.build_enroll()
#    This will remove options CONTENT-FORMAT & URI-PORT from the next
#    outgoing CoAP message
#    (Any option that is not in 'coap.options_master' will be ignored)
#
#    Example (Overwrite Options):
#    coap.options_overwrite = coap.build_options(uri_path='/est/bad')
#    coap_msg = est.build_enroll()
#    This will change URI-PATH option value in next outgoing CoAP message
#    (Any option not in 'coap.options_master', will be ignored, skipped)
#
#    Example (Option String):
#    coap.option_string = 'FEEDBEEF1234'.decode('hex')
#    coap_msg = est.build_enroll()
#    This changes the options to the string above on next outgoing CoAP message
#
#    Retry Limit
#    -----------
#    This can be used to purposely not respond to messages from the server.
#    Causing the server to re-transmit its last message.
#
#    To change for a single transmitted portion of a message:
#    coap.set_retry_limit(#)
#    To change for entire test:
#    coap.RETRY_LIMIT = #
#
#    Response Delay
#    --------------
#    Can be used to purposely delay responding to messages from the server.
#    Used to check response timeouts are honored.
#
#    To change for a single transmitted portion of a message:
#    coap.set_response_delay(#)
#    To change for entire test:
#    coap.RESPONSE_DELAY = #
#
# End of Design Notes
#---------------------------------------------------------------------------
"""

from socket import *
import ssl
from dtls import do_patch
#import dtls
import sys
import os
import re
import time
import datetime
import base64
import binascii
import argparse
import signal
import inspect
import traceback
import random
import platform
import subprocess
import math
import string
import json
import ast
import shutil

# Keep track of the script name for log messages
SCRIPT_NAME = os.path.basename(__file__)

# Initialize socket state
secure_active = False

# Intialize timestamp flag
timestamp_flag = False

# Make sure you are running python version 2.7.9 or newer
# Needed for DTLS 1.2 support
if sys.version_info < (2, 7, 9):
    print('{}: Need python version 2.7.9 or greater'.format(SCRIPT_NAME,))
    print('[COMPLETED] Exit status = 1')
    sys.stdout.flush()
    exit(1)

### CONSTANTS
MISSING     = '__MISSING__'
DEFAULT     = '__DEFAULT__'
ERROR       = '__ERROR__'
EMPTY       = '__EMPTY__'
DEFAULT_NUM = -1
MISSING_NUM = -2
NONE        = -1
PASS        = 0
FAIL        = 1
NOT_RUN     = -1
YES         = 1
NO          = 0

# Following used to determine which side started the message handshake
CLIENT      = 2
SERVER      = 3

# Operating System
PLATFORM    = platform.system()
PID         = str(os.getpid())

### FIXME: Taken from pydtls/dtls/sslconnection.py
PROTOCOL_DTLS     = 259
PROTOCOL_DTLSv1   = 256
PROTOCOL_DTLSv1_2 = 258

### TIMERS
SOCKET_TIMEOUT     = 5
CONNECTION_TIMEOUT = 30
READ_TIMEOUT       = 10
#FIXME: Update with the actual EST client timeout value
COAP_ACK_TIMEOUT   = 3

### COUNTERS
ERROR_LIMIT = 5

# Split out the command line
parser = argparse.ArgumentParser()

parser.add_argument('--test', action='store', dest='test_case', required=True,
                    default='NONE', help='Test Case to execute')
parser.add_argument('--cacert', action='store', dest='cacert_file',
                    required=True, default=None,
                    help='CA Certificate file name')
parser.add_argument('--cert', action='store', dest='cert_file',
                    default=None, help='Certificate file name')
parser.add_argument('--key', action='store', dest='key_file',
                    default=None, help='Private Key file name')
parser.add_argument('--csr', action='store', dest='csr_file',
                    default=None, help='CSR file name')
parser.add_argument('--noverify', action='store_false', dest='cert_verify',
                    default=True,
                    help='Do NOT verify enroll/re-enroll payload cert')
parser.add_argument('--server', action='store', dest='hostname',
                    default='', help='Name/IP of the EST server')
parser.add_argument('--port', action='store', dest='socket', type=int,
                    default=5684, help='Socket # of the EST server')
parser.add_argument('--inet', action='store', dest='inet', type=int,
                    default=4, help='IP stack version to communicate over')
parser.add_argument('--block_size', action='store', dest='block', type=int,
                    default=2048, help='Payload Block Size (16-2048) [2^n]')
parser.add_argument('--protocol', action='store', dest='protocol',
                    default='1.2', help='DTLS Protocol (1 or 1.2 or None)')
parser.add_argument('--cipher', action='store', dest='cipher',
                    default=None, help='SSL Cipher')
parser.add_argument('--early', action='store_true', dest='early_neg',
                    default=False, help='Client BLOCK2 early negotiation')
parser.add_argument('--base64', action='store_true', dest='base64',
                    default=False, help='Send/Receive payload base64 encoded')
parser.add_argument('--noclose', action='store_false', dest='close_alert',
                    default=True,
                    help='Do NOT send close/notify alert when closing DTLS')
parser.add_argument('--value', action='store', dest='value', type=int,
                    default=None, help='Test Case specific value to pass in')
parser.add_argument('--string', action='store', dest='string',
                    default=None, help='Test Case specific string to pass in')
parser.add_argument('--count', action='store', dest='iterations', type=int,
                    default=1, help='(For loop tests) Number of iterations')
parser.add_argument('--duration', action='store', dest='duration', type=int,
                    default=604800, help='(For loop tests) Max execution time')
parser.add_argument('--debug', action='store_true', dest='debug1',
                    default=False, help='Print out additional output')
parser.add_argument('--DEBUG', action='store_true', dest='debug2',
                    default=False,
                    help='Keep output files & Print out additional output')
parser.add_argument('--timestamp', action='store_true', dest='timestamp',
                    default=False, help='Print times of start/stop of callflow')
parser.add_argument('--out', action='store', dest='outcert',
                    default=None, help='Name of output certificate file')
parser.add_argument('--output_dir', action='store', dest='tmp_dir',
                    default=None,
                    help='Directory for generated pem/pkcs7/key files')
#FIXME: BRSKI not supported yet
parser.add_argument('--masa-cert', action='store', dest='masa_cert_file',
                    default=None, help='MASA Certificate file name')
parser.add_argument('--masa-cacert', action='store', dest='masa_cacert_file',
                    default=None, help='MASA CA Certificate file name')

try:
    arg = parser.parse_args()
except:
    # Problems parsing the command line
    print('[COMPLETED] Exit status = 1')
    sys.stdout.flush()
    exit(1)

# Build out default IP address
if arg.hostname == '':
    if arg.inet == 6:
        arg.hostname = '::1'
    else:
        arg.hostname = '127.0.0.1'

# Build out debug level
arg.debug = 0
if arg.debug2:
    arg.debug = 2
elif arg.debug1:
    arg.debug = 1

### GENERAL FUNCTIONS

#-----------------------------------------------------------------------
# Method:
#   exit_program
# Description:
#   Cleanup & exit program
# Input:
#   status = (Optional) Exit status to return to the shell
# Output:
#   None
#-----------------------------------------------------------------------
def exit_program(status=FAIL):
    print('[COMPLETED] Exit status = {}'.format(status,))
    sys.stdout.flush()
    exit(status)

#-----------------------------------------------------------------------
# Method:
#   fname
# Description:
#   Print out the function name (typically for log messages)
# Input:
#   level = (Optional) Which function on the stack to return
# Output:
#   <string> - Function name
#-----------------------------------------------------------------------
def fname(level=1):
   return inspect.stack()[level][3]

#-----------------------------------------------------------------------
# Method:
#   print_log
# Description:
#   Print out log messages in a specific format
# Input:
#    header = Short string typically to identify log level
#      data = (Optional) Log message text
#     title = (Optional) Which function was this log message called
# Output:
#   Nothing
#-----------------------------------------------------------------------
def print_log(header, data='', title=''):
    if title == '':
        title = fname(2)
    if title == '<module>':
        title = SCRIPT_NAME
    print('{}: [{}] {}'.format(title, header, data,))

#-----------------------------------------------------------------------
# Method:
#   print_debug
# Description:
#   Print out debug log messages
# Input:
#   string = Log message text
# Output:
#   Nothing
#-----------------------------------------------------------------------
# Print out a debug message in a specific format
def print_debug(string):
    if arg.debug:
        print_log('DEBUG', string, title=fname(2))

#-----------------------------------------------------------------------
# Method:
#   signal_handler
# Description:
#   Used to handle any unusual termination of this program and return failure
# Input:
#   signal = Signal type
#    frame = Frame
# Output:
#   Nothing
#-----------------------------------------------------------------------
def signal_handler(signal, frame):

    global exit_status

    print_str = "Program terminated with signal '{}'".format(signal)
    print_log('FATAL', print_str)
    exit_program(exit_status)

#-----------------------------------------------------------------------
# Method:
#   signal_handler_pass
# Description:
#   Used to handle any unusual termination of this program and return success
# Input:
#   signal = Signal type
#    frame = Frame
# Output:
#   Nothing
#-----------------------------------------------------------------------
def signal_handler_pass(signal, frame):
    global INTERRUPT_FLAG

    print_str = "Program terminated with signal '{}'".format(signal)
    print_log('NOTIFY', print_str)
    INTERRUPT_FLAG = True

#-----------------------------------------------------------------------
# Method:
#   case
# Description:
#   Compare test case passed in with the current one
# Input:
#   test_case = Test case name
# Output:
#   True/False
#-----------------------------------------------------------------------
def case(test_case):
    return arg.test_case == test_case

#-----------------------------------------------------------------------
# Method:
#   case_name
# Description:
#   Determine the full name of the test to be performed
# Input:
#   None
# Output:
#   <string> - Test case name
#-----------------------------------------------------------------------
def case_name():

    # Test case name passed in
    test_case = arg.test_case

    # Make sure the test case is present
    if test_case not in globals():
        print_str = "Testcase '{}' is NOT found".format(test_case,)
        print_log('ERROR', print_str, '<module>')
        exit_program(FAIL)

    # Make sure the test case is a function
    global_type = str(globals()[test_case])
    if not global_type.startswith('<function '):
        print_str = "Testcase '{}' is NOT valid".format(test_case,)
        print_log('ERROR', print_str, '<module>')
        exit_program(FAIL)

    # Valid test case
    return test_case

#-----------------------------------------------------------------------
# Method:
#   test_start
# Description:
#   Common startup routine for each test case
# Input:
#   additional_info = (Optional) String with more test description information
#             title = (Optional) String with the title of the test case
# Output:
#   Nothing
#-----------------------------------------------------------------------
def test_start(additional_info='', title=''):

    # Testcase name
    global testcase_name
    if title == '':
        title = testcase_name

    # Print out log message
    print_log('START', data=additional_info, title=title,)

    # Initialize EST/CoAP parameters
    est.init()

#-----------------------------------------------------------------------
# Method:
#   timeout_check
# Description:
#   Determine if the timeout occurred with the expected period
# Input:
#         start_time = Time to compare against
#   expected_timeout = Expected timeout value
#      threshold_pct = (Optional) Percentage off the expected timeout
#                                 value to still pass
# Output:
#   True/False
#-----------------------------------------------------------------------
def timeout_check(start_time, expected_timeout, threshold_pct=20.0):

    # Verify the threshhold parameter
    try:
        threshold_pct = float(threshold_pct)
    except:
        print_str = "Invalid 'threshold_pct' value '{}'"
        print_log('WARNING', print_str.format(threshold_pct))
        threshold_pct = 20.0
    if (threshold_pct < 0.0) or (threshold_pct > 100.0):
        print_str = "Out-of-Range 'threshold_pct' value '{}'"
        print_log('WARNING', print_str.format(threshold_pct))
        threshold_pct = 20.0

    # Calculate the minimum/maximum allowable values
    minimum_time = expected_timeout * (1.00 - (threshold_pct/100))
    maximum_time = expected_timeout * (1.00 + (threshold_pct/100))

    # Calculate the elapsed time
    elapsed_time = time.time() - start_time

    # Did the timeout occur when it was suppose to
    if (elapsed_time > maximum_time) or (elapsed_time < minimum_time):
        print_str = "Out of range, expected '{}', actual '{:.2f}' seconds"
        print_log('ERROR', print_str.format(expected_timeout, elapsed_time,))
        return False

    # Test passed
    print_str = "In range, expected '{}', actual '{:.2f}' seconds"
    print_debug(print_str.format(expected_timeout, elapsed_time,))
    return True

#-----------------------------------------------------------------------
# Method:
#   temp_dir
# Description:
#   Build out a temporary directory
# Input:
#   platform = Which operating system is this program running under
# Output:
#   <string> - Directory name
#-----------------------------------------------------------------------
def temp_dir(platform):

    # Linux platform
    tempdir = '/tmp/'
    if arg.tmp_dir is not None:
        tempdir = arg.tmp_dir.rstrip('/')
        tempdir += '/'

    # Windows platform
    if platform == 'Windows':
        try:
            tempdir = os.environ['TEMP'] + '\\'
        except KeyError:
            tempdir = '.\\'

    # Return the directory
    return tempdir

#-----------------------------------------------------------------------
# Method:
#   delete_file
# Description:
#   Delete file
# Input:
#    filename = File to delete
#   filenames = (Optional) List of files to delete
# Output:
#   True/False
# Note:
#   If filename argument is set, then filenames argument is ignored
#-----------------------------------------------------------------------
def delete_file(filename=None, filenames=None):
    # Initialize variables
    results = True

    # Single file or a list of files
    if filename is not None:
        filenames = [filename,]

    # Loop through each file
    for filename in filenames:
        if os.path.isfile(filename):
            try:
                os.remove(filename)
            except OSError:
                results = False

    # Return results
    return results

#-----------------------------------------------------------------------
# Method:
#   write_file
# Description:
#   Write contents to a file
# Input:
#   filename = Output filename
#    content = Text to write
#       mode = (Optional) Write Mode (Default is 'w')
# Output:
#   True/False
#-----------------------------------------------------------------------
def write_file(filename, content, mode='w'):

    # Remove stale file
    delete_file(filename)

    # Write the content
    try:
        file = open(filename, mode)
        file.write(content)
        if not mode.endswith('b'):
            file.write('\n')
        file.close()
    except IOError:
        print_log('ERROR', sys.exc_info()[1])
        return False

    # Return success
    return True

#-----------------------------------------------------------------------
# Method:
#   adjust_string
# Description:
#   Add/Truncate a string
# Input:
#       string = Text string
#   adjustment = (Optional) Add/Truncation # of bytes from the message
# Output:
#   <string> - Updated string
#-----------------------------------------------------------------------
def adjust_string(string, adjustment=0):

    # Add to the return string
    if adjustment > 0:
       add_string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
       try:
           # Loop until string is long enough
           while len(add_string) < adjustment:
               add_string += add_string
           add_string = add_string[:adjustment]
           string += add_string
       except TypeError:
           pass

    # Truncate the return string
    if adjustment < 0:
        try:
            string = string[:adjustment]
        except TypeError:
            pass

    # Return the updated string
    return string

#-----------------------------------------------------------------------
# Method:
#   print_string
# Description:
#   Return a version of the string that can be printed to standard output
# Input:
#   text = Text string
# Output:
#   <string> - Printable string
#-----------------------------------------------------------------------
def print_string(text):

    # Initialize variables
    return_str = ''
    valid_count = 0
    invalid_count = 0

    # Loop through each character
    for char in text:
        # Check if character is printable
        if char in string.printable:
            return_str += char
            valid_count += 1
        else:
            return_str += '.'
            invalid_count += 1

    # Return printable string
    if valid_count >= invalid_count:
        return return_str
    else:
        return ''

#-----------------------------------------------------------------------
# Method:
#   fold_string
# Description:
#   Return a version of the string that add line feeds for readability
# Input:
#     text = Text string
#   length = (Optional) Number of characters per line
#   spacer = (Optional) Number of spaces before each line
#    strip = (Optional) Get rid of spaces before/after string
# Output:
#   <string> - Printable string
#-----------------------------------------------------------------------
def fold_string(text, length=76, spacer=0, strip=True):

    # Initialize variables
    index = 0
    length_text = len(text)
    spacer_str = ' ' * spacer
    return_str = '' + spacer_str

    # Loop through until all characters have been folded
    while index < length_text:
        return_str += text[index:index+length]
        index += length
        if index < length_text:
           return_str += '\n' + spacer_str

    # Return string
    if strip:
        return_str = return_str.strip()
    return return_str

#-----------------------------------------------------------------------
# Method:
#   text_string
# Description:
#   Build a string of a specific length
# Input:
#   length = String Length
#     type = (Optional) What characters to put in string
#                       (lowercase/hexstring/random)
# Output:
#   <string> - Text string
#-----------------------------------------------------------------------
def text_string(length, type='lowercase'):

    # Lowercase alphabet
    if type == 'lowercase':
        return ''.join(map(chr, (ord('a')+(y%26) for y in range(length))))

    # Hex character ASCII
    if type == 'hexstring':
        num_chars = int((length + 1) / 2)
        text_str = ''.join('{:02x}'.format(y%256) for y in range(num_chars))
        return text_str[:length]

    # Random bytes
    if type == 'random':
        text_str = \
          ''.join('{:c}'.format(random.randint(0, 255)) for _ in range(length))
        return text_str

    # Generic single character string
    return 'A' * length

#-----------------------------------------------------------------------
# Method:
#   unsigned_max
# Description:
#   Return the largest integer that can fit into the bytes requested
# Input:
#   bytes = Number of bytes width
# Output:
#   <integer>
#-----------------------------------------------------------------------
def unsigned_max(bytes=2):

    # Calculate the maximum value
    return (1 << (bytes * 8)) - 1

#-----------------------------------------------------------------------
# Method:
#   int2string
# Description:
#   Convert an integer into a byte array string
# Input:
#   integer = Number to convert
#     width = (Optional) Length of the string to return
# Output:
#   <string>
#-----------------------------------------------------------------------
def int2string(integer, width=DEFAULT):

    # Initialize return string
    return_string = ''

    # Loop through until all the bytes are converted
    while integer:
        return_string = chr(integer % 256) + return_string
        integer = integer / 256

    # Does the length need to be adjusted
    if width == DEFAULT:
        width = len(return_string)
    for _ in range(len(return_string), width):
        return_string = chr(0) + return_string

    # Return string
    return return_string

#-----------------------------------------------------------------------
# Method:
#   pkcs7_unsign
# Description:
#   Unsign/verify the pkcs7 signed text passed in
# Input:
#        text = Payload to be signed
#   cert_file = Certificate to verify the text
#     ca_file = CA certificate to verify the text
# Output:
#        text - unsigned data
#-----------------------------------------------------------------------
def pkcs7_unsign(text, cert_file, ca_file, format='text'):

    # Decode the text
    if format == 'base64':
        try:
            text = base64.b64decode(text)
        except:
            print_log('ERROR', 'Problems base64 decoding text provided')
            return EMPTY

    # Build out the temporary bin/text filenames
    out_file = temp_dir(PLATFORM) + 'pkcs7unsigned_' + PID + '.txt'
    in_file = temp_dir(PLATFORM) + 'pkcs7signed_' + PID + '.bin'
    delete_file(filenames=[out_file, in_file,])

    # Store the payload
    try:
        file = open(in_file, 'w')
        file.write(text)
        file.close()
    except:
        print_log('ERROR', "Problems writing file '{}'".format(in_file))
        return EMPTY

    if arg.debug:
        print_log('DEBUG', print_string(text), fname(),)

    # Need to unsign/verify the payload
    command = ['openssl', 'smime', '-verify', '-inform', 'DER', '-in', in_file,
               '-out', out_file, '-CAfile', ca_file, '-signer', cert_file]
    try:
        output = subprocess.check_output(command)
    except:
        print_log('ERROR', "Problems executing '{}'".format(" ".join(command)))
        traceback.print_exc()
        delete_file(filenames=[in_file, out_file,])
        return EMPTY

    # Make sure openssl command was successful
    if not os.path.isfile(out_file):
        print_log('ERROR', 'OpenSSL command was unsuccessful', fname(),)
        delete_file(filenames=[in_file, out_file,])
        return EMPTY

    # Read in the unsigned data
    try:
        with open(out_file, mode='rb') as file:
            text = file.read()
    except:
        print_log('ERROR', "Problems reading file '{}'".format(out_file))
        text = EMPTY

    # Remove temp files
    delete_file(filenames=[out_file, in_file,])

    return text


### UDP class

class Udp:
    #-----------------------------------------------------------------------
    # Variables:
    #   message = Incoming UDP message
    #-----------------------------------------------------------------------
    message = ''

    #-----------------------------------------------------------------------
    # Initialize global class parameters
    #-----------------------------------------------------------------------
    def __init__(self):
        self.message = ''

    #-----------------------------------------------------------------------
    # Method:
    #   server_parameters
    # Description:
    #   Setup the UDP server parameters
    # Input:
    #   inet - IPv4/IPv6 connection
    # Output:
    #   Server parameters tuple
    #-----------------------------------------------------------------------
    @staticmethod
    def server_parameters(inet):
        if inet == 6:
            return arg.hostname, arg.socket, 0, 0,
        return arg.hostname, arg.socket,

    #-----------------------------------------------------------------------
    # Method:
    #   socket_objects
    # Description:
    #   Create UDP socket objects for connections
    # Input:
    #      inet - IPv4/IPv6 connection
    #   sockets - Number of socket objects to create
    # Output:
    #   List of socket objects
    #-----------------------------------------------------------------------
    @staticmethod
    def socket_objects(inet, sockets=1):

        # Initialize variables
        return_list = []

        # Loop through number of iterations
        for _ in range(sockets):
            # Create a socket object
            if inet == 6:
                object = socket(AF_INET6, SOCK_DGRAM, 0)
            else:
                object = socket(AF_INET, SOCK_DGRAM)

            # Append a socket object list
            return_list.append(object)

        # Return results
        return return_list

    #-----------------------------------------------------------------------
    # Method:
    #   setup
    # Description:
    #   Setup the UDP socket
    # Input:
    #   socket_params - UDP tuple to open socket
    #   socket_object - Socket object to connect to the server with
    # Output:
    #   Nothing
    #-----------------------------------------------------------------------
    @staticmethod
    def setup(socket_params, socket_object):

        # Initialize variables
        global LOOP_TEST

        # Setup UDP parameters to the socket
        try:
            socket_object.connect(socket_params)
        except:
            print_log('CONNECT ERROR', sys.exc_info()[1])
            if not LOOP_TEST:
                exit_program(FAIL)
            return False

        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   read
    # Description:
    #   Read incoming UDP message from the socket
    # Input:
    #   timeout = (Optional) Time to wait for a message to arrive
    # Output:
    #   True/False/None
    #   (Message is stored in Class variable self.message)
    #-----------------------------------------------------------------------
    def read(self, timeout=READ_TIMEOUT):

        # Initialize return message & return code
        self.message = ''
        return_code = True

        # Setup timeout
        client_conn.settimeout(timeout)

        # Wait for the the start of the message
        try:
            message, dont_care = client_conn.recvfrom(4096)
        except:
            error_msg = str(sys.exc_info()[1])
            if re.search('time.*out', error_msg, re.IGNORECASE):
                print_log('WARNING', error_msg)
                return None
            else:
                print_log('ERROR', sys.exc_info()[1])
                return False

        # Print out entire message
        print_log('INFO', 'Message received')
        if arg.debug:
            print_msg = 'Incoming message:\n{}'.format(message.encode('hex'))
            print_log('INFO', print_msg)
            print('===============================')

        # Return code
        if message != '':
            self.message = message
        return return_code

    #-----------------------------------------------------------------------
    # Method:
    #   read_msg
    # Description:
    #   Validate the CoAP message received from the UDP socket
    # Input:
    #       timeout = (Optional) Time to wait for a message to arrive
    #   pass_result = (Optional) Value to return on success
    # Output:
    #   True/False
    #   (Message is stored in Class variable self.message)
    #-----------------------------------------------------------------------
    def read_msg(self, timeout=READ_TIMEOUT, pass_result=True):

        # Determine the return values
        fail_result = False
        log_level = 'ERROR'
        if pass_result is None:
            pass_result = True
            log_level = 'INFO'
        if not pass_result:
            fail_result = True
            log_level = 'INFO'

        # Read in UDP message
        return_code = self.read(timeout)
        if return_code is None:
            pass
        elif return_code:
            return pass_result
        else:
            return fail_result

        # Fail if no message was received
        if self.message == '':
            print_log(log_level, 'No message received')
            return fail_result
        elif not pass_result:
            print_log('ERROR', 'Unexpected message received')

        # Return success
        return pass_result

    #-----------------------------------------------------------------------
    # Method:
    #   write
    # Description:
    #   Send a UDP message across the socket
    # Input:
    #   message = UDP message
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    @staticmethod
    def write(message):

        # Initialize variables
        global timestamp_flag

        # Print out debug message
        if arg.debug:
            print_msg = 'Outgoing message:\n{}'.format(message.encode('hex'))
            print_log('INFO', print_msg)
            print('===============================')

        # Print timestamp
        if (not timestamp_flag) and arg.timestamp:
            print_msg = 'Start timestamp {}'.format(datetime.datetime.now(),)
            print_log('INFO', print_msg, testcase_name)
            timestamp_flag = True

        # Send the message (client_args built out under 'MAIN PROGRAM')
        try:
            client_conn.sendto(message, client_args)
        except:
            print_msg = 'Unexpected write error: {}'.format(sys.exc_info()[0])
            print_log('ERROR', print_msg)
            return False

        # Return success
        print_log('INFO', 'Message sent')
        return True


### DTLS class

class Dtls:
    #-----------------------------------------------------------------------
    # Variables:
    #            message = Incoming CoAP message
    #    sequence_number = Client Hello sequence number field
    #   message_sequence = Client Hello message sequence field
    #        random_time = Client Hello random time field
    #       random_bytes = Client Hello random bytes field
    #            rx_dict = Server Hello Verify request response parsed
    #            tx_dict = Client Hello request parsed
    #         IDLE_STATE = Time before a DTLS handshake connection is IDLE
    #          peer_cert = Server certificate
    #-----------------------------------------------------------------------
    message = ''
    sequence_number = 0
    message_sequence = 0
    random_time = int(time.time())
    random_bytes = text_string(28, 'random')
    tx_dict = {}
    rx_dict = {}
    IDLE_STATE = 35
    peer_cert = ''

    #-----------------------------------------------------------------------
    # Constants:
    #   DTLS read errors
    #-----------------------------------------------------------------------
    PEER_TERMINATED = 6
    TIMEOUT         = 502

    #-----------------------------------------------------------------------
    # Initialize global class parameters
    #-----------------------------------------------------------------------
    def __init__(self):
        self.message = ''

    #-----------------------------------------------------------------------
    # Method:
    #   protocol_version
    # Description:
    #   Determine the DTLS protocol version under test
    # Input:
    #   None
    # Output:
    #   Nothing (arg.protocol is updated with the proper DTLS value)
    #-----------------------------------------------------------------------
    @staticmethod
    def protocol_version():

        # DTLS Protocol
        if arg.protocol == '1':
            arg.protocol = PROTOCOL_DTLSv1
        elif arg.protocol == '1.0':
            arg.protocol = PROTOCOL_DTLSv1
        elif arg.protocol == '1.2':
            arg.protocol = PROTOCOL_DTLSv1_2
        elif re.search('none', arg.protocol, re.IGNORECASE):
            arg.protocol = 0
        elif arg.protocol == '0':
            arg.protocol = 0
        else:
            print_str = "Invalid DTLS protocol '{}'".format(arg.protocol)
            print_log('ARG ERROR', print_str, '<module>')
            exit_program(FAIL)

    #-----------------------------------------------------------------------
    # Method:
    #   read
    # Description:
    #   Read incoming CoAP message from the secure socket
    # Input:
    #   timeout = (Optional) Time to wait for a message to arrive
    # Output:
    #   PASS/FAIL
    #   (Message is stored in Class variable self.message)
    #-----------------------------------------------------------------------
    def read(self, timeout=READ_TIMEOUT):

        # Initialize return message & return code
        self.message = ''
        message = ''
        return_code = PASS

        # Setup timeout
        secure_conn.settimeout(timeout)

        # Wait for the the start of the message
        try:
            buffer = secure_conn.read()
        except ssl.SSLZeroReturnError:
            raise
        except ssl.SSLWantReadError:
            raise
        except ssl.SSLWantWriteError:
            raise
        except ssl.SSLSyscallError:
            raise
        except ssl.SSLEOFError:
            raise
        except ssl.CertificateError:
            raise
        except ssl.SSLError as err:
            return_code = err.errno
            if return_code is None:
                return_code = sys.exc_info()[1][0]
                return return_code
            if return_code == self.TIMEOUT:
                print_log('ERROR', 'Timed out')
                return return_code
            print_log('ERROR', sys.exc_info()[1])
            return return_code

        # Reduce the timeout for subsequent message reads
        secure_conn.settimeout(0.1)

        # Wait for the remainder of the message
        while buffer:
            # Look for additional portions of the message
            message += buffer
            try:
                buffer = secure_conn.read()
            except ssl.SSLZeroReturnError:
                raise
            except ssl.SSLWantReadError:
                raise
            except ssl.SSLWantWriteError:
                raise
            except ssl.SSLSyscallError:
                raise
            except ssl.SSLEOFError:
                raise
            except ssl.CertificateError:
                raise
            except ssl.SSLError as err:
                return_code = err.errno
                if return_code is None:
                    return_code = sys.exc_info()[1][0]
                if return_code == self.PEER_TERMINATED:
                    break
                if return_code == self.TIMEOUT:
                    break
                print_log('ERROR', sys.exc_info()[1])
                return return_code
            except:
                raise

        # Print out entire message
        print_log('INFO', 'Message received')
        if arg.debug:
            print_msg = 'Incoming message:\n{}'.format(message.encode('hex'))
            print_log('INFO', print_msg)
            print('===============================')

        # Return code
        if message != '':
            self.message = message
        return return_code

    #-----------------------------------------------------------------------
    # Method:
    #   read_msg
    # Description:
    #   Validate the CoAP message received from the secure socket
    # Input:
    #           timeout = (Optional) Time to wait for a message to arrive
    #       pass_result = (Optional) Value to return on success
    #   exp_return_code = (Optional) Expected return code
    # Output:
    #   True/False
    #   (Message is stored in Class variable self.message)
    #-----------------------------------------------------------------------
    def read_msg(self, timeout=READ_TIMEOUT, pass_result=True,
                       exp_return_code=-1):

        # Determine the return values
        fail_result = False
        log_level = 'ERROR'
        if not pass_result:
            log_level = 'INFO'
            fail_result = True

        # Read in DTLS message
        return_code = self.read(timeout)
        if return_code == PASS:
            return pass_result
        if return_code == self.TIMEOUT:
            pass  # - Read timeout occurred
        elif return_code == self.PEER_TERMINATED:
            print_log('NOTICE', 'Peer terminated the connection')
        else:
            print_log('WARNING', "Unknown return code '{}'".format(return_code))

        # Check if an error was expected from the server
        if exp_return_code == return_code:
            return pass_result
        if exp_return_code != -1:
            return fail_result

        # Fail if no message was received
        if self.message == '':
            print_log(log_level, 'No message received')
            return fail_result
        elif not pass_result:
            print_log('ERROR', 'Unexpected message received')

        # Return success
        return pass_result

    #-----------------------------------------------------------------------
    # Method:
    #   write
    # Description:
    #   Send a CoAP message across the DTLS connection
    # Input:
    #   message = CoAP message
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    @staticmethod
    def write(message):

        # Initialize variables
        global timestamp_flag

        # Print out debug message
        if arg.debug:
            print_msg = 'Outgoing message:\n{}'.format(message.encode('hex'))
            print_log('INFO', print_msg)
            print('===============================')

        # Print timestamp
        if (not timestamp_flag) and arg.timestamp:
            print_msg = 'Start timestamp {}'.format(datetime.datetime.now(),)
            print_log('INFO', print_msg, testcase_name)
            timestamp_flag = True

        # Send the message
        try:
            secure_conn.write(message)
        except:
            print_msg = 'Unexpected write error: {}'.format(sys.exc_info()[0])
            print_log('ERROR', print_msg)
            return False

        # Return success
        print_log('INFO', 'Message sent')
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   setup
    # Description:
    #   Setup the DTLS and UDP sockets
    # Input:
    #   udp_conn - UDP socket object
    # Output:
    #   Nothing
    #-----------------------------------------------------------------------
    def setup(self, udp_conn):
        # Track the secure/UDP connection
        global secure_conn
        global secure_active

        # Variables to track to run this method and how to return results
        global testcase_name
        global LOOP_TEST
        return_code = True

        # Open DTLS connection
        try:
            secure_conn = ssl.wrap_socket(udp_conn,
                                          server_side=False,
                                          certfile=arg.cert_file,
                                          keyfile=arg.key_file,
                                          ca_certs=arg.cacert_file,
                                          suppress_ragged_eofs=False,
                                          ssl_version=arg.protocol,
                                          ciphers=arg.cipher)
            secure_active = True
            secure_conn.settimeout(60)
            self.peer_cert = secure_conn.getpeercert(True)
        except ssl.SSLError:
            print_log('SSL ERROR', sys.exc_info()[1])
            return_code = False
        except:
            print_log('ERROR', sys.exc_info()[1])
            return_code = False

        # Return results
        if not return_code:
            self.teardown('UDP', udp_conn)
            if not LOOP_TEST:
                exit_program(FAIL)
        return return_code

    #-----------------------------------------------------------------------
    # Method:
    #   teardown
    # Description:
    #   Shutdown the DTLS and UDP sockets
    # Input:
    #   connection = Which socket to close
    #                  'BOTH' will close SSL & UDP
    #                  'SSL' will close SSL
    #                  'UDP' will close just UDP
    #     udp_conn = Client socket object
    #
    # Output:
    #   Nothing
    #-----------------------------------------------------------------------
    @staticmethod
    def teardown(connection, udp_conn):

        # Secure connection
        global secure_conn
        global secure_active

        # SSL connection
        if ((connection == 'BOTH') or (connection == 'SSL')) and \
            (arg.protocol > 0):
            if secure_active:
                secure_active = False
                if arg.close_alert:
                    try:
                        secure_conn.unwrap()
                    except:
                        # Print error log message (except for read timeout)
                        error_msg = str(sys.exc_info()[1])
                        if not error_msg.startswith('502:'):
                            print("Unexpected unwrap error:", error_msg)
                try:
                    secure_conn.shutdown(SHUT_RDWR)
                except:
                    print("Unexpected shutdown error:", sys.exc_info()[0])
                try:
                    secure_conn.close()
                except:
                    pass

        # UDP connection
        if (connection == 'BOTH') or (connection == 'UDP'):
            try:
                udp_conn.shutdown(SHUT_RDWR)
            except:
                print("Unexpected error:", sys.exc_info()[0])
            try:
                udp_conn.close()
            except:
                pass

        # Log message
        protocol = 'DTLS'
        if connection == 'UDP':
            protocol = 'UDP'
        print_log('INFO', '{} connection closed'.format(protocol))

    #-----------------------------------------------------------------------
    # Method:
    #   parse_msg
    # Description:
    #   Parse the DTLS payload
    # Input:
    #        text = Byte string
    #   direction = (Optional) 'tx' (outgoing) or 'rx' (incoming)
    #               Default is 'rx'
    # Output:
    #   True/False (All fields are stored either in the dtls_obj.rx_dict
    #              (incoming) or dtls_obj.tx_dict (outgoing) dictionary)
    #-----------------------------------------------------------------------
    def parse_msg(self, text, direction='rx'):

        # Initialize dictionaries
        msg_dict = {}
        if direction == 'rx':
            self.rx_dict = {}
        else:
            self.tx_dict = {}

        # No message received
        if text == '':
            return False

        # Print debug header
        if arg.debug:
            if direction == 'rx':
                print('Incoming:')
            else:
                print('Outgoing:')

        # Don't crash, if there is a problem parsing
        try:
            # Pull out the Content Type (1 byte)
            value = ord(text[0])
            msg_dict['Content Type'] = value
            print_debug('Content Type: 0x{:1x} ({})'.format(value, value,))

            # Version (2 bytes)
            value = text[1:3]
            msg_dict['Version'] = value
            print_debug('     Version: 0x{}'.format(value.encode('hex')))

            # Epoch (2 bytes)
            value = int(text[3:5].encode('hex'), 16)
            msg_dict['Epoch'] = value
            print_debug('       Epoch: 0x{:04x} ({})'.format(value, value,))

            # Sequence Number (6 bytes)
            value = int(text[5:11].encode('hex'), 16)
            msg_dict['Sequence Number'] = value
            print_debug('  Sequence #: 0x{:012x} ({})'.format(value, value,))

            # Length (2 bytes)
            value = int(text[11:13].encode('hex'), 16)
            msg_dict['Length'] = value
            print_debug('      Length: 0x{:04x} ({})'.format(value, value,))

            # Handshake Type (1 byte)
            value = ord(text[13])
            msg_dict['Handshake Type'] = value
            print_str = 'Handshake ==> Type: 0x{:02x} ({})'
            print_debug(print_str.format(value, value,))

            # Handshake Length (3 bytes)
            value = int(text[14:17].encode('hex'), 16)
            msg_dict['Handshake Length'] = value
            print_str = '            Length: 0x{:06x} ({})'
            print_debug(print_str.format(value, value,))

            # Message Sequence (2 bytes)
            value = int(text[17:19].encode('hex'), 16)
            msg_dict['Message Sequence'] = value
            print_str = '      Msg Sequence: 0x{:04x} ({})'
            print_debug(print_str.format(value, value,))

            # Fragment Offset (3 bytes)
            value = int(text[19:22].encode('hex'), 16)
            msg_dict['Fragment Offset'] = value
            print_str = '       Frag Offset: 0x{:06x} ({})'
            print_debug(print_str.format(value, value,))

            # Fragment Length (3 bytes)
            value = int(text[22:25].encode('hex'), 16)
            msg_dict['Fragment Length'] = value
            print_str = '       Frag Length: 0x{:06x} ({})'
            print_debug(print_str.format(value, value,))

            # Handshake Version (2 bytes)
            value = text[25:27]
            msg_dict['Handshake Version'] = value
            print_debug('           Version: 0x{}'.format(value.encode('hex')))

            ### Parse DTLS message specific portions
            # Client Hello
            if msg_dict['Handshake Type'] == 1:
                # Random Bytes (32 bytes)
                value = text[27:59]
                msg_dict['Random'] = value
                print_str = '            Random: 0x{}'
                value_str = fold_string(value.encode('hex'), 32, 41)
                print_debug(print_str.format(value_str))

                # Variable length fields
                index = 59

                # Session ID (Length = 1 byte)
                length = ord(text[index])
                msg_dict['Session ID Length'] = length
                print_str = '    Session ID Len: 0x{:02x} ({})'
                print_debug(print_str.format(length, length,))
                index += 1
                value = text[index:index+length]
                msg_dict['Session ID'] = value
                if value != '':
                    print_str = '        Session ID: 0x{}'
                    value_str = fold_string(value.encode('hex'), 32, 41)
                    print_debug(print_str.format(value_str))
                index += length

                # Cookie (Length = 1 byte)
                length = ord(text[index])
                msg_dict['Cookie Length'] = length
                print_str = '        Cookie Len: 0x{:02x} ({})'
                print_debug(print_str.format(length, length,))
                index += 1
                value = text[index:index+length]
                msg_dict['Cookie'] = value
                if value != '':
                    print_str = '            Cookie: 0x{}'
                    value_str = fold_string(value.encode('hex'), 32, 41)
                    print_debug(print_str.format(value_str))
                index += length

                # Ciphers (Length = 2 byte)
                length = int(text[index:index+2].encode('hex'), 16)
                msg_dict['Ciphers Length'] = length
                print_str = '       Ciphers Len: 0x{:02x} ({})'
                print_debug(print_str.format(length, length,))
                index += 2
                value = text[index:index+length]
                msg_dict['Ciphers'] = value
                if value != '':
                    print_str = '           Ciphers: 0x{}'
                    value_str = fold_string(value.encode('hex'), 32, 41)
                    print_debug(print_str.format(value_str))
                index += length

                # Compression Methods (Length = 1 byte)
                length = ord(text[index])
                msg_dict['Compression Methods Length'] = length
                print_str = 'Compress Methd Len: 0x{:02x} ({})'
                print_debug(print_str.format(length, length,))
                index += 1
                value = text[index:index+length]
                msg_dict['Compression Methods'] = value
                if value != '':
                    print_str = '  Compress Methods: 0x{}'
                    print_debug(print_str.format(value.encode('hex')))
                index += length

                # Extensions (Length = 2 byte)
                length = int(text[index:index+2].encode('hex'), 16)
                msg_dict['Extensions Length'] = length
                print_str = '    Extensions Len: 0x{:02x} ({})'
                print_debug(print_str.format(length, length,))
                index += 2
                # FIXME: If needed, parse out each extension
                value = text[index:index+length]
                msg_dict['Extensions'] = value
                if value != '':
                    print_str = '        Extensions: 0x{}'
                    value_str = fold_string(value.encode('hex'), 32, 41)
                    print_debug(print_str.format(value_str))
                index += length

            # Hello Verify Request
            if msg_dict['Handshake Type'] == 3:

                # Variable length fields
                index = 27

                # Cookie (Length = 1 byte)
                length = ord(text[index])
                msg_dict['Cookie Length'] = length
                print_str = '        Cookie Len: 0x{:02x} ({})'
                print_debug(print_str.format(length, length,))
                index += 1
                value = text[index:index+length]
                msg_dict['Cookie'] = value
                if value != '':
                    print_str = '            Cookie: 0x{}'
                    value_str = fold_string(value.encode('hex'), 32, 41)
                    print_debug(print_str.format(value_str))
                index += length

        except:
            # Error parsing message, get rid of any partial information stored
            print_log('ERROR', sys.exc_info()[1])
            return False

        # Copy results to the correct dictionary
        if direction == 'rx':
            for element in msg_dict:
                self.rx_dict[element] = msg_dict[element]
        else:
            for element in msg_dict:
                self.tx_dict[element] = msg_dict[element]

        # Return success
        if arg.debug:
            print('===============================')
        return True


### CoAP class

class CoAP:

    #-----------------------------------------------------------------------
    # Variables:
    #     rx_dict = Dictionary storing incoming CoAP message fields/values
    #     tx_dict = Dictionary storing outgoing CoAP message fields/values
    #-----------------------------------------------------------------------
    rx_dict = {}
    tx_dict = {}

    #-----------------------------------------------------------------------
    # Initialize global class parameters
    #-----------------------------------------------------------------------
    def __init__(self):
        self.rx_dict = {}
        self.tx_dict = {}

    #-----------------------------------------------------------------------
    # Constants:
    #   Timeout (in seconds)
    #   Retry Limit (integer)
    #   Response Delay (number - greater than or equal to zero)
    #-----------------------------------------------------------------------
    TIMEOUT = 3
    RETRY_LIMIT = 0
    RESPONSE_DELAY = 0
    TRANSMIT_DELAY = 0
    MTU = 1152
    IDLE_STATE = 10
    STALE_STATE = 300

    #-----------------------------------------------------------------------
    # Constants:
    #   Version (2 bits)
    #-----------------------------------------------------------------------
    VERSION = 1

    #-----------------------------------------------------------------------
    # Constants:
    #   Method Codes (1 byte)
    #-----------------------------------------------------------------------
    GET         = 1
    POST        = 2
    PUT         = 3
    DELETE      = 4
    METHOD_CODE = POST  # - Default value

    #-----------------------------------------------------------------------
    # Constants:
    #   Response Codes (1 byte)
    #   Upper 3 bits (class), lower 5 bits (detail)
    #-----------------------------------------------------------------------
    EMPTY_MSG                  = 0x00
    CREATED                    = 0x41
    DELETED                    = 0x42
    VALID                      = 0x43
    CHANGED                    = 0x44
    CONTENT                    = 0x45
    CONTINUE                   = 0x5F
    BAD_REQ                    = 0x80
    UNAUTHORIZED               = 0x81
    BAD_OPTION                 = 0x82
    FORBIDDEN                  = 0x83
    NOT_FOUND                  = 0x84
    METHOD_NOT_ALLOWED         = 0x85
    NOT_ACCEPTABLE             = 0x86
    REQ_ENTITY_INCOMPLETE      = 0x88
    PRECONDITION_FAILED        = 0x8C
    REQ_ENTITY_TOO_LARGE       = 0x8D
    UNSUPPORTED_CONTENT_FORMAT = 0x8F
    INTERNAL_SERVER_ERROR      = 0xA0
    NOT_IMPLEMENTED            = 0xA1
    BAD_GATEWAY                = 0xA2
    SERVICE_UNAVAILABLE        = 0xA3
    GATEWAY_TIMEOUT            = 0xA4
    PROXYING_NOT_SUPPORTED     = 0xA5

    #-----------------------------------------------------------------------
    # Dictionary:
    #   code_dict
    # Description:
    #   Value/name translation of the CoAP code field
    # Note:
    #   UNKNOWN value is for unexpected/unsupported values
    #-----------------------------------------------------------------------
    code_dict = {}
    for code in range(0, 256):
        code_dict[code] = 'UNKNOWN'
    code_dict[GET]    = 'GET'
    code_dict[POST]   = 'POST'
    code_dict[PUT]    = 'PUT'
    code_dict[DELETE] = 'DELETE'
    code_dict[0x00] = 'EMPTY MESSAGE'
    code_dict[0x41] = 'CREATED'
    code_dict[0x42] = 'DELETED'
    code_dict[0x43] = 'VALID'
    code_dict[0x44] = 'CHANGED'
    code_dict[0x45] = 'CONTENT'
    code_dict[0x5F] = 'CONTINUE'
    code_dict[0x80] = 'BAD REQUEST'
    code_dict[0x81] = 'UNAUTHORIZED'
    code_dict[0x82] = 'BAD OPTION'
    code_dict[0x83] = 'FORBIDDEN'
    code_dict[0x84] = 'NOT FOUND'
    code_dict[0x85] = 'METHOD NOT ALLOWED'
    code_dict[0x86] = 'NOT ACCEPTABLE'
    code_dict[0x88] = 'REQUEST ENTITY INCOMPLETE'
    code_dict[0x8C] = 'PRECONDITION FAILED'
    code_dict[0x8D] = 'REQUEST ENTITY TOO LARGE'
    code_dict[0x8F] = 'UNSUPPORTED CONTENT FORMAT'
    code_dict[0xA0] = 'INTERNAL SERVER ERROR'
    code_dict[0xA1] = 'NOT IMPLEMENTED'
    code_dict[0xA2] = 'BAD GATEWAY'
    code_dict[0xA3] = 'SERVICE UNAVAILABLE'
    code_dict[0xA4] = 'GATEWAY TIMEOUT'
    code_dict[0xA5] = 'PROXYING NOT SUPPORTED'
    code_dict['GET']                        = GET
    code_dict['POST']                       = POST
    code_dict['PUT']                        = PUT
    code_dict['DELETE']                     = DELETE
    code_dict['EMPTY MESSAGE']              = EMPTY_MSG
    code_dict['CREATED']                    = CREATED
    code_dict['DELETED']                    = DELETED
    code_dict['VALID']                      = VALID
    code_dict['CHANGED']                    = CHANGED
    code_dict['CONTENT']                    = CONTENT
    code_dict['CONTINUE']                   = CONTINUE
    code_dict['BAD REQUEST']                = BAD_REQ
    code_dict['UNAUTHORIZED']               = UNAUTHORIZED
    code_dict['BAD OPTION']                 = BAD_OPTION
    code_dict['FORBIDDEN']                  = FORBIDDEN
    code_dict['NOT FOUND']                  = NOT_FOUND
    code_dict['METHOD NOT ALLOWED']         = METHOD_NOT_ALLOWED
    code_dict['NOT ACCEPTABLE']             = NOT_ACCEPTABLE
    code_dict['REQUEST ENTITY INCOMPLETE']  = REQ_ENTITY_INCOMPLETE
    code_dict['PRECONDITION FAILED']        = PRECONDITION_FAILED
    code_dict['REQUEST ENTITY TOO LARGE']   = REQ_ENTITY_TOO_LARGE
    code_dict['UNSUPPORTED CONTENT FORMAT'] = UNSUPPORTED_CONTENT_FORMAT
    code_dict['INTERNAL SERVER ERROR']      = INTERNAL_SERVER_ERROR
    code_dict['NOT IMPLEMENTED']            = NOT_IMPLEMENTED
    code_dict['BAD GATEWAY']                = BAD_GATEWAY
    code_dict['SERVICE UNAVAILABLE']        = SERVICE_UNAVAILABLE
    code_dict['GATEWAY TIMEOUT']            = GATEWAY_TIMEOUT
    code_dict['PROXYING NOT SUPPORTED']     = PROXYING_NOT_SUPPORTED

    #-----------------------------------------------------------------------
    # Constants:
    #   Transaction Type values (2 bits)
    #-----------------------------------------------------------------------
    CONFIRM          = 0
    NON_CONFIRM      = 1
    ACK              = 2
    RESET            = 3
    TRANSACTION_TYPE = CONFIRM  # - Default value

    #-----------------------------------------------------------------------
    # Constants:
    #   Token fields
    #-----------------------------------------------------------------------
    TOKEN = ''
    TOKEN_LENGTH = DEFAULT_NUM

    #-----------------------------------------------------------------------
    # Dictionary:
    #   transaction_dict
    # Description:
    #   Name/value & value/name translation of the CoAP transaction types
    # Note:
    #   UNKNOWN value is for testing purposes only
    #-----------------------------------------------------------------------
    transaction_dict = {
        'CONFIRM'     : CONFIRM,
        'NON_CONFIRM' : NON_CONFIRM,
        'ACK'         : ACK,
        'RESET'       : RESET,
        CONFIRM       : 'CONFIRM',
        NON_CONFIRM   : 'NON_CONFIRM',
        ACK           : 'ACK',
        RESET         : 'RESET'
    }

    #-----------------------------------------------------------------------
    # Constants:
    #   Options Values (1 byte)
    #-----------------------------------------------------------------------
    IF_MATCH        = 1
    URI_HOST        = 3
    ETAG            = 4
    IF_NONE_MATCH   = 5
    URI_PORT        = 7
    LOCATION_PATH   = 8
    URI_PATH        = 11
    CONTENT_FORMAT  = 12
    MAX_AGE         = 14
    URI_QUERY       = 15
    ACCEPT          = 17
    LOCATION_QUERY  = 20
    BLOCK2          = 23
    BLOCK1          = 27
    SIZE2           = 28
    PROXY_URI       = 35
    PROXY_SCHEME    = 39
    SIZE1           = 60

    #-----------------------------------------------------------------------
    # Dictionary:
    #   options_dict
    # Description:
    #   Name/value & value/name translation of the CoAP options
    # Note:
    #   UNKNOWN value is for testing purposes only
    #-----------------------------------------------------------------------
    options_dict = {
        'IF_MATCH'       : IF_MATCH,
        'URI_HOST'       : URI_HOST,
        'ETAG'           : ETAG,
        'IF_NONE_MATCH'  : IF_NONE_MATCH,
        'URI_PORT'       : URI_PORT,
        'LOCATION_PATH'  : LOCATION_PATH,
        'URI_PATH'       : URI_PATH,
        'CONTENT_FORMAT' : CONTENT_FORMAT,
        'MAX_AGE'        : MAX_AGE,
        'URI_QUERY'      : URI_QUERY,
        'ACCEPT'         : ACCEPT,
        'LOCATION_QUERY' : LOCATION_QUERY,
        'BLOCK2'         : BLOCK2,
        'BLOCK1'         : BLOCK1,
        'SIZE2'          : SIZE2,
        'PROXY_URI'      : PROXY_URI,
        'PROXY_SCHEME'   : PROXY_SCHEME,
        'SIZE1'          : SIZE1,
        'UNKNOWN'        : 65534,
        IF_MATCH       : 'IF_MATCH',
        URI_HOST       : 'URI_HOST',
        ETAG           : 'ETAG',
        IF_NONE_MATCH  : 'IF_NONE_MATCH',
        URI_PORT       : 'URI_PORT',
        LOCATION_PATH  : 'LOCATION_PATH',
        URI_PATH       : 'URI_PATH',
        CONTENT_FORMAT : 'CONTENT_FORMAT',
        MAX_AGE        : 'MAX_AGE',
        URI_QUERY      : 'URI_QUERY',
        ACCEPT         : 'ACCEPT',
        LOCATION_QUERY : 'LOCATION_QUERY',
        BLOCK2         : 'BLOCK2',
        BLOCK1         : 'BLOCK1',
        SIZE2          : 'SIZE2',
        PROXY_URI      : 'PROXY_URI',
        PROXY_SCHEME   : 'PROXY_SCHEME',
        SIZE1          : 'SIZE1'
    }

    #-----------------------------------------------------------------------
    # Dictionary:
    #   option_format_dict
    # Description:
    #   Used to guide the user on how option values are stored and retrieved
    #-----------------------------------------------------------------------
    option_format_dict = {
        IF_MATCH       : 'opaque',
        URI_HOST       : 'string',
        ETAG           : 'opaque',
        IF_NONE_MATCH  : 'empty',
        URI_PORT       : 'int',
        LOCATION_PATH  : 'string',
        URI_PATH       : 'string',
        CONTENT_FORMAT : 'int',
        MAX_AGE        : 'int',
        URI_QUERY      : 'string',
        ACCEPT         : 'int',
        LOCATION_QUERY : 'string',
        BLOCK2         : 'block',
        BLOCK1         : 'block',
        SIZE2          : 'int',
        PROXY_URI      : 'string',
        PROXY_SCHEME   : 'string',
        SIZE1          : 'int',
    }

    #-----------------------------------------------------------------------
    # Dictionary:
    #   option_max_size
    # Description:
    #   Maximum size (in bytes) of the option
    #-----------------------------------------------------------------------
    option_max_size = {
        IF_MATCH       : 8,
        URI_HOST       : 255,
        ETAG           : 8,
        IF_NONE_MATCH  : 0,
        URI_PORT       : 2,
        LOCATION_PATH  : 255,
        URI_PATH       : 255,
        CONTENT_FORMAT : 2,
        MAX_AGE        : 4,
        URI_QUERY      : 255,
        ACCEPT         : 2,
        LOCATION_QUERY : 255,
        BLOCK2         : 3,
        BLOCK1         : 3,
        SIZE2          : 4,
        PROXY_URI      : 1034,
        PROXY_SCHEME   : 255,
        SIZE1          : 4,
    }

    #-----------------------------------------------------------------------
    # Dictionary:
    #   content_format_dict
    # Description:
    #   Name/value & value/name translation of the CoAP option content-type
    # Note:
    #   UNKNOWN value is for testing purposes only
    #   TBD values are not yet assigned in the RFC
    #-----------------------------------------------------------------------
    ####FIXME: (Wait for RFC to be completed)
    TBD5 = 10005
    content_format_dict = {
        'text/plain'                   : 0,
        'text/xml'                     : 1,
        'text/csv'                     : 2,
        'text/html'                    : 3,
        'image/gif'                    : 21,
        'image/jpeg'                   : 22,
        'image/png'                    : 23,
        'image/tiff'                   : 24,
        'audio/raw'                    : 25,
        'video/raw'                    : 26,
        'application/link-format'      : 40,
        'application/xml'              : 41,
        'application/octet-stream'     : 42,
        'application/rdf+xml'          : 43,
        'application/soap+xml'         : 44,
        'application/atom+xml'         : 45,
        'application/xmpp+xml'         : 46,
        'application/exi'              : 47,
        'application/x-bxml'           : 48,
        'application/fastinfoset'      : 49,
        'application/soap+fastinfoset' : 50,
        'application/json'             : 51,
        'application/multipart-core'   : 62,
        'application/pkcs7-mime+skg'   : 280,
        'application/pkcs7-mime+certs' : 281,
        'application/pkcs7-mime+cmcreq': 282,
        'application/pkcs7-mime+cmcres': 283,
        'application/pkcs8'            : 284,
        'application/csrattrs'         : 285,
        'application/pkcs10'           : 286,
        'application/voucher+cms'      : TBD5,
            0: 'text/plain',
            1: 'text/xml',
            2: 'text/csv',
            3: 'text/html',
           21: 'image/gif',
           22: 'image/jpeg',
           23: 'image/png',
           24: 'image/tiff',
           25: 'audio/raw',
           26: 'video/raw',
           40: 'application/link-format',
           41: 'application/xml',
           42: 'application/octet-stream',
           43: 'application/rdf+xml',
           44: 'application/soap+xml',
           45: 'application/atom+xml',
           46: 'application/xmpp+xml',
           47: 'application/exi',
           48: 'application/x-bxml',
           49: 'application/fastinfoset',
           50: 'application/soap+fastinfoset',
           51: 'application/json',
           62: 'application/multipart-core',
          280: 'application/pkcs7-mime+skg',
          281: 'application/pkcs7-mime+certs',
          282: 'application/pkcs7-mime+cmcreq',
          283: 'application/pkcs7-mime+cmcres',
          284: 'application/pkcs8',
          285: 'application/csrattrs',
          286: 'application/pkcs10',
         TBD5: 'application/voucher+cms',
    }

    #-----------------------------------------------------------------------
    # Variables:
    #   CoAP message fields that may be adjusted during message transmissions
    #-----------------------------------------------------------------------
    version            = VERSION
    transaction_type   = TRANSACTION_TYPE
    token_length       = TOKEN_LENGTH
    method_code        = METHOD_CODE
    message_id         = random.randint(0, 65535)
    message_start_side = CLIENT
    token              = TOKEN
    block1_number      = 0
    block1_mbit        = 0
    block1_size        = DEFAULT_NUM
    block2_number      = 0
    block2_size        = DEFAULT_NUM
    block2_mbit        = None
    retry_limit        = RETRY_LIMIT
    response_delay     = RESPONSE_DELAY
    transmit_delay     = TRANSMIT_DELAY

    #-----------------------------------------------------------------------
    # Variables:
    #      rx_body = Full payload received
    #   tx_pending = Full payload to send
    #   tx_sending = Current payload block to send
    #      tx_sent = Payload that has been sent
    #     tx_count = Track how many messages the client has sent
    #-----------------------------------------------------------------------
    rx_body = ''
    tx_pending = None
    tx_sending = None
    tx_sent = ''
    tx_count = 0

    #-----------------------------------------------------------------------
    # Option Dictionary/Lists to allow negative testing of the options
    #-----------------------------------------------------------------------
    options_master    = {}
    options_add       = {}
    options_overwrite = {}
    options_delete    = []
    options_string    = EMPTY

    #-----------------------------------------------------------------------
    # Method:
    #   reset_fields
    # Description:
    #   Reset all CoAP specific header fields back to default
    # Input:
    #   None
    # Output:
    #   Nothing
    #-----------------------------------------------------------------------
    def reset_fields(self):
        self.version           = DEFAULT_NUM
        self.transaction_type  = DEFAULT_NUM
        self.method_code       = DEFAULT_NUM
        self.token_length      = DEFAULT_NUM

        #    options_master - Dictionary with options to be sent
        #       options_add - Dictionary with options to added to options_master
        # options_overwrite - Dictionary with options to rewrite options_master
        #    options_delete - List with options to removed from options_master
        #    options_string - Ignore all the options above & send a user string
        self.options_master    = {}
        self.options_add       = {}
        self.options_overwrite = {}
        self.options_delete    = []
        self.options_string    = EMPTY

        # Transmission modifications
        self.set_retry_limit(self.RETRY_LIMIT)
        self.set_transmit_delay(self.TRANSMIT_DELAY)
        self.set_response_delay(self.RESPONSE_DELAY)

        # Clear Message ID when server has started the transaction
        if self.message_start_side == SERVER:
            self.set_message_id(init=True)

    #-----------------------------------------------------------------------
    # Method:
    #   send
    # Description:
    #   Send CoAP message with optional response delays
    # Input:
    #          message = CoAP message
    #   response_delay = (Optional) Time to wait before sending CoAP msg
    #   transmit_delay = (Optional) Time to wait before transmitting CoAP msg
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def send(self, message, response_delay=DEFAULT_NUM,
                            transmit_delay=DEFAULT_NUM):

        # Nothing to send, just return
        if message is None:
            return True

        # No delays when client request message is to be sent
        if self.message_start_side == CLIENT:
            response_delay = 0

        # Response delay value
        if response_delay == DEFAULT_NUM:
            response_delay = self.get_response_delay()

        # Transmit delay time
        if transmit_delay == DEFAULT_NUM:
            if self.tx_count:
                transmit_delay = self.get_transmit_delay()
            else:
                transmit_delay = 0
        if transmit_delay > response_delay:
            response_delay = transmit_delay

        # Wait before sending response
        time.sleep(response_delay)

        # Send message
        if arg.protocol:
            return dtls_obj.write(message)
        return udp_obj.write(message)

    #-----------------------------------------------------------------------
    # Method:
    #   read_parse
    # Description:
    #   Read/parse the incoming CoAP message
    # Input:
    #        timeout = (Optional) Time to wait for a message to arrive
    #    retry_limit = (Optional) # of times to force client to retransmit
    #                             last message
    #    ack_timeout = (Optional) Time between re-transmissions
    #   message_flag = (Optional) Expect a response from the client
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def read_parse(self, timeout=DEFAULT_NUM,
                         retry_limit=DEFAULT_NUM,
                         ack_timeout=COAP_ACK_TIMEOUT,
                         message_flag=True):

        # Update timeout
        if timeout == DEFAULT_NUM:
            timeout = READ_TIMEOUT

        # Failure return code
        return_fail = not message_flag

        # Keep track of any re-transmissions by comparing received messages
        message = ''
        message_rx = ''
        start_count = -1
        start_time = time.time()

        # No retries when waiting for a server response message
        if self.message_start_side == CLIENT:
            retry_limit = 0

        # Retry limit value
        if retry_limit == DEFAULT_NUM:
            retry_limit = self.get_retry_limit()

        # Loop through how many times to force client to re-transmit
        for retry_count in range(start_count, retry_limit):

            # Calculate the read timeout value
            read_timeout = timeout
            if retry_count != start_count:
                read_timeout = ack_timeout + retry_count + 3

            # Read in DTLS message
            if arg.protocol:
                dtls_obj.read_msg(read_timeout, message_flag)
                message_rx = dtls_obj.message
            else:
                udp_obj.read_msg(read_timeout, message_flag)
                message_rx = udp_obj.message

            # No message received
            if message_rx == '':
                break

            # First message
            if message == '':
                start_time = time.time()
                message = message_rx
                continue

            # Re-transmission (check if it matches previous message)
            if message != message_rx:
                # Convert to a printable version
                message = message.encode('hex')
                cur_message = message_rx.encode('hex')

                # Log results
                print_log('ERROR', 'Server did not retransmit previous message')
                print_str = 'Previous: {}\n Current: {}'
                print_debug(print_str.format(message, cur_message,))
                return False

            # Re-transmission successful
            print_debug('Re-transmission detected')

            # Check the server re-transmission time
            if not timeout_check(start_time, ack_timeout):
                return False

            # Record current time and update for next expected timeout
            start_time = time.time()
            # Expecting timeout value to double after each timeout
            ack_timeout += ack_timeout
            continue

        # Parse the message
        if not self.parse_msg(message_rx, direction='rx'):
            return return_fail

        # Return success
        return message_flag

    #-----------------------------------------------------------------------
    # Method:
    #   get_message_id
    # Description:
    #   Return a message ID value
    # Input:
    #   None
    # Output:
    #   <integer> - 2 byte maximum
    #-----------------------------------------------------------------------
    def get_message_id(self):
        return self.message_id

    #-----------------------------------------------------------------------
    # Method:
    #   set_message_id
    # Description:
    #   Return a message ID value
    # Input:
    #   current_num = (Optional) Reset the message ID
    #     increment = (Optional) Adjust value by a specified amount
    #          init = (Optional) Reset message ID to default
    # Output:
    #   <integer> - 2 byte maximum
    #-----------------------------------------------------------------------
    def set_message_id(self, current_num=DEFAULT_NUM, increment=0, init=False):

        # Set message ID back to default
        if init:
            self.message_id = DEFAULT_NUM
            return DEFAULT_NUM

        # Get the current value, if nothing is passed in
        if current_num == DEFAULT_NUM:
            current_num = self.message_id

        # Does it need to be updated
        current_num += increment

        # Make sure the format is correct
        current_num = current_num % 65536

        # Store the updated values
        self.message_id = current_num

        # Return the message ID
        return current_num

    #-----------------------------------------------------------------------
    # Method:
    #   next_message_id
    # Description:
    #   Return the next message ID value when more messages to be sent
    # Input:
    #   current_num = Manually set the message ID (Optional)
    #     increment = Adjust value by a specified amount
    # Output:
    #   <integer> - 2 byte maximum
    #-----------------------------------------------------------------------
    def next_message_id(self, current_num=DEFAULT_NUM):

        # If not the 1st message, then increment from previous value
        increment = 0
        if len(self.rx_dict) != 0:
            increment = 1

        # Return the next value
        message_id = self.set_message_id(current_num, increment)
        return message_id

    #-----------------------------------------------------------------------
    # Method:
    #   update_message_id
    # Description:
    #   Change message ID when no value is currently set
    # Input:
    #   default_value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def update_message_id(self, updated_value):

        # Default value
        message_id = self.get_message_id()
        if message_id == DEFAULT_NUM:
            return self.set_message_id(updated_value)

        # Return value
        return message_id

    #-----------------------------------------------------------------------
    # Method:
    #   get_version
    # Description:
    #   Return a CoAP version value
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_version(self):
        return self.version

    #-----------------------------------------------------------------------
    # Method:
    #   set_version
    # Description:
    #   Set & return that CoAP version value
    # Input:
    #   value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_version(self, value):
        self.version = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   update_version
    # Description:
    #   Change version value when no value is currently set
    # Input:
    #   updated_value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def update_version(self, updated_value):

        # Default value
        version = self.get_version()
        if version == DEFAULT_NUM:
            return self.set_version(updated_value)

        # Return value
        return version

    #-----------------------------------------------------------------------
    # Method:
    #   get_transaction_type
    # Description:
    #   Return a CoAP transaction type value
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_transaction_type(self):
        return self.transaction_type

    #-----------------------------------------------------------------------
    # Method:
    #   set_transaction_type
    # Description:
    #   Set & return that CoAP transaction type value
    # Input:
    #   value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_transaction_type(self, value):
        self.transaction_type = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   update_transaction_type
    # Description:
    #   Change transaction type value when no value is currently set
    # Input:
    #   updated_value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def update_transaction_type(self, updated_value):

        # Default value
        trans_type = self.get_transaction_type()
        if trans_type == DEFAULT_NUM:
            return self.set_transaction_type(updated_value)

        # Return value
        return trans_type

    #-----------------------------------------------------------------------
    # Method:
    #   get_transaction_type_number
    # Description:
    #   Determine the value of the transaction type
    # Input:
    #   Either number/string for the transaction type
    # Output:
    #   <integer> = Transaction type number
    #        None = Not found (error)
    #-----------------------------------------------------------------------
    def get_transaction_type_number(self, transaction_name=DEFAULT):

        # Generic error (default value)
        if (transaction_name == DEFAULT) or (transaction_name == ''):
            return self.transaction_dict['CONFIRM']

        # Number or string
        try:
            # Integer
            transaction_type = int(transaction_name)
            if transaction_type is not self.transaction_dict:
                transaction_type = None
        except ValueError:
            # String (convert to an integer)
            try:
                transaction_type = self.transaction_dict[transaction_name]
                return transaction_type
            except KeyError:
                transaction_type = None

        # Could not find transaction type
        if transaction_type is None:
            print_str = "Invalid transaction type '{}'".format(transaction_name)
            print_log('ERROR', print_str)

        # Return value
        return transaction_type

    #-----------------------------------------------------------------------
    # Method:
    #   get_method_code
    # Description:
    #   Return a CoAP method code value
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_method_code(self):
        return self.method_code

    #-----------------------------------------------------------------------
    # Method:
    #   set_method_code
    # Description:
    #   Set & return that CoAP method code value
    # Input:
    #   value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_method_code(self, value):
        self.method_code = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   update_method_code
    # Description:
    #   Change method code value when no value is currently set
    # Input:
    #   updated_value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def update_method_code(self, updated_value):

        # Default value
        method_code = self.get_method_code()
        if method_code == DEFAULT_NUM:
            return self.set_method_code(updated_value)

        # Return value
        return method_code

    #-----------------------------------------------------------------------
    # Method:
    #   get_token
    # Description:
    #   Return a CoAP token value
    # Input:
    #   None
    # Output:
    #   <string> - Suppose to be a 0-8 byte string
    #-----------------------------------------------------------------------
    def get_token(self):
        return self.token

    #-----------------------------------------------------------------------
    # Method:
    #   set_token
    # Description:
    #   Set & return that CoAP token value
    # Input:
    #   value = String
    # Output:
    #   <string> - Suppose to be a 0-8 byte string
    #-----------------------------------------------------------------------
    def set_token(self, value):
        self.token = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   update_token
    # Description:
    #   Change token value when no value is currently set
    # Input:
    #   default_value = String
    # Output:
    #   <string> - Suppose to be a 0-8 byte string
    #-----------------------------------------------------------------------
    def update_token(self, updated_value):

        # Default value
        token = self.get_token()
        if token == DEFAULT:
            return self.set_token(updated_value)

        # Return value
        return token

    #-----------------------------------------------------------------------
    # Method:
    #   get_token_length
    # Description:
    #   Return a CoAP token length value
    # Input:
    #   None
    # Output:
    #   <string> - Suppose to be a 0-8 byte string
    #-----------------------------------------------------------------------
    def get_token_length(self):

        # Get the currently stored value
        token_length = self.token_length

        # If still at default, calculate based off token length
        if token_length == DEFAULT_NUM:
            return len(self.get_token())

        return token_length

    #-----------------------------------------------------------------------
    # Method:
    #   set_token_length
    # Description:
    #   Set & return that CoAP token length value
    # Input:
    #   value = Integer
    # Output:
    #   <integer> - Length for the token length field
    #-----------------------------------------------------------------------
    def set_token_length(self, value):
        self.token_length = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   build_token
    # Description:
    #   Build a token with random numbers and store the value
    # Input:
    #   length = Length of the token
    # Output:
    #   <string> - Suppose to be a 0-8 byte string
    #-----------------------------------------------------------------------
    def build_token(self, length=DEFAULT_NUM):
        # Initialize variables
        token = ''
        token_chars = \
          '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-.?~='
        token_len_list = [0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8,]

        # Setup the token length field
        if length == DEFAULT_NUM:
            self.set_token_length(length)
            length = token_len_list[random.randint(0, len(token_len_list)-1)]

        # Build out a random token
        for _ in range(0, length):
            index = random.randint(0, len(token_chars)-1)
            token += token_chars[index]

        # Store the updated token
        self.set_token(token)
        return token

    #-----------------------------------------------------------------------
    # Method:
    #   get_retry_limit
    # Description:
    #   Return a CoAP client retransmission retry limit
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_retry_limit(self):
        return self.retry_limit

    #-----------------------------------------------------------------------
    # Method:
    #   set_retry_limit
    # Description:
    #   Set & return that CoAP client retransmission retry limit
    # Input:
    #   value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_retry_limit(self, value):
        self.retry_limit = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_response_delay
    # Description:
    #   Return the CoAP transmission delay time (in seconds)
    # Input:
    #   None
    # Output:
    #   <number>
    #-----------------------------------------------------------------------
    def get_response_delay(self):
        return self.response_delay

    #-----------------------------------------------------------------------
    # Method:
    #   set_response_delay
    # Description:
    #   Set & return the CoAP transmission delay time (in seconds)
    # Input:
    #   value = Number (greater than or equal to zero)
    # Output:
    #   <number>
    #-----------------------------------------------------------------------
    def set_response_delay(self, value):
        self.response_delay = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_transmit_delay
    # Description:
    #   Return the CoAP transmission delay time (in seconds)
    # Input:
    #   None
    # Output:
    #   <number>
    #-----------------------------------------------------------------------
    def get_transmit_delay(self):
        return self.transmit_delay

    #-----------------------------------------------------------------------
    # Method:
    #   set_transmit_delay
    # Description:
    #   Set & return the CoAP transmission delay time (in seconds)
    # Input:
    #   value = Number (greater than or equal to zero)
    # Output:
    #   <number>
    #-----------------------------------------------------------------------
    def set_transmit_delay(self, value):
        self.transmit_delay = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   block_bytes2num
    # Description:
    #   Convert block size value in bytes to the # in the block option string
    # Input:
    #          bytes = Value: 16, 32, 64, 128, 256, 512, 1024, 2048
    #   fix_on_error = (Optional) Always return a valid return value
    # Output:
    #   <integer> = From 0 (16 bytes) to 7 (2048 bytes)
    #-----------------------------------------------------------------------
    @staticmethod
    def block_bytes2num(bytes, fix_on_error=True):

        # Convert: 16 bytes = 0, thru, 2048 bytes = 7
        fvalue = math.log(bytes, 2)
        ivalue = int(fvalue) - 4
        if fix_on_error and (( ivalue < 0 ) or ( ivalue > 7 )):
            print_str = "{}: Invalid block size value '{}', using '6' (1024)"
            print_log('WARNING', print_str.format(value,))
            ivalue = 6
        return ivalue

    #-----------------------------------------------------------------------
    # Method:
    #   block_num2bytes
    # Description:
    #   Convert block size value in option to # of bytes
    # Input:
    #   value = Number from 0-7
    # Output:
    #   <bytes> = From 16 bytes = 0 to 2048 bytes = 7
    #-----------------------------------------------------------------------
    @staticmethod
    def block_num2bytes(value):

        # Convert: 0 = 16 bytes, 7 = 2048 bytes
        value += 4
        value = 2 ** value
        if ( value < 16 ) or ( value > 2048 ):
            print_str = "Invalid block size value '{}', using '1024' (6)"
            print_log('WARNING', print_str.format(value))
            value = 1024
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_block1_number
    # Description:
    #   Return a CoAP option BLOCK1 number value
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_block1_number(self):
        return self.block1_number

    #-----------------------------------------------------------------------
    # Method:
    #   set_block1_number
    # Description:
    #   Set & return that CoAP option BLOCK1 number value
    # Input:
    #       value = Integer
    #   increment = Adjust the block1 number by a specified amount
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_block1_number(self, value=DEFAULT_NUM, increment=0):

        # Get the current value, if nothing is passed in
        if value == DEFAULT_NUM:
            value = self.block1_number

        # Does it need to be updated
        value += increment

        # Update the value
        self.block1_number = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_block2_number
    # Description:
    #   Return a CoAP option BLOCK2 number value
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_block2_number(self):
        return self.block2_number

    #-----------------------------------------------------------------------
    # Method:
    #   set_block2_number
    # Description:
    #   Set & return that CoAP option BLOCK2 number value
    # Input:
    #       value = Integer
    #   increment = Adjust the block2 number by a specified amount
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_block2_number(self, value=DEFAULT_NUM, increment=0):

        # Get the current value, if nothing is passed in
        if value == DEFAULT_NUM:
            value = self.block2_number

        # Does it need to be updated
        value += increment

        # Update the value
        self.block2_number = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_block1_mbit
    # Description:
    #   Return a CoAP option BLOCK1 M-bit value
    # Input:
    #   None
    # Output:
    #   <integer> (Should be 0/1 - 1 bit)
    #-----------------------------------------------------------------------
    def get_block1_mbit(self):
        return self.block1_mbit

    #-----------------------------------------------------------------------
    # Method:
    #   set_block1_mbit
    # Description:
    #   Set & return that CoAP option BLOCK1 M-bit value
    # Input:
    #   value - Integer
    # Output:
    #   <integer> (Should be 0/1 - 1 bit)
    #-----------------------------------------------------------------------
    def set_block1_mbit(self, value):
        self.block1_mbit = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_block2_mbit
    # Description:
    #   Return a CoAP option BLOCK2 M-bit value
    # Input:
    #   None
    # Output:
    #   <integer> (Should be 0/1 - 1 bit)
    #-----------------------------------------------------------------------
    def get_block2_mbit(self):
        return self.block2_mbit

    #-----------------------------------------------------------------------
    # Method:
    #   set_block2_mbit
    # Description:
    #   Set & return that CoAP option BLOCK2 M-bit value
    # Input:
    #   value - Integer
    # Output:
    #   <integer> (Should be 0/1 - 1 bit)
    #-----------------------------------------------------------------------
    def set_block2_mbit(self, value):
        self.block2_mbit = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_block1_size
    # Description:
    #   Return a CoAP option BLOCK1 size value
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_block1_size(self):
        return self.block1_size

    #-----------------------------------------------------------------------
    # Method:
    #   set_block1_size
    # Description:
    #   Set & return that CoAP option BLOCK1 size value
    # Input:
    #   value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_block1_size(self, value=DEFAULT_NUM):

        # Default value
        if value == DEFAULT_NUM:
            value = arg.block
        value = self.block_bytes2num(value)

        # Return updated value
        self.block1_size = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_block2_size
    # Description:
    #   Return a CoAP option BLOCK2 size value
    # Input:
    #   None
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def get_block2_size(self):
        return self.block2_size

    #-----------------------------------------------------------------------
    # Method:
    #   set_block2_size
    # Description:
    #   Set & return that CoAP option BLOCK2 size value
    # Input:
    #   value = Integer
    # Output:
    #   <integer>
    #-----------------------------------------------------------------------
    def set_block2_size(self, value=DEFAULT_NUM):

        # Default value
        if value == DEFAULT_NUM:
            value = arg.block
        value = self.block_bytes2num(value)

        # Return updated value
        self.block2_size = value
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   parse_options
    # Description:
    #   Pull out the option numbers and values from the string provided
    # Input:
    #        text = Byte string (Just options portion)
    #   direction = (Optional) 'tx' (outgoing) or 'rx' (incoming)
    #               Default is 'rx'
    # Output:
    #    index - Index to the next field past the options
    #   string - Option string to print information
    #-----------------------------------------------------------------------
    def parse_options(self, text, direction='rx'):

        # Initial variables
        options_list = []
        option_number = 0
        option_header = False
        index = 0
        options_print_str = ''
        uri_path = ''

        # Loop until all the options have been parsed
        while index < len(text):

            # End of options will have an 0xFF value or End of text
            option_byte = ord(text[index])
            if option_byte == 255:
                print_debug(' End Options: 0xFF (255)')

                # Store the options information
                if direction == 'rx':
                    self.rx_dict['Options'] = options_list
                else:
                    self.tx_dict['Options'] = options_list

                # Add URI information to print message
                if uri_path != '':
                    uri_obj = re.search('/est/+([^ ]+)$', uri_path)
                    if uri_obj:
                        uri_path = '[' + uri_obj.group(1) + ']'
                    options_print_str += 'URI:{} '.format(uri_path,)

                # Payload index
                return index+1, options_print_str

            # Print out beginning options debug
            if not option_header:
                option_header = True
                print_debug('     Options:')
            print_str = '      *1st byte: 0x{:02x} ({})'
            print_str = print_str.format(option_byte, option_byte,)
            print_debug(print_str)

            # Pull out the option delta (top 4 bits)
            option_delta = option_byte / 16
            print_str = '            Delta: 0x{:1x} ({})'
            print_str = print_str.format(option_delta, option_delta,)
            print_debug(print_str)

            # Parse any extended delta values & calculate the option number
            index += 1
            if option_delta == 13:
                byte = ord(text[index])
                option_delta = byte + 13
                option_number += option_delta
                print_str = '        Ext Delta: 0x{:02x} ({}), Total Delta: {}'
                print_str = print_str.format(byte, byte, option_delta,)
                print_debug(print_str)
                index += 1
            elif option_delta == 14:
                byte = (ord(text[index]) * 256) + ord(text[index+1])
                option_delta = byte + 269
                option_number += option_delta
                print_str = '        Ext Delta: 0x{:04x} ({}), Total Delta: {}'
                print_str = print_str.format(byte, byte, option_delta,)
                print_debug(print_str)
                index += 2
            else:
                option_number += option_delta

            # Pull out the option length (bottom 4 bits)
            option_len = option_byte % 16
            print_str = '           Length: 0x{:1x} ({})'
            print_str = print_str.format(option_len, option_len,)
            print_debug(print_str)

            # Parse any extended length values
            if option_len == 13:
                byte = ord(text[index])
                option_len = byte + 13
                print_str = '       Ext Length: 0x{:02x} ({}), Total Length: {}'
                print_str = print_str.format(byte, byte, option_len,)
                print_debug(print_str)
                index += 1
            elif option_len == 14:
                byte = (ord(text[index]) * 256) + ord(text[index+1])
                option_len = byte + 269
                print_str = '       Ext Length: 0x{:04x} ({}), Total Length: {}'
                print_str = print_str.format(byte, byte, option_len,)
                print_debug(print_str)
                index += 2

            # Print out debug information (option name)
            try:
                option_name = self.options_dict[option_number]
                format = self.option_format_dict[option_number]
                number = option_number
            except:
                option_name = '0x{:x}'.format(option_number)
                number = 'UNKNOWN'
                format = 'opaque'
            print_str = '             Name: {} ({})'
            print_debug(print_str.format(option_name, number,))

            # Option value
            option_value = text[index:index+option_len]

            # Print out debug information (option value)
            if format == 'string':
                string = option_value
                if option_number == self.URI_PATH:
                    uri_path += '/' + option_value
            elif format == 'int':
                if option_value != '':
                    value = option_value.encode('hex')
                    string = '0x{} ({})'.format(value, int(value, 16),)
                else:
                    string = '0x0 (NULL)'
            else:
                string = '0x{}'.format(option_value.encode('hex'))
            if option_len:
                print_debug('            Value: {}'.format(string))

            # Block options have addition information to parse
            if format == 'block':
                block_num = 0
                block_mbit = 0
                block_size = 0

                # Parse out the last byte of the option
                if option_len != 0:
                    value = ord(option_value[-1])
                    block_size = value % 8
                    block_mbit = ( value & 8 ) / 8
                    block_num = value / 16

                # Block number can either be 1/2, 1 1/2, 2 1/2 bytes long
                if option_len == 1:
                    print_str = '               Block Num: 0x{:1x} ({})'
                    print_str = print_str.format(block_num, block_num,)
                elif option_len == 2:
                    block_num += ord(option_value[-2]) * 16
                    print_str = '               Block Num: 0x{:03x} ({})'
                    print_str = print_str.format(block_num, block_num,)
                elif option_len == 3:
                    block_num += ord(option_value[-2]) * 16
                    block_num += ord(option_value[-3]) * 4096
                    print_str = '               Block Num: 0x{:05x} ({})'
                    print_str = print_str.format(block_num, block_num,)
                else:
                    option_str = option_value.encode('hex')
                    option_str = option_str[:-1]
                    block_num = int('0'+option_str, 16)
                    print_str = '               Block Num: 0x{} ({})'
                    print_str = print_str.format(option_str, block_num,)
                print_debug(print_str)

                # Print remaining BLOCK information
                if option_len > 0:
                    # Block M-bit
                    print_str = '              Block Mbit: {}'
                    print_debug(print_str.format(block_mbit,))

                    # Block Size
                    byte_size = self.block_num2bytes(block_size)
                    print_str = '              Block Size: 0x{:1x} ({} bytes)'
                    print_debug(print_str.format(block_size, byte_size,))

                # Save the block information
                options_list.append((option_number,
                  (option_len, block_num, block_mbit, block_size,)))
                options_print_str += '{}:{}/{}/{} '.format(option_name,
                                                           block_num,
                                                           block_mbit,
                                                           block_size,)

            # Store all other options as a single piece of data
            else:
                # Store option information
                options_list.append((option_number, option_value,))

            # Look for next option
            index += option_len

        # Store the options information
        if direction == 'rx':
            self.rx_dict['Options'] = options_list
        else:
            self.tx_dict['Options'] = options_list

        # Add URI information to print message
        if uri_path != '':
            uri_obj = re.search('/est/+([^ ]+)$', uri_path)
            if uri_obj:
                uri_path = '[' + uri_obj.group(1) + ']'
            options_print_str += 'URI:{}'.format(uri_path,)

        # No payload found
        return index, options_print_str

    #-----------------------------------------------------------------------
    # Method:
    #   parse_msg
    # Description:
    #   Parse the CoAP payload
    # Input:
    #        text = Byte string
    #   direction = (Optional) 'tx' (outgoing) or 'rx' (incoming)
    #               Default is 'rx'
    # Output:
    #   True/False (All fields are stored either in the coap.rx_dict (incoming)
    #               or coap.tx_dict (outgoing) dictionary)
    #-----------------------------------------------------------------------
    def parse_msg(self, text, direction='rx'):

        # Initialize dictionaries
        msg_dict = {}
        if direction == 'rx':
            self.rx_dict = {}
            parse_str = '--> '
        else:
            self.tx_dict = {}
            parse_str = '<-- '

        # No message received
        if text == '':
            return False

        # Print debug header
        if arg.debug:
            if direction == 'rx':
                print('Incoming:')
            else:
                print('Outgoing:')

        # Don't crash, if there is a problem parsing
        try:
            # Pull out the CoAP version field (top 2 bits, 1st byte)
            byte = ord(text[0])
            value = byte / 64
            msg_dict['Version'] = value
            print_debug('     Version: 0x{:1x} ({})'.format(value, value,))

            # Pull out the transaction type field (3rd & 4th bits, 1st byte)
            byte = byte % 64
            value = byte / 16
            msg_dict['Transaction Type'] = value
            name = 'UNKNOWN'
            if value in self.transaction_dict:
                name = self.transaction_dict[value]
                parse_str += name + '/'
            else:
                parse_str += '0x{:1x}/'.format(value)
            print_str = '  Trans Type: 0x{:1x} ({}) [{}]'
            print_str = print_str.format(value, value, name,)
            print_debug(print_str)

            # Pull out the token length field (bottom 4 bits, 1st byte)
            token_len = byte % 16
            msg_dict['Token Length'] = token_len
            print_str = '   Token Len: 0x{:1x} ({})'
            if token_len > 8:
                print_str += ' <====== Invalid Length'
            print_debug(print_str.format(token_len, token_len,))

            # Pull out the Method Code (2nd byte)
            # (Class is top 3 bits, Detail bottom 5 bits)
            byte = ord(text[1])
            class_num = byte / 32
            detail_num = byte % 32
            if class_num > 0:
                method_str = '[{}.{:02d}]'.format(class_num, detail_num)
            elif detail_num > 0:
                method_str = '[REQ]'
            else:
                method_str = '[0.00]'

            msg_dict['Method Code'] = byte
            print_str = ' Method Code: 0x{:02x} ({}) - {} {}'
            print_debug(print_str.format(byte, byte, method_str,
                                         self.code_dict[byte],))
            msg_dict['Class'] = class_num
            print_str = '         Class: 0x{:1x} ({})'
            print_debug(print_str.format(class_num, class_num,))
            msg_dict['Detail'] = detail_num
            print_str = '        Detail: 0x{:02x} ({})'
            print_debug(print_str.format(detail_num, detail_num,))
            parse_str += self.code_dict[byte].replace(' ', '-') + ' '

            # Pull out the Message ID (3rd & 4th bytes)
            byte = (ord(text[2]) * 256) + ord(text[3])
            msg_dict['Message ID'] = byte
            print_debug('  Message ID: 0x{:04x} ({})'.format(byte, byte,))
            parse_str += 'MID:{:04x} '.format(byte)

            # Pull out the token
            index = 4 + token_len
            string = text[4:index]
            msg_dict['Token'] = string
            if string != '':
                print_debug('       Token: 0x{}'.format(string.encode('hex')))
                parse_str += 'TOK:{} '.format(string.encode('hex'))

            # Pull out the options (Starting after the token)
            # (Payload is returned)
            text = text[index:]
            index, print_str = self.parse_options(text, direction)
            parse_str += print_str

            # Pull payload
            text = text[index:]
            if text != '':
                msg_dict['Payload'] = text
                print_debug('     Payload({}): 0x{}'.format(len(text),
                                                            text.encode('hex')))
                parse_str += 'PAYLOAD({})'.format(len(text))
                text = print_string(text)
                if text != '':
                    print_debug("              '{}'".format(text))
        except:
            # Error parsing message, get rid of any partial information stored
            print_log('ERROR', sys.exc_info()[1])
            return False

        # Copy results to the correct dictionary
        if direction == 'rx':
            for element in msg_dict:
                self.rx_dict[element] = msg_dict[element]
        else:
            for element in msg_dict:
                self.tx_dict[element] = msg_dict[element]

        # Return success
        if arg.debug:
            print('===============================')
        else:
            print_log('INFO', parse_str)
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   calc_block_length
    # Description:
    #   Calculate the # of bytes needed for the block option length
    # Input:
    #   number = Current block number
    # Output:
    #   <int>
    #-----------------------------------------------------------------------
    @staticmethod
    def calc_block_length(number):
        # Upper 4 bits of the 1 byte
        if number < 16:
            return 1
        # Upper 12 bits of the 2 bytes
        if number < 4096:
            return 2
        # Upper 20 bits of the 3 bytes
        return 3

    #-----------------------------------------------------------------------
    # Method:
    #   calc_block_number
    # Description:
    #   Calculate the 1st received block2 number
    # Input:
    #    block = Either BLOCK1 or BLOCK2 option
    #   number = Current block number
    # Output:
    #    True - Value was set/updated
    #   False - Value was already set
    #-----------------------------------------------------------------------
    def calc_block_number(self, block, number):

        # Blocks have been previously received, just return
        if number:
            return number

        # Only for BLOCK1 right now
        if block == self.BLOCK2:
            return number

        # Block number calculated off 1st message sent + received block size
        number = \
          len(self.tx_sent) / self.block_num2bytes(self.get_block1_size())
        return number

    #-----------------------------------------------------------------------
    # Method:
    #   get_option_value
    # Description:
    #   Pull the value from CoAP options list
    # Input:
    #           number = Which option to retrieve
    #   suboption_name = Block options contain several fields
    #                    ('length', 'number', 'mbit', 'size')
    # Output:
    #   <string> or <int> = Option value
    #-----------------------------------------------------------------------
    def get_option_value(self, number, suboption_name=None):

        # Unknown option
        if number not in self.options_dict:
            return None

        # Option not found
        if 'Options' not in self.rx_dict:
            return None

        # Loop through all options from incoming message & find the match
        for option in self.rx_dict['Options']:

            # Get option number and check if it's a match
            option_number, option_value = option
            if len(option) == 3:
                option_number, option_len, option_value = option
            if option_number != number:
                continue

            # Match found
            if self.option_format_dict[option_number] == 'int':
                if option_value == '':
                    option_value = chr(0)
                return int(option_value.encode('hex'), 16)
            if self.option_format_dict[option_number] != 'block':
                return option_value

            # Block options have suboptions

            # Return raw string if no suboption is present
            if suboption_name is None:
                return option_value

            # If block tuple is not correct length, then return nothing
            if len(option_value) != 4:
                return None

            # Parse out block tuple and return interested value
            block_len, block_num, block_mbit, block_size = option_value
            if suboption_name == 'length':
                return block_len
            if suboption_name == 'number':
                return block_num
            if suboption_name == 'mbit':
                return block_mbit
            if suboption_name == 'size':
                return block_size
            if suboption_name == 'bytes':
                return self.block_num2bytes(block_size)
            # Invalid suboption, return nothing
            return None

        # No matching option found, so no value to return
        return None

    #-----------------------------------------------------------------------
    # Method:
    #   build_option_value
    # Description:
    #   Build out a specific type of value for an option
    # Input:
    #        number = Which option name to build a value for
    #         value = (Optional) Option value
    #                   too small - Invalid value
    #                   maximum   - Largest/longest option value
    #                   minimum   - Smallest/shortest option value
    #                   too large - Invalid value
    #                   DEFAULT   - Any valid value
    #   return_type = (Optional) Format to return the value as
    #                 Either: DEFAULT or 'string', Default is DEFAULT
    # Output:
    #   <string> or <int> = Option value
    #-----------------------------------------------------------------------
    def build_option_value(self, number, value=DEFAULT, return_type=DEFAULT):

        # Unknown option
        if number not in self.options_dict:
            return value

        # Type of option
        option_type = self.option_format_dict[number]

        # Default value
        if value == DEFAULT:
            if option_type == 'int':
                value = 1
            elif option_type == 'empty':
                value = ''
            elif option_type == 'block':
                value = coap.setup_block_option(number, (1, 0, 0, arg.block,))
                value = value[number]
            else:
                value = "tbd"

        # Cannot do anything with these types, just return value
        if option_type == 'empty':
            return value
        if option_type == 'block':
            return value

        # Integer
        if option_type == 'int':
            if type(value) is int:
                return_value = value
            elif value == 'minimum':
                return_value = value
            elif value == 'maximum':
                return_value = unsigned_max(self.option_max_size[number])
            elif value == 'too large':
                return_value = unsigned_max(self.option_max_size[number]) + 1
            else:
                return_value = 1
            if return_type == DEFAULT:
                return return_value
            return int2string(return_value)

        # String/opaque
        if value == 'too small':
            return ''
        if value == 'minimum':
            return '1'
        if value == 'maximum':
            return text_string(self.option_max_size[number])
        if value == 'too large':
            return text_string(self.option_max_size[number] + 1)
        return value

    #-----------------------------------------------------------------------
    # Method:
    #   get_option_number
    # Description:
    #   Determine the option number
    # Input:
    #   option_name = Either number/string for the option
    #    error_flag = (Optional) Return an error when no value is found
    # Output:
    #   <integer> = Option number
    #        None = Not found (error)
    #-----------------------------------------------------------------------
    def get_option_number(self, option_name, error_flag=True):

        # Number or string
        try:
            # Integer
            option_number = int(option_name)
            if option_number is not self.options_dict:
                if error_flag:
                    option_number = None
        except ValueError:
            # String (convert to an integer)
            try:
                option_number = self.options_dict[option_name]
                return option_number
            except KeyError:
                option_number = None

        # Could not find the option
        if option_number is None:
            print_str = "Invalid option '{}'".format(option_name)
            print_log('ERROR', print_str)

        # Return value
        return option_number

    #-----------------------------------------------------------------------
    # Method:
    #   get_content_format_number
    # Description:
    #   Determine the value of the content-format option
    # Input:
    #   content_name = Content format integer/name value
    #     error_flag = (Optional) Return an error when no value is found
    # Output:
    #   <integer> = Content-Format option number
    #        None = Not found (error)
    #-----------------------------------------------------------------------
    def get_content_format_number(self, content_name=DEFAULT, error_flag=True):

        # Generic error (default value)
        if (content_name == DEFAULT) or (content_name == ''):
            return self.content_format_dict['application/pkcs10']

        # Number or string
        try:
            # Integer
            content_format = int(content_name)
            if content_format is not self.content_format_dict:
                if error_flag:
                    content_format = None
        except ValueError:
            # String (convert to an integer)
            try:
                content_format = self.content_format_dict[content_name]
                return content_format
            except KeyError:
                content_format = None

        # Could not find content-format
        if content_format is None:
            print_str = "Invalid content-format '{}'".format(content_name)
            print_log('ERROR', print_str)

        # Return value
        return content_format

    #-----------------------------------------------------------------------
    # Method:
    #   validate_msg
    # Description:
    #   Compare the values in the CoAP response with expected values
    # Input:
    #        method_code = Method code value expected to receive
    #   transaction_type = Transaction Type expected to receive
    #         empty_flag = An empty message ACK is an acceptable response
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_msg(self,
                     method_code=DEFAULT_NUM,
                     transaction_type=DEFAULT_NUM,
                     empty_flag=False):

        # Initialize return value
        return_flag = True
        token_flag = True

        # Method code
        if method_code == DEFAULT_NUM:
            method_code = self.CONTENT

        # Transaction type
        if transaction_type == DEFAULT_NUM:
            transaction_type = self.ACK

        # Method Code
        value = self.rx_dict['Method Code']
        # Token Flag
        if self.EMPTY_MSG == value:
            token_flag = False

        # Empty ACK alternate response
        if empty_flag:
            # Method Code check
            if (method_code != value) and (self.EMPTY_MSG != value):
                return_flag = False
                print_str = "Expected method code '{}', Received '{}'"
                print_log('ERROR', print_str.format(method_code, value,))

            # Transaction Type check
            value = self.rx_dict['Transaction Type']
            if (transaction_type != value) and (self.ACK != value):
                return_flag = False
                print_str = "Expected transaction type '{}', Received '{}'"
                print_log('ERROR', print_str.format(self.ACK, value,))

        else:
            # Method Code check
            if method_code != value:
                return_flag = False
                print_str = "Expected method code '{}', Received '{}'"
                print_log('ERROR', print_str.format(method_code, value,))

            # Transaction Type check
            value = self.rx_dict['Transaction Type']
            if transaction_type != value:
                return_flag = False
                print_str = "Expected transaction type '{}', Received '{}'"
                print_log('ERROR', print_str.format(transaction_type, value,))

        # Message ID check
        value = self.rx_dict['Message ID']
        if self.message_start_side == CLIENT:
            if self.tx_dict['Message ID'] != value:
                return_flag = False
                print_str = "Expected message ID '{}', Received '{}'"
                print_str = print_str.format(self.tx_dict['Message ID'], value,)
                print_log('ERROR', print_str)
        else:
            # Update the message ID for the server response
            last_message_id = self.get_message_id()
            if last_message_id != DEFAULT_NUM:
                last_message_id += 1
                if last_message_id != value:
                    return_flag = False
                    print_str = "Expected message ID '{}', Received '{}'"
                    print_str = print_str.format(last_message_id, value,)
                    print_log('ERROR', print_str)

        # Version check
        value = self.rx_dict['Version']
        if self.VERSION != value:
            print_str = "Expected version '{}', Received '{}'"
            print_str = print_str.format(self.VERSION, value,)
            print_log('ERROR', print_str)
            return_flag = False

        # Token check
        value = self.rx_dict['Token']
        if not token_flag:
            current_token = ''
        else:
            current_token = self.get_token()
            # Token not set yet, set it from incoming message
            if current_token == DEFAULT:
                current_token = self.set_token(value)
        if current_token != value:
            return_flag = False
            print_str = "Expected token '{}', Received '{}'"
            print_log('ERROR', print_str.format(current_token, value,))

        # Return results
        return return_flag

    #-----------------------------------------------------------------------
    # Method:
    #   validate_option
    # Description:
    #   Compare the values in CoAP option response with expected values
    # Input:
    #           number = Option number
    #   expected_value = Expected value for the option
    #    optional_flag = (Optional) Ignore error, if not present
    #     equal_result = (Optional) Value to return when equal
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_option(self, number, expected_value,
                        optional_flag=False,
                        equal_result=True):

        # Initialize return value
        name = self.options_dict[number]

        # Get option value from the received message
        value = self.get_option_value(number)

        # Option was not present
        if value is None:
           if not optional_flag:
                print_log('ERROR', '{}: Option NOT found'.format(name))
                return False
           print_log('NOTICE', '{}: Option NOT found'.format(name))
           return True

        # Check option value is equal to the expected value
        if equal_result:
            if value != expected_value:
                print_str = "{}: Expected option value '{}', Received '{}'"
                print_str = print_str.format(name, expected_value, value,)
                print_log('ERROR', print_str)
                return False
            # Return success
            return True

        # Check the option value is not equal to the expected value
        if value == expected_value:
            print_str = "{}: Received unexpected option value '{}'"
            print_str = print_str.format(name, value,)
            print_log('ERROR', print_str)
            return False
        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   validate_payload_size
    # Description:
    #   Compare the length of the payload with the block size limit
    # Input:
    #   None
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_payload_size(self):

        # Initialize variables
        mbit = 0

        # Payload to check (no payload, nothing to check)
        if 'Payload' not in self.rx_dict:
            return True

        # Calculate BLOCK2 size/mbit
        expected_size = self.get_option_value(self.BLOCK2, 'size')
        if expected_size is None:
            expected_size = self.get_block2_size()
        else:
            mbit = self.get_option_value(self.BLOCK2, 'mbit')
        expected_size = self.block_num2bytes(expected_size)

        # Actual size
        actual_size = len(self.rx_dict['Payload'])

        # If mbit is set, the lengths MUST be the same
        if mbit == 1:
            if actual_size == expected_size:
                return True
            compare_str = ''
        # No mbit set, the length must be less than/equal to expected
        else:
            if actual_size <= expected_size:
                return True
            compare_str = '<= '

        # Wrong payload size received
        print_str = "Expected payload size '{}{}' bytes, Received '{}'"
        print_str = print_str.format(compare_str, expected_size, actual_size,)
        print_log('ERROR', print_str)
        return False

    #-----------------------------------------------------------------------
    # Method:
    #   update_block_size
    # Description:
    #   Make sure the block size matches between server/client
    # Input:
    #   block = Either BLOCK1 or BLOCK2 option
    # Output:
    #    True - Value was set/updated
    #   False - Value was already set
    #-----------------------------------------------------------------------
    def update_block_size(self, block):

        # Log title
        name = self.options_dict[block]

        # Check for BLOCK2 option
        rx_size = self.get_option_value(block, 'size')
        if rx_size is None:
            return False

        # If the default size and received size are same then return
        if block == self.BLOCK1:
            tx_size = self.get_block1_size()
        else:
            tx_size = self.get_block2_size()
        if rx_size == tx_size:
            return True

        # Client block size is greater than the server (reduce client size)
        if rx_size < tx_size:
            print_str = "{}: Expected block size '{}', Reduced to '{}'"
            print_log('NOTICE', print_str.format(name, tx_size, rx_size,))
            bytes = self.block_num2bytes(rx_size)
            self.set_block1_size(bytes)
            self.set_block2_size(bytes)
            return True

        # Client block size is less than the server (reduce server size)
        print_str = "{}: Expected block size '{}', Client sent '{}'"
        print_log('NOTICE', print_str.format(name, tx_size, rx_size,))
        bytes = self.block_num2bytes(rx_size)
        self.set_block1_size(bytes)
        self.set_block2_size(bytes)
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   validate_block
    # Description:
    #   Compare the values in CoAP block option response with expected values
    # Input:
    #    block = Option number for either BLOCK1 or BLOCK2
    #   number = Expected block number
    #     mbit = Expected M-bit value
    #     size = Expected payload size (0-7)
    #    bytes = Expected payload size in bytes (16-2048)
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_block(self, block,
                       number=DEFAULT_NUM,
                       mbit=DEFAULT_NUM,
                       size=DEFAULT_NUM,
                       bytes=DEFAULT_NUM):

        # Initialize variables
        return_flag = True
        name = self.options_dict[block]

        # Block Size check
        if size != DEFAULT_NUM:
            value = self.get_option_value(block, 'size')
            if not self.update_block_size(block):
                if (value is not None) and (size != value):
                    print_str = "{}: Expected block size '{}', Received '{}'"
                    print_str = print_str.format(name, size, value,)
                    print_log('ERROR', print_str)
                    return_flag = False

        # Block Number check
        if number != DEFAULT_NUM:
            value = self.get_option_value(block, 'number')

            # Check block number
            if (value is not None) and (number != value):
                print_str = "{}: Expected block number '{}', Received '{}'"
                print_log('ERROR', print_str.format(name, number, value,))
                return_flag = False

        # Block M-bit check
        rx_mbit = self.get_option_value(block, 'mbit')
        if mbit != DEFAULT_NUM:
            if (rx_mbit is not None) and (mbit != rx_mbit):
                print_str = "{}: Expected block M-bit '{}', Received '{}'"
                print_log('ERROR', print_str.format(name, mbit, rx_mbit,))
                return_flag = False

        # Block payload byte size check
        rx_bytes = self.get_option_value(block, 'bytes')
        if bytes != DEFAULT_NUM:
            if (rx_bytes is not None) and (bytes != rx_bytes):
                print_str = \
                  "{}: Expected block size in bytes '{}', Received '{}'"
                print_log('ERROR', print_str.format(name, bytes, rx_bytes,))
                return_flag = False

        # Return results
        return return_flag

    #-----------------------------------------------------------------------
    # Method:
    #   setup_option
    # Description:
    #   Load option into outgoing options dictionary
    # Input:
    #   option_number = Which option to add to the dictionary
    #   option_values = Value(s) of the option to add to the dictionary
    #                   Note: If the option to be added is an integer
    #                         pass in the value as an integer.
    #                         All other option types are stored as a string.
    #         options = Pass in any dictionary options already built out
    #                   (Optional, default is no dictionary)
    #                   Note: If the 'option_number' is in dictionary passed in,
    #                         it will get overwritten
    # Output:
    #   <options> = A dictionary containing all the options generated
    #-----------------------------------------------------------------------
    def setup_option(self, option_number, option_values, options=None):

        # Make sure there is a return dictionary
        if options is None:
            options = {}

        # Do not do anything if option has no value, return original dictionary
        if option_values is None:
            return options

        # Create a list of values for the option
        if type(option_values) is not list:
            option_values = [option_values,]

        # Initialize option dictionary return value
        if option_number not in options:
            options[option_number] = []

        # Loop through each option value
        for option_value in option_values:

            # Determine if it's a known option
            if option_number in self.options_dict:

                # Option is integer format, convert to hex string
                if self.option_format_dict[option_number] == 'int':
                    try:
                        num_str = int2string(option_value)
                        options[option_number].append(num_str)
                        continue
                    except:
                        pass

            # Just store the value as the string passed in
            if option_number >= 0:
                options[option_number].append(option_value)

        # Return a dictionary with all the options
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   setup_block_option
    # Description:
    #   Load block option into outgoing options dictionary
    # Input:
    #          block = Typically BLOCK1 (27) or BLOCK2 (23)
    #   block_values = 4 item tuple containing (len, num, mbit, size)
    #            length - Length of the number field (typically 1-3)
    #            number - number of the block (typically starts at 1)
    #              mbit - More bit flag (1 for more data, 0 for last block)
    #              size - Block size (typically 0-7) for sizes (16-2048 bytes)
    #                     Either 0-7 or 16-2048 (2^n) values are acceptable
    #        options = Pass in any dictionary options already built out
    #                  (Optional, default is no dictionary)
    #                  Note: If BLOCK option is in dictionary passed in,
    #                        it will get overwritten
    #    block_value = User defined string for a BLOCK value
    #                  (Used for negative testing)
    # Output:
    #   <options> = A dictionary containing all the options generated
    #-----------------------------------------------------------------------
    def setup_block_option(self, block, block_values=(), options=None,
                           block_value=EMPTY):

        # Initialize dictionary
        if options is None:
            options = {}

        # Initialize dictionary entry
        if block not in options:
            options[block] = []

        # If block string provided, then use that
        if block_value != EMPTY:
            options[block].append(block_value)
            return options

        # If all the block values not provided, then don't do anything
        if len(block_values) is not 4:
            if len(block_values) is not 0:
                print_str = "Invalid block tuple value '{}'"
                print_log('NOTICE', print_str.format(block_values))
            return options

        # Parse out the block values
        block_len, block_num, block_mbit, block_size = block_values

        # No option length, just return a NULL string
        if block_len == 0:
            options[block].append('')
            return options

        # Calculate the block size
        if ( block_size >= 0 ) and ( block_size <= 7 ):
            value = block_size
        else:
            value = self.block_bytes2num(block_size, fix_on_error=False)
            if ( value < 0 ) or ( value > 7 ):
                print_str = "Invalid block size value '{}'"
                print_log('WARNING', print_str.format(block_size))
                return options

        # M-bit value
        if block_mbit:
            value += 8

        # Block number (lowest 4 bits)
        value += ( block_num % 16 ) * 16
        block_value = chr(value)
        block_len += -1
        block_num = block_num / 16

        # Fill the rest of the block number
        for _ in range(0, block_len):
            value = block_num % 256
            block_value = chr(value) + block_value
            block_num = block_num / 256

        # Return updated options
        options[block].append(block_value)
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   build_options
    # Description:
    #   Build CoAP options list
    # Input:
    #        options = Pass in any dictionary options already built out
    #                  (Optional, default is no dictionary)
    #                  Note: If BLOCK option is in dictionary passed in,
    #                        it will get overwritten
    #  option_number = Option number typically not already defined
    #   option_value = Option value for the option number above
    #       if_match = Option 'If-Match' value as string
    #       uri_host = Option 'URI-Host' value as string
    #           etag = Option 'ETag' value as string
    #  if_none_match = Option 'If-None-Match' value as string (typically empty)
    #       uri_port = Option 'URI-Port' value as integer
    #  location_path = Option 'Location-Path' value as string
    #       uri_path = Option 'URI-Path' value as string
    # content_format = Option 'Content-Format' value as integer
    #        max_age = Option 'Max-Age' value as integer
    #      uri_query = Option 'URI-Query' value as string
    #         accept = Option 'Accept' value as integer
    # location_query = Option 'Location-Query' value as string
    #         block2 = Option 'BLOCK2' value as string
    #                  Note: If present, 'block2_values' is ignored
    #  block2_values = Option 'BLOCK2' value as 4 item tuple
    #                  (length, number, mbit, size)
    #                  length - Length of the number field (typically 1-3)
    #                  number - number of the block (typically starts at 1)
    #                    mbit - More bit flag (1 for more blocks, 0 for last)
    #                    size - Block size (0-7) for sizes (16-2048 bytes)
    #                           Either 0-7 or 16-2048 (2^n) values are allowed
    #         block1 = Option 'BLOCK1' value as string
    #                  Note: If present, 'block1_values' is ignored
    #  block1_values = Option 'BLOCK1' value as 4 item tuple
    #                  (length, number, mbit, size)
    #                  length - Length of the number field (typically 1-3)
    #                  number - number of the block (typically starts at 1)
    #                    mbit - More bit flag (1 for more blocks, 0 for last)
    #                    size - Block size (0-7) for sizes (16-2048 bytes)
    #                           Either 0-7 or 16-2048 (2^n) values are allowed
    #          size2 = Option 'Size2' value as integer
    #      proxy_uri = Option 'Proxy-URI' value as string
    #   proxy_scheme = Option 'Proxy-Scheme' value as string
    #          size1 = Option 'Size1' value as integer
    # Output:
    #   <options> = A dictionary containing all the options generated
    #-----------------------------------------------------------------------
    def build_options(self,
                      options=None,
                      option_number=DEFAULT_NUM,
                      option_value='',
                      if_match=None,
                      uri_host=None,
                      etag=None,
                      if_none_match=None,
                      uri_port=None,
                      location_path=None,
                      uri_path=None,
                      content_format=None,
                      max_age=None,
                      uri_query=None,
                      accept=None,
                      location_query=None,
                      block2=EMPTY,
                      block2_values=(),
                      block1=EMPTY,
                      block1_values=(),
                      size2=None,
                      proxy_uri=None,
                      proxy_scheme=None,
                      size1=None):

        # If no existing options passed in, initialize the dictionary
        if options is None:
            options = {}

        # Unknown option (treat value as a string)
        options = self.setup_option(option_number, option_value, options)

        # Load up the rest of the options
        options = self.setup_option(self.IF_MATCH, if_match, options)
        options = self.setup_option(self.URI_HOST, uri_host, options)
        options = self.setup_option(self.ETAG, etag, options)
        options = self.setup_option(self.IF_NONE_MATCH, if_none_match, options)
        options = self.setup_option(self.URI_PORT, uri_port, options)
        options = self.setup_option(self.LOCATION_PATH, location_path, options)
        options = self.setup_option(self.URI_PATH, uri_path, options)
        options = self.setup_option(self.CONTENT_FORMAT, content_format,
                                    options)
        options = self.setup_option(self.MAX_AGE, max_age, options)
        options = self.setup_option(self.URI_QUERY, uri_query, options)
        options = self.setup_option(self.ACCEPT, accept, options)
        options = self.setup_block_option(self.BLOCK2, block2_values, options,
                                          block2)
        options = self.setup_block_option(self.BLOCK1, block1_values, options,
                                          block1)
        options = self.setup_option(self.LOCATION_QUERY, location_query,
                                    options)
        options = self.setup_option(self.SIZE2, size2, options)
        options = self.setup_option(self.PROXY_URI, proxy_uri, options)
        options = self.setup_option(self.PROXY_SCHEME, proxy_scheme, options)
        options = self.setup_option(self.SIZE1, size1, options)

        # Return the dictionary with all the options filled in
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   build_option_list
    # Description:
    #   Look through all the options in the dictionary and put them in order
    # Input:
    #   options = Pass in the options dictionary
    # Output:
    #   <list> = A list containing all the option values in ascending order
    #-----------------------------------------------------------------------
    @staticmethod
    def build_option_list(options_dict=None):

        # Initialize the dictionary
        if options_dict is None:
            options_dict = {}

        # Build out all valid options in ascending order
        option_list = sorted(options_dict.keys(), key=int)

        # Return option list
        return option_list

    #-----------------------------------------------------------------------
    # Method:
    #   build_option_string
    # Description:
    #   Parse through all defined options and build out a option string
    # Input:
    #   options_dict = List of dictionary options to build out
    #     adjustment = Tweak the length of the final options string
    #     add_string = Append user defined options string to the end
    # Output:
    #   <string> = Options string to add to the CoAP message
    #-----------------------------------------------------------------------
    def build_option_string(self,
                            options_dict=None,
                            adjustment=0,
                            add_string=''):

        # Initialize variables
        option_string = ''
        self.tx_dict['Options'] = []

        # Use a user defined option string
        if self.options_string != EMPTY:
            self.tx_dict['Options'].append((DEFAULT_NUM, self.options_string))
            return self.options_string

        # If options not provided, use class defined dictionary
        if options_dict is None:
            options_dict = self.options_master

        # Delete any user defined option fields
        for option in self.options_delete:
            if option in options_dict:
                options_dict.pop(option)

        # Update any user defined option fields
        for option in self.options_overwrite.keys():
            if option in options_dict:
                options_dict[option] = self.options_overwrite[option]

        # Add any user defined class options
        for option in self.options_add.keys():
            if option not in options_dict:
                options_dict[option] = self.options_add[option]
                self.options_add.pop(option)

        # Add any user defined option fields
        for option in options_dict.keys():
            if option in self.options_add:
                value_list = self.options_add[option]
                if type(value_list) is not list:
                    value_list = [value_list]
                for value in value_list:
                    options_dict[option].append(value)

        # Build out options
        option_prev = 0
        for option_num in self.build_option_list(options_dict):
            for option_value in options_dict[option_num]:
                self.tx_dict['Options'].append((option_num, option_value))
                option_len = len(option_value)

                # Build out the 3 delta values
                option_delta = option_num - option_prev
                option_delta1 = -1
                option_delta2 = -1
                if option_delta < 13:
                    option_byte1 = option_delta * 16
                elif option_delta < 269:
                    option_byte1 = 208
                    option_delta1 = option_delta - 13
                else:
                    option_byte1 = 224
                    option_delta2 = option_delta - 269

                # Build out the 3 length values
                option_len1 = -1
                option_len2 = -1
                if option_len < 13:
                    option_byte1 += option_len
                elif option_len < 269:
                    option_byte1 += 13
                    option_len1 = option_len - 13
                else:
                    option_byte1 += 14
                    option_len2 = option_len - 269

                # Build out the option
                option_string += chr(option_byte1)
                if option_delta1 != -1:
                    option_string += chr(option_delta1)
                if option_delta2 != -1:
                    option_string += chr(option_delta2 / 256)
                    option_string += chr(option_delta2 % 256)
                if option_len1 != -1:
                    option_string += chr(option_len1)
                if option_len2 != -1:
                    option_string += chr(option_len2 / 256)
                    option_string += chr(option_len2 % 256)
                option_string += option_value

                # Set the previous option value
                option_prev = option_num

        # Any adjustment to the string
        option_string = adjust_string(option_string, adjustment)

        # Append any additional characters to the string
        option_string += add_string

        # Return options string
        return option_string

    #-----------------------------------------------------------------------
    # Method:
    #   build_msg
    # Description:
    #   Build a CoAP message
    # Input:
    #    options = Options value as string
    #    payload = Payload value as string
    #   truncate = Strip characters from the end of the string
    # Output:
    #   <string> = CoAP byte string
    #-----------------------------------------------------------------------
    def build_msg(self, options='', payload=MISSING, truncate=0):

        # Initialize the dictionary to store current values
        self.tx_dict = {}

        # Build out CoAP header fields
        version          = self.update_version(self.VERSION)
        transaction_type = self.update_transaction_type(self.TRANSACTION_TYPE)
        token            = self.update_token('')
        token_length     = self.get_token_length()
        method_code      = self.update_method_code(self.POST)
        message_id       = self.get_message_id()

        # Build out 1st byte (Version, Transaction Type, Token Length)
        self.tx_dict['Version'] = version
        self.tx_dict['Transaction Type'] = transaction_type
        self.tx_dict['Token Length'] = token_length
        byte = (version * 64) + (transaction_type * 16) + token_length
        coap_str = chr(byte)

        # Build out 2nd byte (Method Code)
        self.tx_dict['Method Code'] = method_code
        coap_str += chr(method_code)

        # Build out 3rd & 4th bytes (Message ID)
        self.tx_dict['Message ID'] = message_id
        coap_str += chr(message_id / 256) + chr(message_id & 255)

        # Build out token
        self.tx_dict['Token'] = token
        coap_str += token

        # Build out options
        self.tx_dict['Options'] = options
        coap_str += options

        # Add payload
        if payload == MISSING:
            self.tx_dict['Payload'] = ''
        elif payload == EMPTY:
            self.tx_dict['Payload'] = ''
            coap_str += chr(0xFF)
        else:
            self.tx_dict['Payload'] = payload
            coap_str += chr(0xFF) + payload

        # Truncate a portion of the string
        if truncate:
            coap_str = coap_str[:truncate]

        # Return the resulting string
        self.parse_msg(coap_str, 'tx')
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   build_payload
    # Description:
    #   Build payload to fit in next message to be sent
    # Input:
    #   payload = User defined payload for this block
    # Output:
    #   <string> - Payload to be sent on next message
    #-----------------------------------------------------------------------
    def build_payload(self, payload=DEFAULT):

        # No more BLOCK1 options when done sending message
        if self.get_block1_mbit() == 0:
            return MISSING

        # If user defined payload, then just return it
        if payload != DEFAULT:
            return payload

        # Get the BLOCK1 size (in bytes)
        block_size = self.block_num2bytes(self.get_block1_size())

        # Update payload strings
        payload = self.tx_pending[:block_size]
        self.tx_sending = payload
        self.tx_pending = self.tx_pending[block_size:]
        self.tx_sent += self.tx_sending

        # Pull out the portion of the payload and return it
        if payload == '':
            payload = MISSING
        return payload

    #-----------------------------------------------------------------------
    # Method:
    #   calc_block1_mbit
    # Description:
    #   Determine the mbit value for the next BLOCK1 to be sent
    # Input:
    #   mbit = User defined mbit value for this block
    # Output:
    #   0/1/None - Mbit
    #-----------------------------------------------------------------------
    def calc_block1_mbit(self, mbit=DEFAULT_NUM):

        # User defined value, just return it
        if mbit != DEFAULT_NUM:
            return mbit

        # M-bit state
        mbit = 0
        if len(self.tx_pending) > 0:
            mbit = 1
        elif self.tx_sending == self.tx_sent:
            mbit = None

        # Record value for later verification
        self.set_block1_mbit(mbit)

        # Return value
        return mbit

    #-----------------------------------------------------------------------
    # Method:
    #   build_block1_rsp
    # Description:
    #   Build a block1 option to the message to be sent
    # Input:
    #   options = Pass in any dictionary options already built out
    #             (Optional, default is no dictionary)
    # Output:
    #   <dict> - Updated options
    #-----------------------------------------------------------------------
    def build_block1_rsp(self, options=None):

        # If no options provided, then initialize return dictionary
        if options is None:
            options = {}

        # M-bit
        mbit = 0
        if len(self.tx_pending) > 0:
            mbit = 1
        elif self.tx_sending == self.tx_sent:
            return options

        # Block number
        size = self.block_num2bytes(self.get_block1_size())
        number = (len(self.tx_sent) - 1) / size
        self.set_block1_number(number)

        # Block length
        length = self.calc_block_length(number)

        # Return a BLOCK1 for this message
        block_list = (length, number, mbit, size,)
        options = self.setup_block_option(options=options,
                                          block=self.BLOCK1,
                                          block_values=block_list,)
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   build_block2_rsp
    # Description:
    #   Build a block2 option in response to message just received
    # Input:
    #   options = Pass in any dictionary options already built out
    #             (Optional, default is no dictionary)
    # Output:
    #   <dict> - Updated options
    #-----------------------------------------------------------------------
    def build_block2_rsp(self, options=None):

        # If no message has been received, then just return
        if len(self.rx_dict) == 0:
            return options

        # If no options provided, then initialize return dictionary
        if options is None:
            options = {}

        # Get current option parameters
        value = self.get_option_value(self.BLOCK2)

        # No BLOCK2 option, don't add BLOCK2
        if value is None:
            return options

        # Parse out BLOCK2 options
        length, number, dont_care, dont_care = value
        mbit = 0
        block_size = self.get_block2_size()

        # Update the BLOCK2 number parameter
        if number:
            number += 1
        else:
            number = len(self.rx_body) / self.block_num2bytes(block_size)

        # Update the BLOCK2 length parameter
        length = self.calc_block_length(number)

        # Return a BLOCK2 for the next message
        value = (length, number, mbit, block_size)
        options = self.setup_block_option(options=options,
                                          block=self.BLOCK2,
                                          block_values=value,)
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   build_size1_rsp
    # Description:
    #   Build a size1 option to the message to be sent
    # Input:
    #   options = Pass in any dictionary options already built out
    #             (Optional, default is no dictionary)
    #   payload = Outgoing payload string
    #      size = Block1 M-bit value
    # Output:
    #   <dict> - Updated options
    #-----------------------------------------------------------------------
    def build_size1_rsp(self, options=None, payload='', size=DEFAULT_NUM):

        # If no options provided, then initialize return dictionary
        if options is None:
            options = {}

        # If no payload, then just return with options
        if payload == MISSING:
            return options

        # Calculate SIZE1 option value
        if size == DEFAULT_NUM:
            size = len(payload)
            if payload == EMPTY:
                size = 0

        # Add a SIZE1 option to the list of options
        options = self.setup_option(self.SIZE1, size, options)
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   next_msg
    # Description:
    #   Update/Store information needed for next portion of a response
    # Input:
    #   None
    # Output:
    #   None
    #-----------------------------------------------------------------------
    def next_msg(self):

        # Increment number of messages transmitted
        self.tx_count += 1

        # Save off this portion of the payload
        if 'Payload' in self.rx_dict:
            self.rx_body += self.rx_dict['Payload']

        # Empty ACK received
        if (self.rx_dict['Method Code'] == self.EMPTY_MSG) and \
           (self.rx_dict['Transaction Type'] == self.ACK):
            self.message_start_side = SERVER

        # Get current option parameters
        current_number = self.get_option_value(self.BLOCK2, 'number')
        if current_number is None:
            return

        # Next BLOCK2 number
        next_number = 1
        if current_number == 0:
            next_number = \
              len(self.rx_body) / self.block_num2bytes(self.get_block2_size())

        # Update the block number for next message received
        self.set_block2_number(current_number, increment=next_number)

    #-----------------------------------------------------------------------
    # Method:
    #   done
    # Description:
    #   Keep track of the server responses to check if all data received
    # Input:
    #   direction = (Optional) which direction is data being sent
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def done(self, direction=SERVER):

        # Client is still receiving payload
        if direction == SERVER:
            mbit = self.get_option_value(self.BLOCK2, 'mbit')
            if mbit == 1:
                return False
            return True

        # Client is done sending payload
        mbit = self.get_block1_mbit()
        if (mbit is None) or (mbit == 0):
            return True
        return False

    #-----------------------------------------------------------------------
    # Method:
    #   validate_response_code
    # Description:
    #   Compare the response method code with an expected value
    # Input:
    #   method_code = Expected method code
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_response_code(self, method_code):

        # Compare expect and actual response method code
        actual_code = self.rx_dict['Method Code']
        if actual_code  == method_code:
            return True

        # Print error
        print_str = \
          "Expected response method code '{}' ({}), Received '{}' (())"
        print_str = print_str.format(self.code_dict[method_code], method_code,
                                     self.code_dict[actual_code], actual_code,)
        print_log('ERROR', print_str)
        return False

    #-----------------------------------------------------------------------
    # Method:
    #   build_empty_ack
    # Description:
    #   Build a CoAP Empty-Message ACK string
    # Input:
    #   message_id = (Optional) CoAP message ID
    # Output:
    #   <string> - CoAP string
    #-----------------------------------------------------------------------
    def build_empty_ack(self, message_id=DEFAULT_NUM):

        # Setup CoAP header fields
        self.set_transaction_type(self.ACK)
        self.set_method_code(self.EMPTY_MSG)
        self.set_token('')
        self.set_token_length(DEFAULT_NUM)

        # Change the message ID
        if message_id != DEFAULT_NUM:
            self.set_message_id(message_id)
        else:
            message_id = self.get_message_id()
            if message_id == DEFAULT_NUM:
                self.set_message_id(self.rx_dict['Message ID'])

        # Build out CoAP string
        return self.build_msg()

    #-----------------------------------------------------------------------
    # Method:
    #   build_reset
    # Description:
    #   Build a CoAP Reset Message string
    # Input:
    #   method_code = CoAP method code
    #    message_id = (Optional) CoAP message ID
    # Output:
    #   <string> - CoAP string
    #-----------------------------------------------------------------------
    def build_reset(self, method_code, message_id=DEFAULT_NUM):

        # Setup CoAP header fields
        self.set_transaction_type(self.RESET)
        self.set_method_code(method_code)

        # Change the message ID
        if message_id != DEFAULT_NUM:
            self.set_message_id(message_id)
        else:
            if self.message_start_side == CLIENT:
                message_id = coap.next_message_id()
            else:
                message_id = self.get_message_id()
            if message_id == DEFAULT_NUM:
                self.set_message_id(self.rx_dict['Message ID'])

        # Build out CoAP string
        return self.build_msg()

    #-----------------------------------------------------------------------
    # Method:
    #   rx_error
    # Description:
    #   Receive a CoAP error message
    #   Parse/validate the response
    # Input:
    #       error_number = (Optional) CoAP error expected
    #   transaction_type = (Optional) Transaction type
    #         empty_flag = (Optional) Empty ACK expected (True/False)
    #            payload = (Optional) Payload string
    #       read_timeout = (Optional) Read timeout
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def rx_error(self, error_number=BAD_REQ,
                       transaction_type=RESET,
                       empty_flag=True,
                       payload=None,
                       read_timeout=READ_TIMEOUT):

        # Server will send an error message and parse
        if not self.read_parse(timeout=read_timeout):
            return False

        # Validate the message (either EMPTY ACK or error)
        if not self.validate_msg(error_number, transaction_type, empty_flag):
            return False

        # Validate the payload
        if (payload is not None) and (payload != self.rx_dict['Payload']):
            print_str = "Expected payload '{}', Received '{}'"
            print_str = print_str.format(payload, self.rx_dict['Payload'],)
            print_log('ERROR', print_str)
            return False

        # If not EMPTY ACK then return
        if self.rx_dict['Method Code'] != self.EMPTY_MSG:
            return True

        # Server will send an error message and parse
        if not self.read_parse():
            return False

        # Server is in control of the connection
        self.message_start_side = SERVER
        self.set_message_id(init=True)

        # Validate the error message
        if not self.validate_msg(error_number, transaction_type, False):
            return False

        # Send EMPTY_ACK
        if self.rx_dict['Transaction Type'] == self.CONFIRM:
            if not self.send(self.build_empty_ack()):
                return False

        # Return success
        return True


### EST class

class Est:

    #-----------------------------------------------------------------------
    # Initialize global class parameters
    #-----------------------------------------------------------------------
    def __init__(self):
        self.est_dict = {}

    #-----------------------------------------------------------------------
    # Constants:
    #   Message Types
    #-----------------------------------------------------------------------
    GET_CACERTS     = 1
    SIMPLE_ENROLL   = 2
    SIMPLE_REENROLL = 3
    CSR_ATTRS       = 4
    SERVER_KEYGEN   = 5
    REQ_VOUCHER     = 11
    VOUCHER_STATUS  = 12
    ENROLL_STATUS   = 13
    # Used for Content-Type POST messages (Enroll/Re-enroll/Server-KeyGen)
    CSR             = 100
    # Used for multipart Server-Side KeyGen
    CERTIFICATE     = 200
    PRIVATE_KEY     = 201
    # Used to retrieve EST resource list from the server
    COAP_RESOURCE   = 1000
    # Keep track of all the EST types
    EST_LIST = [GET_CACERTS, SIMPLE_ENROLL, SIMPLE_REENROLL, CSR_ATTRS,
                SERVER_KEYGEN, REQ_VOUCHER, VOUCHER_STATUS, ENROLL_STATUS,]

    #-----------------------------------------------------------------------
    # Constants:
    #   Message Payloads
    #-----------------------------------------------------------------------
    CSR_PAYLOAD = '''
    MIHGMG4CAQAwDDEKMAgGA1UEAwwBWDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
    BOk3d7zL957eyBzZF4sFb93vU6n9e/guVm3UBBoruhdbKThH7kr0QvBDYCjmn3v1
    CSFikFiLEw24aaEUTiqpz/agADAKBggqhkjOPQQDAgNIADBFAiEAxsqf3DOFAEUh
    +JtUYu+9ImGw0S5ZmAArUowS08KrmiMCIBGXR6xO+mF+rw2bxCTTEDNAT5m/WsgH
    uCe4lULmswNa
    '''
    CSR_PAYLOAD = CSR_PAYLOAD.translate(None, ' \t\r')
    if not arg.base64:
        CSR_PAYLOAD = base64.b64decode(CSR_PAYLOAD)

    CSR_PAYLOAD2 = '''
    MIIBLzCB1gIBADB0MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM
    A1JUUDEWMBQGA1UECgwNQ2lzY28gU3lzdGVtczEZMBcGA1UECwwQQ2lzY29QS0kg
    RGV2VGVzdDEXMBUGA1UEAwwOQmFja3VwLmNzci5jb20wWTATBgcqhkjOPQIBBggq
    hkjOPQMBBwNCAATON8H3cvKoqxdZbzQ8cXgIBzwGjFB8ZiqIrbK0ZxnhheDxRf+s
    /mJc5cODhbzYGVoRITTl5V9CNB8yAMTPYbWzoAAwCgYIKoZIzj0EAwIDSAAwRQIg
    V/zTxvX1YaLdbKt0w5zJbtroQEPBj4lh5JBIabkxYbcCIQC9iKC7D1xDI7iBS5ed
    yXa2mX1YO+XFnfwyXp9EQGXQrA==
    '''
    CSR_PAYLOAD2 = CSR_PAYLOAD2.translate(None, ' \t\r')
    if not arg.base64:
        CSR_PAYLOAD2 = base64.b64decode(CSR_PAYLOAD2)

    #-----------------------------------------------------------------------
    # EST Output Files:
    #-----------------------------------------------------------------------
    CACERT_FILE = temp_dir(PLATFORM) + 'coap-cacert-' + str(PID) + '.pkcs7'
    CACERT_PEM  = temp_dir(PLATFORM) + 'coap-cacert-' + str(PID) + '.pem'
    CERT_FILE   = temp_dir(PLATFORM) + 'coap-cert-' + str(PID) + '.pkcs7'
    CERT_PEM    = temp_dir(PLATFORM) + 'coap-cert-' + str(PID) + '.pem'
    CSR_FILE    = temp_dir(PLATFORM) + 'coap-csr-' + str(PID) + '.base64'
    KEY_FILE    = temp_dir(PLATFORM) + 'coap-key-' + str(PID) + '.key'
    KEY_PEM     = temp_dir(PLATFORM) + 'coap-key-' + str(PID) + '.pem'

    #-----------------------------------------------------------------------
    # EST Message Control:
    #-----------------------------------------------------------------------
    MSG_RETRY_LIMIT = 1

    #-----------------------------------------------------------------------
    # Dictionary:
    #   type_dict
    # Description:
    #   Name/value & value/name translation of the EST message types
    #-----------------------------------------------------------------------
    # Message Names
    type_dict = {'GET_CACERTS'     : GET_CACERTS,
                 'SIMPLE_ENROLL'   : SIMPLE_ENROLL,
                 'SIMPLE_REENROLL' : SIMPLE_REENROLL,
                 'CSR_ATTRS'       : CSR_ATTRS,
                 'SERVER_KEYGEN'   : SERVER_KEYGEN,
                 'REQ_VOUCHER'     : REQ_VOUCHER,
                 'VOUCHER_STATUS'  : VOUCHER_STATUS,
                 'ENROLL_STATUS'   : ENROLL_STATUS,
                 GET_CACERTS       : 'GET_CACERTS',
                 SIMPLE_ENROLL     : 'SIMPLE_ENROLL',
                 SIMPLE_REENROLL   : 'SIMPLE_REENROLL',
                 CSR_ATTRS         : 'CSR_ATTRS',
                 SERVER_KEYGEN     : 'SERVER_KEYGEN',
                 REQ_VOUCHER       : 'REQ_VOUCHER',
                 VOUCHER_STATUS    : 'VOUCHER_STATUS',
                 ENROLL_STATUS     : 'ENROLL_STATUS'
    }

    #-----------------------------------------------------------------------
    # Dictionary:
    #   url_dict
    # Description:
    #   URL names
    #-----------------------------------------------------------------------
    url_dict = {GET_CACERTS     : 'crts',
                SIMPLE_ENROLL   : 'sen',
                SIMPLE_REENROLL : 'sren',
                CSR_ATTRS       : 'att',
                SERVER_KEYGEN   : 'skg',
                REQ_VOUCHER     : 'rv',
                VOUCHER_STATUS  : 'vs',
                ENROLL_STATUS   : 'es'
    }

    #-----------------------------------------------------------------------
    # Dictionary:
    #   content_format_dict
    # Description:
    #   Content Type value in the HTTP header
    #-----------------------------------------------------------------------
    content_format_dict = {CSR             : 'application/pkcs10',
                           GET_CACERTS     : 'application/pkcs7-mime+certs',
                           SIMPLE_ENROLL   : 'application/pkcs7-mime+certs',
                           SIMPLE_REENROLL : 'application/pkcs7-mime+certs',
                           CSR_ATTRS       : 'application/csrattrs',
                           SERVER_KEYGEN   : 'application/multipart-core',
                           CERTIFICATE     : 'application/pkcs7-mime+certs',
                           PRIVATE_KEY     : 'application/pkcs8',
                           REQ_VOUCHER     : 'application/voucher+cms',
                           VOUCHER_STATUS  : 'application/json',
                           ENROLL_STATUS   : 'application/json',
                           COAP_RESOURCE   : 'text/plain'
    }

    #-----------------------------------------------------------------------
    # Method:
    #   init
    # Description:
    #   Initialize message flow parameters before each EST message transaction
    # Input:
    #   None
    # Output:
    #   None
    #-----------------------------------------------------------------------
    @staticmethod
    def init():
        coap.set_block1_number(0)
        coap.set_block1_mbit(1)
        coap.set_block1_size()
        coap.set_block2_number(0)
        coap.set_block2_size()
        coap.reset_fields()
        coap.rx_body = ''
        coap.tx_pending = None
        coap.tx_sent = ''
        coap.tx_count = 0
        coap.set_token_length(DEFAULT_NUM)
        coap.set_token(coap.build_token())

    #-----------------------------------------------------------------------
    # Method:
    #   update_csr_payload
    # Description:
    #   Setter function to setup CSR payload for POST messages
    # Input:
    #   payload = CSR payload to be sent
    # Output:
    #   <string> - CSR payload
    #-----------------------------------------------------------------------
    def update_csr_payload(self, payload):

        # Pull in the default
        if payload == DEFAULT:
            return self.CSR_PAYLOAD
        return payload

    #-----------------------------------------------------------------------
    # Method:
    #   build_uri
    # Description:
    #   Build EST CoAP URI
    # Input:
    #            uri = Non-standard URI requested (Default is 'DEFAULT')
    #   message_type = EST message type
    #       path_seg = (Optional) Path Segment
    # Output:
    #   <string> = Full CoAP URI
    #-----------------------------------------------------------------------
    def build_uri(self, uri, message_type, path_seg=None):

        # Non-standard URI passed in, just pass it back
        if uri != DEFAULT:
            return uri

        # Build out the full path
        # FIXME: Remove when for RFC is updated
        # uri = '/.well-known/est'
        uri = '/est'
        if path_seg is not None:
            uri += '/' + path_seg
        uri += '/' + self.url_dict[message_type]

        # Return updated URI
        return uri

    #-----------------------------------------------------------------------
    # Method:
    #   get_content_format
    # Description:
    #   Get CoAP content-format/accept option value for a specific EST message
    # Input:
    #   message_type = EST message type
    # Output:
    #   <integer> = coap.content_format_dict value
    #-----------------------------------------------------------------------
    def get_content_format(self, message_type):
        content_format_str = self.content_format_dict[message_type]
        return coap.content_format_dict[content_format_str]

    #-----------------------------------------------------------------------
    # Method:
    #   build_options
    # Description:
    #   Build EST specific options list
    # Input:
    #         uri_host = Option 'URI-Host' value as string
    #         uri_port = Option 'URI-Port' value as integer
    #              uri = URI to be parsed into 'URI-Path'/'URI-Query' strings
    #   content_format = Option 'Content-Format' value as an integer
    #    accept_format = Option 'Accept' value as an integer
    # Output:
    #   <options> = A dictionary containing all the options generated
    #-----------------------------------------------------------------------
    @staticmethod
    def build_options(uri_host,
                      uri_port,
                      uri,
                      content_format=MISSING_NUM,
                      accept_format=MISSING_NUM):

        # Initialize return options dictionary
        options = {}

        # URI-Host option
        if uri_host == DEFAULT:
            #FIXME: Update Options - To restore, uncomment below & remove if/del
            #options = coap.setup_option(coap.URI_HOST, arg.hostname, options)
            if coap.URI_HOST in options:
                del options[coap.URI_HOST]
        elif uri_host != MISSING:
            options = coap.setup_option(coap.URI_HOST, uri_host, options)
        else:
            if coap.URI_HOST in options:
                del options[coap.URI_HOST]

        # URI-Port option
        if uri_port == DEFAULT_NUM:
            #FIXME: Update Options - To restore, uncomment below & remove if/del
            #options = coap.setup_option(coap.URI_PORT, arg.socket, options)
            if coap.URI_PORT in options:
                del options[coap.URI_PORT]
        elif uri_port != MISSING_NUM:
            options = coap.setup_option(coap.URI_PORT, uri_port, options)
        else:
            if coap.URI_PORT in options:
                del options[coap.URI_PORT]

        # URI-Path option
        if uri != MISSING:
            if uri.startswith('/'):
                uri = uri[1:]
            query_list = uri.split('?')
            if len(query_list) == 1:
                uri_path = uri
                uri_query = None
            else:
                uri_path, uri_query = query_list
            uri_path = uri_path.split('/')

            options = coap.setup_option(coap.URI_QUERY, uri_query, options,)
            options = coap.setup_option(coap.URI_PATH, uri_path, options)
        else:
            if coap.URI_PATH in options:
                del options[coap.URI_PATH]

        # Content-Format option
        if content_format != MISSING_NUM:
            options = coap.setup_option(coap.CONTENT_FORMAT,
                                        content_format,
                                        options)

        # Accept option
        if accept_format != MISSING_NUM:
            options = coap.setup_option(coap.ACCEPT, accept_format, options)

        # Return the updated options dictionary
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   build_get
    # Description:
    #   Build EST GET CoAP request message
    # Input:
    #   message_type = EST message type
    #           host = Option 'URI-Host' value as string
    #           port = Option 'URI-Port' value as integer
    #            uri = Option 'URI-Path' value as string
    #       path_seg = Path segment for the URI (Optional, default is '')
    #          token = Token value as string
    #      token_len = Token length as integer
    #        payload = Any data to append to the end of this message
    # Output:
    #   <string> - CoAP message
    #-----------------------------------------------------------------------
    def build_get(self,
                  message_type,
                  host=DEFAULT,
                  port=DEFAULT_NUM,
                  uri=DEFAULT,
                  path_seg=None,
                  payload=MISSING):

        # Method Code
        coap.update_method_code(coap.GET)

        # Build out path for the EST GET
        uri = self.build_uri(uri, message_type, path_seg)

        # Build the accept option
        accept = MISSING_NUM
        if message_type != self.COAP_RESOURCE:
            accept = self.get_content_format(message_type)

        # Setup all the EST specific options
        coap.options_master = \
          self.build_options(host, port, uri, accept_format=accept)

        # Build BLOCK2 early negotiation
        if arg.early_neg:
            coap.options_master = coap.setup_block_option(coap.BLOCK2,
                                             options=coap.options_master,
                                             block_values=(1, 0, 0, arg.block),)

        # Build out options
        options_str = coap.build_option_string()

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=payload)

        # Return CoAP message
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   validate_get
    # Description:
    #   Check the response back from server to an EST GET request
    # Input:
    #   message_type = EST message type
    #         method = CoAP Method Code
    #    transaction = Expected Transaction Type
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_get(self, message_type,
                           method=DEFAULT_NUM,
                           transaction=DEFAULT_NUM):

        # Build out the expected transaction type value
        if transaction == DEFAULT_NUM:
            transaction = coap.ACK

        # Empty ACK a valid response
        empty = False

        # Build out the expected method code value
        if method == DEFAULT_NUM:
            method = coap.CONTENT
            empty = True
        if coap.message_start_side == SERVER:
            empty = False

        # Validate the response
        result1 = coap.validate_msg(method_code=method,
                                    transaction_type=transaction,
                                    empty_flag=empty,)

        # Check out option BLOCK2
        result2 = True
        result3 = True
        value = coap.get_option_value(coap.BLOCK2, 'number')
        if value is not None:
            result2 = coap.validate_block(coap.BLOCK2,
                                          number=coap.get_block2_number(),
                                          size=coap.get_block2_size())

            # Check CONTENT-FORMAT value
            if message_type != self.COAP_RESOURCE:
                content_format = self.get_content_format(message_type)
                result3 = coap.validate_option(coap.CONTENT_FORMAT,
                                               content_format,)

        # Payload check
        result4 = coap.validate_payload_size()

        return result1 and result2 and result3 and result4

    #-----------------------------------------------------------------------
    # Method:
    #   validate_get_rsp
    # Description:
    #   Check the separate response back from server to an EST GET request
    # Input:
    #       message_type = EST message type
    #        method_code = CoAP Method Code
    #   transaction_type = CoAP Transaction Type
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_get_rsp(self, message_type,
                         method_code=DEFAULT_NUM,
                         transaction_type=DEFAULT_NUM):

        # Validate the response
        results1 = coap.validate_msg(method_code=method_code,
                                     transaction_type=transaction_type,)

        # Check out option BLOCK2
        results2 = coap.validate_block(coap.BLOCK2,
                                       number=coap.get_block2_number(),
                                       size=coap.get_block2_size())

        # Check CONTENT-FORMAT value
        content_format = self.get_content_format(message_type)
        results3 = coap.validate_option(coap.CONTENT_FORMAT, content_format)

        # Payload check
        results4 = coap.validate_payload_size()

        return results1 and results2 and results3 and results4

    #-----------------------------------------------------------------------
    # Method:
    #   build_post
    # Description:
    #   Build EST POST CoAP request message
    # Input:
    #    message_type = EST message type
    #         payload = CSR to send with the message
    #   block_payload = (Optional) Payload to be sent in a single block
    #      adjustment = (Optional) Tweak the size of the payload
    #            host = (Optional) Option 'URI-Host' value as string
    #            port = (Optional) Option 'URI-Port' value as integer
    #             uri = (Optional) Option 'URI-Path' value as string
    #        path_seg = (Optional) Path segment for the URI (Default is None)
    # Output:
    #   <string> = Byte string for the EST CoAP POST Block
    #-----------------------------------------------------------------------
    def build_post(self,
                   message_type,
                   payload=DEFAULT,
                   block_payload=DEFAULT,
                   adjustment=0,
                   host=DEFAULT,
                   port=DEFAULT_NUM,
                   uri=DEFAULT,
                   path_seg=None):

        # Update CoAP fields
        coap.update_method_code(coap.POST)
        coap.next_message_id()

        # Setup Payload
        if coap.tx_pending is None:
            coap.tx_pending = self.CSR_PAYLOAD
            if payload != DEFAULT:
                coap.tx_pending = payload
        if coap.tx_pending is None:
            print_log('ERROR', "No 'CSR' payload provided")
            raise Exception('Invalid payload provided')

        # Build out this portion of the payload
        if block_payload == DEFAULT:
            # Build out block payload
            block_payload = coap.build_payload()
            coap.calc_block1_mbit()
            block_payload = adjust_string(block_payload, adjustment)

        # Build out the full path for the POST
        uri = self.build_uri(uri, message_type, path_seg)

        # Content/Accept Format options (only when sending payload)
        content = self.get_content_format(self.CSR)
        accept = self.get_content_format(message_type)
        if (message_type == est.VOUCHER_STATUS) or \
           (message_type == est.ENROLL_STATUS):
            content = self.get_content_format(message_type)
            accept = MISSING_NUM

        # Setup all the EST specific options
        coap.options_master = \
          self.build_options(host, port, uri, content, accept)

        # Setup BLOCK1 option for all messages transmitted
        coap.options_master = coap.build_block1_rsp(coap.options_master)

        # Build BLOCK2 early negotiation
        if arg.early_neg and (len(coap.tx_pending) == 0):
            coap.options_master = coap.setup_block_option(coap.BLOCK2,
                                             options=coap.options_master,
                                             block_values=(1, 0, 0, arg.block),)

        # Setup SIZE1 option for all messages transmitted
        size1 = len(payload)
        if len(block_payload) > size1:
            size1 = len(block_payload)
        coap.options_master = coap.build_size1_rsp(coap.options_master,
                                                   size=size1)

        # Build out options
        options_str = coap.build_option_string()

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=block_payload)

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return the CoAP message
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   build_cacerts
    # Description:
    #   Build EST Get CA certs request
    # Input:
    #         host = Option 'URI-Host' value as string
    #         port = Option 'URI-Port' value as integer
    #          uri = Option 'URI-Path' value as string
    #     path_seg = Path segment for the URI (Optional, default is None)
    #      payload = Any data to append to the end of this message
    #   adjustment = Tweak the size of the payload
    # Output:
    #   <string> = Byte string for the EST CoAP Get CA Certs
    #-----------------------------------------------------------------------
    def build_cacerts(self,
                      host=DEFAULT,
                      port=DEFAULT_NUM,
                      uri=DEFAULT,
                      path_seg=None,
                      payload=MISSING,
                      adjustment=0):

        # Initialize the options dictionary
        coap.options_master = {}

        # Get the global Method Code value
        coap.update_method_code(coap.GET)

        # Piggyback (client) or Separate (server) response
        if coap.message_start_side == CLIENT:

            # Update CoAP fields
            coap.next_message_id()
            coap.update_transaction_type(coap.CONFIRM)

            # Build out the full path for Get CA Certs
            uri = self.build_uri(uri, self.GET_CACERTS, path_seg)

            # Build the accept option value
            accept = MISSING_NUM
            if len(coap.rx_dict) == 0:
                accept = self.get_content_format(self.GET_CACERTS)

            # Setup all the EST specific options
            coap.options_master = \
              self.build_options(host, port, uri, accept_format=accept)
        else:

            # Update CoAP fields
            coap.set_message_id(coap.rx_dict['Message ID'])
            coap.update_transaction_type(coap.ACK)

        # Adjust the payload string
        payload = adjust_string(payload, adjustment)

        # Setup BLOCK2 option for all messages received
        coap.options_master = coap.build_block2_rsp(coap.options_master)

        # Build out options
        options_str = coap.build_option_string()

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=payload)

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return the CoAP message
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   build_csrattrs
    # Description:
    #   Build EST CSR Attributes request
    # Input:
    #         host = Option 'URI-Host' value as string
    #         port = Option 'URI-Port' value as integer
    #          uri = Option 'URI-Path' value as string
    #     path_seg = Path segment for the URI (Optional, default is None)
    #      payload = Any data to append to the end of this message
    #   adjustment = Tweak the size of the payload
    # Output:
    #   <string> = Byte string for the EST CoAP CSR Attributes
    #-----------------------------------------------------------------------
    def build_csrattrs(self,
                       host=DEFAULT,
                       port=DEFAULT_NUM,
                       uri=DEFAULT,
                       path_seg=None,
                       payload=MISSING,
                       adjustment=0):

        # Initialize the options dictionary
        coap.options_master = {}

        # Get the global Method Code value
        coap.update_method_code(coap.GET)

        # Piggyback (client) or Separate (server) response
        if coap.message_start_side == CLIENT:

            # Update CoAP fields
            coap.next_message_id()
            coap.update_transaction_type(coap.CONFIRM)

            # Build out the full path for CSR Attributes
            uri = self.build_uri(uri, self.CSR_ATTRS, path_seg)

            # Build the accept option value
            accept = MISSING_NUM
            if len(coap.rx_dict) == 0:
                accept = self.get_content_format(self.CSR_ATTRS)

            # Setup all the EST specific options
            coap.options_master = \
              self.build_options(host, port, uri, accept_format=accept)
        else:

            # Update CoAP fields
            coap.set_message_id(coap.rx_dict['Message ID'])
            coap.update_transaction_type(coap.ACK)

        # Adjust the payload string
        payload = adjust_string(payload, adjustment)

        # Setup BLOCK2 option for all messages received
        coap.options_master = coap.build_block2_rsp(coap.options_master)

        # Build out options
        options_str = coap.build_option_string()

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=payload)

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return the CoAP message
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   build_enroll
    # Description:
    #   Build EST Simple Enroll request
    # Input:
    #         host = Option 'URI-Host' value as string
    #         port = Option 'URI-Port' value as integer
    #          uri = Option 'URI-Path' value as string
    #     path_seg = Path segment for the URI (Optional, default is None)
    #      payload = Any data to add to the end of the message
    #   adjustment = Tweak the size of the payload
    # Output:
    #   <string> = Byte string for the EST CoAP Simple Enroll Block
    #-----------------------------------------------------------------------
    def build_enroll(self,
                     host=DEFAULT,
                     port=DEFAULT_NUM,
                     uri=DEFAULT,
                     path_seg=None,
                     payload=MISSING,
                     adjustment=0):

        # No BLOCK2 option ever sent, so nothing to send
        if coap.get_option_value(coap.BLOCK2) is None:
            return None

        # Piggyback (client) or Separate (server) response
        coap.update_method_code(coap.POST)
        if coap.message_start_side == CLIENT:

            # Update CoAP fields
            coap.next_message_id()
            coap.update_transaction_type(coap.CONFIRM)

            # Build out the full path for Simple Enroll
            uri = self.build_uri(uri, self.SIMPLE_ENROLL, path_seg)

            # Content Format option
            content = self.get_content_format(self.CSR)

            # Accept option
            accept = MISSING_NUM
            if len(coap.rx_dict) == 0:
                accept = self.get_content_format(self.SIMPLE_ENROLL)

            # Setup all the EST specific options
            coap.options_master = \
              self.build_options(host, port, uri, content, accept)

        else:

            # Update CoAP fields
            if coap.get_message_id() == DEFAULT_NUM:
                coap.set_message_id(coap.rx_dict['Message ID'])
            coap.update_transaction_type(coap.ACK)

        # Adjust the payload string
        payload = adjust_string(payload, adjustment)

        # Setup BLOCK2 option for all messages received
        coap.options_master = coap.build_block2_rsp(coap.options_master)

        # Build out options
        options_str = coap.build_option_string()

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=payload)

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return the CoAP message
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   build_reenroll
    # Description:
    #   Build EST Re-Enroll request
    # Input:
    #         host = Option 'URI-Host' value as string
    #         port = Option 'URI-Port' value as integer
    #          uri = Option 'URI-Path' value as string
    #     path_seg = Path segment for the URI (Optional, default is None)
    #      payload = CSR to send with the message
    #   adjustment = Tweak the size of the payload
    # Output:
    #   <string> = Byte string for the EST CoAP Re-Enroll Block
    #-----------------------------------------------------------------------
    def build_reenroll(self,
                       host=DEFAULT,
                       port=DEFAULT_NUM,
                       uri=DEFAULT,
                       path_seg=None,
                       payload=MISSING,
                       adjustment=0):

        # No BLOCK2 option ever sent, so nothing to send
        if coap.get_option_value(coap.BLOCK2) is None:
            return None

        # Piggyback (client) or Separate (server) response
        coap.update_method_code(coap.POST)
        if coap.message_start_side == CLIENT:

            # Update CoAP fields
            coap.next_message_id()
            coap.update_transaction_type(coap.CONFIRM)

            # Build out the full path for Simple Re-Enroll
            uri = self.build_uri(uri, self.SIMPLE_REENROLL, path_seg)

            # Content Format option
            content = self.get_content_format(self.CSR)

            # Accept option
            accept = MISSING_NUM
            if len(coap.rx_dict) == 0:
                accept = self.get_content_format(self.SIMPLE_REENROLL)

            # Setup all the EST specific options
            coap.options_master = \
              self.build_options(host, port, uri, content, accept)
        else:

            # Update CoAP fields
            coap.set_message_id(coap.rx_dict['Message ID'])
            coap.update_transaction_type(coap.ACK)

        # Adjust the payload string
        payload = adjust_string(payload, adjustment)

        # Setup BLOCK2 option for all messages received
        coap.options_master = coap.build_block2_rsp(coap.options_master)

        # Build out options
        options_str = coap.build_option_string()

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=payload)

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return the CoAP message
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   build_server_keygen
    # Description:
    #   Build EST Server-Side KeyGen request
    # Input:
    #         host = Option 'URI-Host' value as string
    #         port = Option 'URI-Port' value as integer
    #          uri = Option 'URI-Path' value as string
    #     path_seg = Path segment for the URI (Optional, default is '')
    #      payload = Any data to add to the end of the message
    #   adjustment = Tweak the size of the payload
    # Output:
    #   <string> = Byte string for the EST CoAP Server-Side KeyGen Block
    #-----------------------------------------------------------------------
    def build_server_keygen(self,
                            host=DEFAULT,
                            port=DEFAULT_NUM,
                            uri=DEFAULT,
                            path_seg=None,
                            payload=MISSING,
                            adjustment=0):

        # No BLOCK2 option ever sent, so nothing to send
        if coap.get_option_value(coap.BLOCK2) is None:
            return None

        # Piggyback (client) or Separate (server) response
        coap.update_method_code(coap.POST)
        if coap.message_start_side == CLIENT:

            # Update CoAP fields
            coap.next_message_id()
            coap.update_transaction_type(coap.CONFIRM)

            # Build out the full path for Server-Side KeyGen
            uri = self.build_uri(uri, self.SERVER_KEYGEN, path_seg)

            # Content Format option
            content = self.get_content_format(self.CSR)

            # Accept option
            accept = MISSING_NUM
            if len(coap.rx_dict) == 0:
                accept = self.get_content_format(self.SERVER_KEYGEN)

            # Setup all the EST specific options
            coap.options_master = \
              self.build_options(host, port, uri, content, accept)
        else:

            # Update CoAP fields
            if coap.get_message_id() == DEFAULT_NUM:
                coap.set_message_id(coap.rx_dict['Message ID'])
            coap.update_transaction_type(coap.ACK)

        # Adjust the payload string
        payload = adjust_string(payload, adjustment)

        # Setup BLOCK2 option for all messages received
        coap.options_master = coap.build_block2_rsp(coap.options_master)

        # Build out options
        options_str = coap.build_option_string()

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=payload)

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return the CoAP message
        return coap_str

    #TODO: EST BRSKI message flows not completed
    #-----------------------------------------------------------------------
    # Method:
    #   build_req_voucher
    # Description:
    #   Build EST BRSKI Request Voucher
    # Input:
    #         host = Option 'URI-Host' value as string
    #         port = Option 'URI-Port' value as integer
    #          uri = Option 'URI-Path' value as string
    #     path_seg = Path segment for the URI (Optional, default is None)
    #        token = Token value as string
    #    token_len = Token length as integer
    #      payload = JSON text to send with the message
    #   adjustment = Tweak the size of the payload
    # Output:
    #   <string> = Byte string for the EST Voucher Status Block
    #-----------------------------------------------------------------------
    def build_req_voucher(self,
                          host=DEFAULT,
                          port=DEFAULT_NUM,
                          uri=DEFAULT,
                          path_seg=None,
                          token=DEFAULT,
                          token_len=DEFAULT_NUM,
                          payload=DEFAULT,
                          adjustment=0):

        # Build out the required payload
        if payload == DEFAULT:
            payload = json_obj.build_req_voucher()

        # Build out this portion of the payload
        block_payload = coap.build_payload(payload)
        # Determine the BLOCK1 M-bit
        mbit = coap.calc_block1_mbit(payload)

        # Update Token field
        if token == DEFAULT:
            coap.build_token(token_len)
        else:
            coap.set_token(token)
        coap.set_token_length(token_len)

        # Build out the full path for Voucher Status
        uri = self.build_uri(uri, self.VOUCHER_STATUS, path_seg)

        # Content Format option (only when sending payload)
        content = MISSING_NUM
        if mbit is not None:
            content = self.get_content_format(self.VOUCHER_STATUS)

        # Setup all the EST specific options
        coap.options_master = self.build_options(host, port, uri, content)

        # Setup BLOCK1 option for all messages transmitted
        coap.options_master = coap.build_block1_rsp(coap.options_master)
        # FIXME: (returned?) Setup BLOCK2 option for all messages received
        coap.options_master = coap.build_block2_rsp(coap.options_master)

        # Build out options
        options_str = coap.build_option_string()

        # Adjust the payload string
        block_payload = adjust_string(block_payload, adjustment)

        # Update the Method code value
        method_code = coap.get_method_code()
        if method_code == DEFAULT_NUM:
            method_code = coap.POST
        coap.set_method_code(method_code)

        # Build out the CoAP message
        coap_str = coap.build_msg(options=options_str, payload=block_payload)

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return the CoAP message
        return coap_str

    #-----------------------------------------------------------------------
    # Method:
    #   parse_multipart
    # Description:
    #   Parse the payload of a multipart CoAP message
    # Input:
    #   payload = Payload received from EST server
    # Output:
    #   [list] - <content_type, payload> Tuple with content-format & payload
    #-----------------------------------------------------------------------
    @staticmethod
    def parse_multipart(payload):

        # Initialize variables
        index = 1
        return_list = []

        # Pull out the CBOR array byte (should be 0x84 - 4 elements)
        array_byte = ord(payload[0])
        if array_byte is not 0x84:
            print_str = \
              "Wrong CBOR array byte, expected '0x84', received '0x{:02x}'"
            print_str = print_str.format(array_byte)
            print_log('ERROR', print_str)
            return []

        # Loop until all the multiparts parsed
        while index < len(payload):

            # Pull out content-format from payload
            byte = ord(payload[index])
            if byte < 0x18:
                content_type = byte
            elif byte == 0x18:
                index += 1
                content_type = ord(payload[index])
            elif byte == 0x19:
                index += 1
                content_type = ord(payload[index]) << 8
                index += 1
                content_type += ord(payload[index])
            else:
                print_str = "Wrong Multipart Content-Format byte, "
                print_str += "expected '0x00-0x19', received '0x{:02x}'"
                print_str = print_str.format(byte)
                print_log('ERROR', print_str)
                return []
            index += 1

            # Pull out length of the multipart from payload
            length = 0
            byte = ord(payload[index])
            if (byte >= 0x40) and (byte <= 0x57):
                length = byte - 0x40
                num_bytes = 0
            elif byte == 0x58:
                num_bytes = 1
            elif byte == 0x59:
                num_bytes = 2
            elif byte == 0x5a:
                num_bytes = 4
            elif byte == 0x5b:
                num_bytes = 8
            else:
                print_str = "Wrong Multipart length byte, "
                print_str += "expected '0x40-0x5b', received '0x{:02x}'"
                print_str = print_str.format(byte)
                print_log('ERROR', print_str)
                return []
            index += 1
            for offset in range(num_bytes):
                length = length << 8
                length += ord(payload[index])
                index += 1

            # Pull out the multipart data
            data = payload[index:index+length]
            if len(data) != length:
                print_log('ERROR', 'Could not parse multipart payload')
                return []

            # Store the content_type/data
            return_list.append((content_type, data))
            index += length

        # Return list
        return return_list

    #-----------------------------------------------------------------------
    # Method:
    #   parse_server_keygen_rsp
    # Description:
    #   Parse the payload of a Server-Side KeyGen response into cert and
    #   private key portions.
    # Input:
    #    payload = Payload received from EST server
    # Output:
    #   <string, string> = Tuple containing cert & private key payload
    #-----------------------------------------------------------------------
    def parse_server_keygen_rsp(self, payload):

        # Initialize variables
        cert_payload = ''
        key_payload = ''

        # Pull out content-format/payload for each multipart
        multipart_list = self.parse_multipart(payload)
        if len(multipart_list) == 0:
            return '', ''

        # Get the Content-Format for cert/private-key
        cert_content = self.get_content_format(self.CERTIFICATE)
        key_content = self.get_content_format(self.PRIVATE_KEY)

        # Pull out the certificate/private key
        for multipart in multipart_list:
            content_format, payload = multipart

            # Certificate payload
            if content_format == cert_content:
                if cert_payload == '':
                    cert_payload = payload
                    continue
                print_log('ERROR', 'Duplicate certificate payload')
                return '', ''

            # Private key payload
            if content_format == key_content:
                if key_payload == '':
                    key_payload = payload
                    continue
                print_log('ERROR', 'Duplicate private key payload')
                return '', ''

            # Unknown content type detected
            print_str = "Unknown content type '{}'".format(content_format)
            print_log('ERROR', print_str)
            return '', ''

        # Return payloads
        return cert_payload, key_payload

    #-----------------------------------------------------------------------
    # Method:
    #   verify_certs
    # Description:
    #   Make sure the certificate payload received from the server is valid
    # Input:
    #   input_file - Base64 encoded DER file from the
    #                Get CA Cert/Simple Enroll/Re-Enroll/Server-Side KeyGen
    #                response
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def verify_certs(self, input_file):

        # Remove the output file
        delete_file(self.CERT_PEM)

        # Command to build out a PEM file
        if arg.base64:
            pkcs7_command = ('openssl base64 -d -in {} | '
              'openssl pkcs7 -inform DER -outform PEM -text '
              '-print_certs -out {} 2>&1')
        else:
            pkcs7_command = ('openssl pkcs7 -inform DER -outform PEM -text '
              '-print_certs -in {} -out {} 2>&1')
        pkcs7_command = pkcs7_command.format(input_file, self.CERT_PEM,)

        # Execute the PEM file command (no command output & PEM file expected)
        output = subprocess.Popen(pkcs7_command, shell=True,
                                  stdout=subprocess.PIPE).stdout.read()
        output = output.strip()
        if output != '':
            print_str = 'Unexpected output from openssl PEM command\n{}'
            print_log('ERROR', print_str.format(output,))
            return False

        # Command to verify the PEM file
        if arg.cert_verify:
            verify_command = 'openssl verify -CAfile {} {}'
            verify_command = verify_command.format(arg.cacert_file,
                                                   self.CERT_PEM,)

            # Execute the verify command ('OK' is expected)
            output = subprocess.Popen(verify_command, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
            output = output.strip()
            if not output.endswith('OK'):
                print_str = 'Unexpected output from openssl verify command\n{}'
                print_log('ERROR', print_str.format(output,))
                return False

        # Just check if it is a valid X.509 certificate
        else:
            check_command = 'openssl x509 -in {} -text -noout'
            check_command = check_command.format(arg.cacert_file)

            # Execute the check command ('unable to load certificate' on errors)
            output = subprocess.Popen(check_command, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
            output = output.strip()
            if output.startswith('unable to load certificate'):
                print_str = 'Error output from openssl x509 command\n{}'
                print_log('ERROR', print_str.format(output,))
                return False

        # Store the certificate file
        if arg.outcert is not None:
           shutil.copy(self.CERT_PEM, arg.outcert)

        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   verify_csrattrs
    # Description:
    #   Make sure the CSR Attributes payload received from the server is valid
    # Input:
    #   input_file - Base64 encoded DER file from the CSR Attributes response
    #    pop_state - Check for challenge password OID (Default is NONE)
    #                NONE - Do not check for challenge password
    #                PASS - Challenge password OID must be present
    #                FAIL - Challenge password OID must NOT be present
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    @staticmethod
    def verify_csrattrs(input_file, pop_state=NONE):

        # Initialize variables
        return_status = True
        print_str = "{}"
        POP_ON = 1
        POP_OFF = 0

        # Command to build out ASN1 parse data
        csr_command = 'openssl base64 -e -in {} | openssl asn1parse 2>&1'
        csr_command = csr_command.format(input_file,)

        # Execute ASN1 parse command (no command output & text file expected)
        output = subprocess.Popen(csr_command, shell=True,
                                  stdout=subprocess.PIPE).stdout.read()
        upper = output.upper()
        if upper.find('ERROR:') != -1:
            print_str = 'Error in output from openssl ASN1 parse command\n{}'
            return_status = False
        elif upper.find(': SEQUENCE') == -1:
            print_str = 'Unexpected output from openssl ASN1 parse command\n{}'
            return_status = False
        if not return_status:
            print_log('ERROR', print_str.format(output,))

        # Check for PoP (challenge password)
        if pop_state != NONE:
            if output.find(' :challengePassword') == -1:
                if pop_state == POP_ON:
                    print_log('ERROR', "Expected PoP OID missing")
                    return_status = False
            else:
                if pop_state == POP_OFF:
                    print_log('ERROR', "Unexpected PoP OID received")
                    return_status = False
            if not return_status:
                print_log('INFO', 'CSR output:\n' + output)

        # Return success
        return return_status

    #-----------------------------------------------------------------------
    # Method:
    #   verify_server_keygen
    # Description:
    #   Make sure the certificate & private key payload received from
    #   the server are valid
    # Input:
    #   cert_file - DER Certificate file from the Server-Side KeyGen response
    #   key_file - DER Private Key file from the Server-Side KeyGen response
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def verify_server_keygen(self, cert_file, pkey_file):

        # Verify the certificate (Need the PEM file for the private key check)
        if not self.verify_certs(cert_file):
            return False

        # Command to get the X.509 information from the certificate
        openssl_command = \
          'openssl x509 -in {} -noout -text'.format(self.CERT_PEM)

        # Execute the OpenSSL file command (collect output message)
        output = subprocess.Popen(openssl_command, shell=True,
                                  stdout=subprocess.PIPE).stdout.read()

        # Pull out the public key algorithm
        algorithm = ''
        algorithm_obj = re.search(' Public Key Algorithm: +([^ ]+)', output)
        if algorithm_obj:
            algorithm = algorithm_obj.group(1).strip()
        if algorithm == 'rsaEncryption':
            algorithm = 'rsa'
        elif algorithm == 'dsaEncryption':
            algorithm = 'dsa'
        elif algorithm == 'id-ecPublicKey':
            algorithm = 'ec'
        else:
            print_str = "Unsupported algorithm is '{}'".format(algorithm)
            print_log('ERROR', print_str)
            return False

        # Remove the output file
        delete_file(self.KEY_PEM)

        # Command to build out a PEM file
        # Convert from RSA/DSA/EC to PEM and store the result
        pem_command = ''
        if arg.base64:
            pem_command = 'openssl base64 -d -in {} | '
        pem_command += \
          'openssl {} -in {} -inform DER -outform PEM -text -out {} 2>&1'
        pem_command = pem_command.format(algorithm, pkey_file, self.KEY_PEM,)

        # Execute the PEM file command (no command output & PEM file expected)
        output = subprocess.Popen(pem_command, shell=True,
                                  stdout=subprocess.PIPE).stdout.read()
        # RSA output removed
        output = output.replace('writing RSA key', '')
        output = output.strip()
        if output != '':
            print_str = 'Unexpected output from openssl PEM command\n{}'
            print_log('ERROR', print_str.format(output,))
            return False

        # RSA/DSA modulus certificate data
        if (algorithm == 'rsa') or (algorithm == 'dsa'):

            # Command to get the X.509 modulus information in the certificate
            openssl_command = 'openssl x509 -in {} -noout -modulus'
            openssl_command = openssl_command.format(self.CERT_PEM,)

            # Execute the modulus command
            output = subprocess.Popen(openssl_command, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
            output = output.strip()

            # Retrieve & clean up the modulus output
            output = output.replace('writing RSA key', '')
            output = output.strip()
            modulus_obj = re.match('Modulus=(.+)', output)
            if not modulus_obj:
                print_str = 'Problems extracting certificate modulus\n{}'
                print_log('ERROR', print_str.format(output,))
                return False
            cert_modulus = modulus_obj.group(1).strip()

        # EC curve public key certificate data
        else:
            # Command to get the public key information in the certificate
            openssl_command = 'openssl x509 -in {} -noout -text'
            openssl_command = openssl_command.format(self.CERT_PEM,)

            # Execute the print certificate command
            output = subprocess.Popen(openssl_command, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
            output = output.strip()

            # Public key output
            pubkey_obj = re.match(' +pub:(.+) +ASN1 OID:', output)
            if not pubkey_obj:
                print_str = 'Problems extracting certificate public key\n{}'
                print_log('ERROR', print_str.format(output,))
                return False
            output = pubkey_obj.group(1).strip()
            cert_modulus = re.sub('[^0-9a-f]', '', output)

        # RSA/DSA modulus key data
        if (algorithm == 'rsa') or (algorithm == 'dsa'):

            # Command to get the modulus information in the private key
            openssl_command = 'openssl {} -in {} -noout -modulus'
            openssl_command = openssl_command.format(algorithm, self.KEY_PEM,)

            # Execute the modulus command
            output = subprocess.Popen(openssl_command, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
            output = output.strip()

            # Retrieve & clean up the modulus output
            if algorithm == 'rsa':
                match_string = 'Modulus=(.+)'
            else:
                match_string = '.+Public Key=(.+)'
            modulus_obj = re.match(match_string, output)
            if not modulus_obj:
                print_str = 'Problems extracting key modulus\n{}'
                print_log('ERROR', print_str.format(output,))
                return False
            key_modulus = modulus_obj.group(1).strip()

        # EC key data
        else:
            # Command to get the key information in the private key
            openssl_command = 'openssl ec -in {} -text'.format(self.KEY_PEM)

            # Execute the modulus command
            output = subprocess.Popen(openssl_command, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
            output = output.strip()

            # Public key output
            pubkey_obj = re.match('pub:(.+)ASN1 OID:', output)
            if not pubkey_obj:
                print_str = 'Problems extracting key public key\n{}'
                print_log('ERROR', print_str.format(output,))
                return False
            output = pubkey_obj.group(1).strip()
            key_modulus = re.sub('[^0-9a-f]', '', output)

        # Match the cert/key information
        if cert_modulus == key_modulus:
            return True

        # Verify failed
        print_str = 'Verify of public key FAILED\n  Cert = {}\n  Key  = {}'
        print_log('ERROR', print_str.format(cert_modulus, key_modulus,))
        return False

    #-----------------------------------------------------------------------
    # Method:
    #   verify_resource
    # Description:
    #   Make sure the CoAP resource payload received from the server is valid
    # Input:
    #   payload = Resource string to parse
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def verify_resource(self, payload):

        # Initialize results
        return_status = True

        # Header line
        match_str = '</est> *; *rt="ace.est"'
        match_obj = re.match(match_str, payload)
        if not match_obj:
            print_str = 'Problems extracting resource header line'
            print_log('ERROR', print_str)
            return False

        # Loop through each of the EST message types
        for message in self.EST_LIST:
            # Search for the EST message type
            uri = self.build_uri(DEFAULT, message)
            match_str = '<' + uri + '> *; *rt="ace.est" *; *ct=(.+)'
            match_obj = re.search(match_str, payload)
            if not match_obj:
                print_str = "Problems extracting EST '{}' line"
                print_log('ERROR', print_str.format(self.type_dict[message]))
                return_status = False
                continue

            # Extract the content-format types
            content_list = match_obj.group(1).strip()
            content_list = content_list.split()

            # Check the content format is present
            content_format = str(self.get_content_format(message))
            if content_format not in content_list:
                print_str = ("Missing content-format in EST '{}' line, "
                             "expected '{}', found '{}'")
                print_log('ERROR', print_str.format(self.type_dict[message],
                                                    content_format,
                                                    ', '.join(content_list),))
                return_status = False

        # Return results
        return return_status

    #-----------------------------------------------------------------------
    # Method:
    #   validate_rsp
    # Description:
    #   Check response back from server on the current CoAP message received
    # Input:
    #   message_type = EST message type
    #   expected_rsp = Method code to receive on the current message
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_rsp(self, message_type, expected_rsp):

        # Validate the response
        results1 = coap.validate_msg(method_code=expected_rsp,
                                     transaction_type=coap.ACK)

        # Check BLOCK1 (if present)
        results2 = True
        value = coap.get_option_value(coap.BLOCK1, 'number')
        if value is not None:
            results2 = coap.validate_block(coap.BLOCK1,
                                           number=coap.get_block1_number(),
                                           size=coap.get_block1_size())
        # BLOCK2 present
        results3 = True
        results4 = True
        value = coap.get_option_value(coap.BLOCK2, 'number')
        if value is not None:
            # Check BLOCK2 values
            results3 = coap.validate_block(coap.BLOCK2,
                                           number=coap.get_block2_number(),
                                           size=coap.get_block2_size())

            # Check CONTENT-FORMAT value
            content_format = self.get_content_format(message_type)
            results4 = coap.validate_option(coap.CONTENT_FORMAT, content_format)

        # Payload check
        results5 = coap.validate_payload_size()

        # Return results
        return results1 and results2 and results3 and results4 and results5

    #-----------------------------------------------------------------------
    # Method:
    #   validate_post
    # Description:
    #   Check the response back from the server to a EST POST request
    # Input:
    #     message_type = EST message type
    #           method = Expected Method Code
    #      transaction = Expected Transaction Type
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def validate_post(self, message_type,
                            method=DEFAULT_NUM,
                            transaction=DEFAULT_NUM):

        # Build out the expected transaction type value
        if transaction == DEFAULT_NUM:
            transaction = coap.ACK

        # Empty ACK a valid response
        empty = False

        # Server response is based on client finished sending POST request
        if method == DEFAULT_NUM:
            if coap.get_block1_mbit():
                method = coap.CONTINUE
            else:
                method = coap.CHANGED
                empty = True
        elif method == coap.VALID:
            if coap.get_block1_mbit():
                method = coap.CONTINUE
            else:
                empty = True
        if coap.message_start_side == SERVER:
            empty = False

        # Validate the response
        result1 = coap.validate_msg(method_code=method,
                                    transaction_type=transaction,
                                    empty_flag=empty,)

        # Check BLOCK1 (if present)
        result2 = True
        value = coap.get_option_value(coap.BLOCK1, 'number')
        if value is not None:
            result2 = coap.validate_block(coap.BLOCK1,
                                          number=coap.get_block1_number(),
                                          size=coap.get_block1_size())
        # BLOCK2 present
        result3 = True
        result4 = True
        value = coap.get_option_value(coap.BLOCK2, 'number')
        if value is not None:
            # Check BLOCK2 values
            result3 = coap.validate_block(coap.BLOCK2,
                                          number=coap.get_block2_number(),
                                          size=coap.get_block2_size())

            # Check CONTENT-FORMAT value
            content_format = self.get_content_format(message_type)
            result4 = coap.validate_option(coap.CONTENT_FORMAT, content_format)

        # Payload check
        result5 = coap.validate_payload_size()

        # Return results
        return result1 and result2 and result3 and result4 and result5

    #-----------------------------------------------------------------------
    # Method:
    #   build_block_rsp
    # Description:
    #   Build a block option in response to message just received
    # Input:
    #     block = Either BLOCK1 or BLOCK2 option
    #   options = Pass in any dictionary options already built out
    #             (Optional, default is no dictionary)
    # Output:
    #   <dict> - Updated options
    #-----------------------------------------------------------------------
    @staticmethod
    def build_block_rsp(block, options=None):

        # If no options provided, then initialize return dictionary
        if options is None:
            options = {}

        # Pull out the current BLOCK number
        number = coap.get_block2_number()
        if block == coap.BLOCK1:
            number = coap.get_block1_number()

        # Build out a BLOCK option
        length = coap.calc_block_length(coap.get_option_value(block, 'length'))
        size = coap.get_option_value(block, 'size')
        values = (length, number, 0, size)
        options = coap.setup_block_option(options=options,
                                          block=block,
                                          block_values=values)

        # Return updated dictionary
        return options

    #-----------------------------------------------------------------------
    # Method:
    #   parse_csr_file
    # Description:
    #   Build a CSR string from a CSR file content
    # Input:
    #   file = Name of the CSR file
    # Output:
    #   <string> - CSR payload string
    #-----------------------------------------------------------------------
    @staticmethod
    def parse_csr_file(file):

        # Read the entire content of the file
        try:
            file = open(file, 'r')
            file_content = file.read()
            file.close()
        except:
            print_log('WARNING', sys.exc_info()[1])
            return ERROR

        # Parse out the content line-by-line
        csr_string = ''
        for line in file_content.splitlines():
            line = line.strip()
            if line == '-----BEGIN CERTIFICATE REQUEST-----':
                csr_string = ''
                continue
            if line == '-----END CERTIFICATE REQUEST-----':
                break
            csr_string += line

        # Remove any whitespaces & base64 encode
        csr_string = csr_string.replace(' ', '')
        if not arg.base64:
            try:
                csr_string = base64.b64decode(csr_string)
            except TypeError:
                print_log('WARNING', 'Problems Base64 decoding CSR file')
                return ERROR

        # Return results
        return csr_string

    #-----------------------------------------------------------------------
    # Method:
    #   tx_rx_validate_get
    # Description:
    #   Send/Receive a CoAP message
    #   Parse/validate the response
    # Input:
    #   tx_message = Outgoing CoAP message
    #   est_message = EST Get message type
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def tx_rx_validate_get(self, tx_message, est_message):

        rx_flag = 0
        for _ in range(self.MSG_RETRY_LIMIT):

            # Send EST GET message
            if not coap.send(tx_message):
                return False

            # Get response and parse (stored in dtls_obj.message)
            if coap.read_parse():
                rx_flag = 1
                break

        # Valid response never received
        if not rx_flag:
            return False

        # Validate the response
        if not self.validate_get(est_message):
            return False

        # Update fields for next message
        coap.next_msg()

        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   rx_validate_get
    # Description:
    #   Receive a CoAP message
    #   Parse/validate the response
    #   Used during an GetCACerts/CSRAttrs when waiting
    #   for an answer to begin from the CA
    # Input:
    #   est_message = EST Get message type
    #      response = (Optional) Expected response method-code
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def rx_validate_get(self, est_message, response=DEFAULT_NUM):

        # Piggyback mode (no additional message expected)
        if coap.message_start_side == CLIENT:
            return True

        # Server will send a CONTEXT message with the response
        if not coap.read_parse():
            return False

        # Update fields expected for that CONTEXT message
        coap.set_message_id(init=True)
        coap.set_token(coap.rx_dict['Token'])

        # Verify the server response with payload
        if not self.validate_get(est_message,
                                 method=response,
                                 transaction=coap.CONFIRM,):
            return False

        # Send Empty ACK response
        coap.send(coap.build_empty_ack())

        # Update fields to continue with the GET message
        coap.set_message_id(random.randint(0, 65535))
        coap.set_token(coap.rx_dict['Token'])
        coap.message_start_side = CLIENT

        # Sleep before sending the next message
        time.sleep(1)

        # Update fields for next message
        coap.next_msg()

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   tx_rx_validate_post
    # Description:
    #   Send/Receive a CoAP message
    #   Parse/validate the response
    # Input:
    #    tx_message = Outgoing CoAP message
    #   est_message = EST POST message type
    #      response = (Optional) Expected response method-code
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def tx_rx_validate_post(self, tx_message,
                                  est_message,
                                  response=DEFAULT_NUM):

        rx_flag = 0
        for _ in range(self.MSG_RETRY_LIMIT):

            # Send EST POST message
            if not coap.send(tx_message):
                return False

            # Get response and parse (stored in dtls_obj.message)
            if coap.read_parse():
                rx_flag = 1
                break

        # Valid response never received
        if not rx_flag:
            return False

        # Validate the response
        if not self.validate_post(est_message, method=response):
            return False

        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   rx_validate_post
    # Description:
    #   Receive a CoAP message
    #   Parse/validate the response
    #   Used during an Enroll/Re-Enroll/Server-Side KeyGen when waiting
    #   for an answer to begin from the CA
    # Input:
    #             est_message = EST Post message type
    #                response = (Optional) Expected response method-code
    #   bad_empty_ack_id_flag = (Optional) Send wrong Message ID for Empty ACK
    #                                      True/False, Default is False
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def rx_validate_post(self, est_message,
                               response=DEFAULT_NUM,
                               bad_empty_ack_id_flag=False):

        # Piggyback mode (no additional message expected)
        if coap.message_start_side == CLIENT:
            return True

        # Server will send a CONTEXT message with the response
        if not coap.read_parse():
            return False

        # Update fields expected for that CONTEXT message
        coap.set_message_id(init=True)
        coap.set_token(coap.rx_dict['Token'])

        # Verify the server response with payload
        if not self.validate_post(est_message,
                                  method=response,
                                  transaction=coap.CONFIRM,):
            return False

        # Build out the message id for the Empty ACK
        msg_id = coap.rx_dict['Message ID']
        increment = 0
        if bad_empty_ack_id_flag:
            increment = 1
        msg_id = coap.set_message_id(msg_id, increment=increment)

        # Send Empty ACK response
        coap.send(coap.build_empty_ack(message_id=msg_id))

        # Update fields to continue with the POST message
        coap.set_message_id(random.randint(0, 65535))
        coap.set_token(coap.rx_dict['Token'])
        coap.message_start_side = CLIENT

        # Sleep before sending the next message
        time.sleep(1)

        # Update fields for next message
        coap.next_msg()

        # Reset any CoAP parameters that may have been changed by a test
        coap.reset_fields()

        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   tx_post
    # Description:
    #   Send CoAP EST post message
    # Input:
    #   est_message = EST message type
    #       payload = Outgoing CoAP POST payload
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def tx_post(self, est_message, payload,):

        # Loop until entire POST has been transmitted
        while True:

            # Build the EST POST message
            coap_msg = self.build_post(est_message, payload)

            # Send EST POST message
            if not coap.send(coap_msg):
                return False

            # Last message to be sent
            mbit = coap.get_block1_mbit()
            if (mbit is None) or (mbit == 0):
                return True

            # Get response and parse (stored in dtls_obj.message)
            if not coap.read_parse():
                return False

            # Validate the response
            if not self.validate_post(est_message):
                return False

    #-----------------------------------------------------------------------
    # Method:
    #   tx_csr
    # Description:
    #   Send CoAP EST CSR message
    # Input:
    #   est_message = EST message type
    #       payload = Outgoing CoAP POST payload
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def tx_csr(self, est_message, payload):

        # Loop until the entire CSR payload has been transmitted
        while True:

            # Build the EST CSR payload
            coap_msg = est.build_post(est_message, payload)

            # Send/Receive/Validate message
            if not self.tx_rx_validate_post(coap_msg, est_message):
                return False

            # Update fields for next message
            coap.next_msg()

            # No more messages to send
            if coap.done(CLIENT):
                return True

    #-----------------------------------------------------------------------
    # Method:
    #   post_callflow
    # Description:
    #   Send/Receive an entire EST POST callflow
    # Input:
    #   est_message = EST message type
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def post_callflow(self, est_message):

        # Initialize variables
        return_status = True

        # Loop until entire CSR POST has been transmitted
        while True:

            # Build the EST message
            coap_msg = self.build_post(est_message, self.CSR_PAYLOAD)

            # Send/Receive/Validate message
            if not self.tx_rx_validate_post(coap_msg, est_message):
                return False

            # Update fields for next message
            coap.next_msg()

            # No more messages to send
            if coap.done(CLIENT):
                break

        # Wait for the Certificate to begin to be received
        if not self.rx_validate_post(est_message):
            return False

        # Loop until entire Certificate has been received
        while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

            # Build the POST response
            if est_message == self.SIMPLE_ENROLL:
                coap_msg = self.build_enroll()
            elif est_message == self.SIMPLE_REENROLL:
                coap_msg = self.build_reenroll()
            else:
                coap_msg = self.build_server_keygen()

            # Send/Receive/Validate message
            if not self.tx_rx_validate_post(coap_msg, est_message):
                return False

            # Update fields for next message
            coap.next_msg()

            # No more messages to send
            if coap.done():
                break

        # Return success
        return True

    #-----------------------------------------------------------------------
    # Method:
    #   get_callflow
    # Description:
    #   Send/Receive an entire EST GET callflow
    # Input:
    #   est_message = EST message type
    # Output:
    #   True/False
    #-----------------------------------------------------------------------
    def get_callflow(self, est_message):

        # Initialize variables
        return_status = True

        # Build out EST CoAP GET message
        coap_msg = self.build_get(est_message)

        # Send/Receive CoAP message
        if not self.tx_rx_validate_get(coap_msg, est_message):
            return False

        # Wait for the Certificate to begin to be received
        if not self.rx_validate_get(est_message):
            return False

        # Loop thru until server completes sending payload
        while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

            # Build the GET response
            if est_message == self.GET_CACERTS:
                coap_msg = self.build_cacerts()
            else:
                coap_msg = self.build_csrattrs()

            # Send/Receive CoAP message
            if not self.tx_rx_validate_get(coap_msg, est_message):
                return False

            # Check if message is complete
            if coap.done():
                break

        # Return success
        return True

### JSON class

class Json:

    #-----------------------------------------------------------------------
    # Variables:
    #   nonce = Request voucher nonce value
    #-----------------------------------------------------------------------
    nonce = EMPTY

    #-----------------------------------------------------------------------
    # Initialize global class parameters
    #-----------------------------------------------------------------------
    def __init__(self):
        self.dict = {}
        self.nonce = EMPTY

    #-----------------------------------------------------------------------
    # Constants:
    #   BRSKI Message Types
    #-----------------------------------------------------------------------
    REQ_VOUCHER    = 1
    VOUCHER_STATUS = 2
    ENROLL_STATUS  = 3

    #-----------------------------------------------------------------------
    # Dictionary:
    #   msg_dict
    # Description:
    #   Value/Name BRSKI translation table
    #-----------------------------------------------------------------------
    msg_dict = {
        'REQ_VOUCHER'    : REQ_VOUCHER,
        'VOUCHER_STATUS' : VOUCHER_STATUS,
        'ENROLL_STATUS'  : ENROLL_STATUS,
        REQ_VOUCHER      : 'REQ_VOUCHER',
        VOUCHER_STATUS   : 'VOUCHER_STATUS',
        ENROLL_STATUS    : 'ENROLL_STATUS'
    }

    #-----------------------------------------------------------------------
    # Dictionary:
    #   field_format_dict
    # Description:
    #   Format of each of the BRSKI JSON parameters
    #-----------------------------------------------------------------------
    field_format_dict = {
       'ietf-voucher:voucher'           : 'json',
       'version'                        : 'string',
       'status'                         : 'boolean',
       'reason'                         : 'string',
       'reason-context'                 : 'json',
       'created-on'                     : 'date',
       'expires-on?'                    : 'date',
       'assertion'                      : 'string',
       'serial-number'                  : 'string',
       'idevid-issuer?'                 : 'base64',
       'pinned-domain-cert'             : 'base64',
       'domain-cert-revocation-checks?' : 'boolean',
       'nonce?'                         : 'base64',
       'last-renewal-date?'             : 'date',
    }

    #-----------------------------------------------------------------------
    # Method:
    #   build_json
    # Description:
    #   Build the BRSKI JSON payload
    # Input:
    #     wrapper = (Optional) Outside wrapper name
    #   json_list = List of 2-item tuples, with each tuple containing
    #               json_parameter, json_value
    # Output:
    #   <string> - JSON payload
    #-----------------------------------------------------------------------
    def build_json(self, wrapper=EMPTY, json_list=None):

       # Initialize json list
       if json_list is None:
           json_list = []

       # Initialize return string
       json_str = ''

       # Loop through each json parameter
       for json_pair in json_list:
           field, value = json_pair
           print_value = '"{}"'.format(value)
           if field in self.field_format_dict:
               if self.field_format_dict[field] == 'boolean':
                   print_value = value
               if self.field_format_dict[field] == 'json':
                   print_value = '{{\n      {}\n    }}'.format(value)
           json_str += '    "{}" : {},\n'.format(field, print_value,)
       json_str = json_str.rstrip()
       json_str = json_str.rstrip(',')

       # Wrapper
       if wrapper != EMPTY:
           json_str = '  "{}" : {{\n{}\n  }}'.format(wrapper, json_str,)

       # External Wrapper
       json_str = '{{\n{}\n}}'.format(json_str)

       # Return JSON string
       return json_str

    #-----------------------------------------------------------------------
    # Method:
    #   build_brski_status
    # Description:
    #   Build the BRSKI JSON payload needed for voucher/enroll status message
    # Input:
    #          version = Version value
    #           status = Status value (typical values are true/false)
    #           reason = Reason value
    #   reason_context = Reason-context JSON value
    #      more_values = List of 2-item tuples with (parameter, value)
    # Output:
    #   <string> - JSON payload
    #-----------------------------------------------------------------------
    def build_brski_status(self,
                           version=DEFAULT,
                           status=DEFAULT,
                           reason=DEFAULT,
                           reason_context=MISSING,
                           more_values=None):

        # Initialize variables
        json_list = []
        if more_values is None:
            more_values = []

        # Version field
        if version == DEFAULT:
            json_list.append(('version', '1'))
        elif version == EMPTY:
            json_list.append(('version', ''))
        elif version != MISSING:
            json_list.append(('version', version))

        # Status field
        if status == DEFAULT:
            json_list.append(('status', 'true'))
        elif status == EMPTY:
            json_list.append(('status', ''))
        elif status != MISSING:
            json_list.append(('status', status))

        # Reason field
        if reason == DEFAULT:
            json_list.append(('reason', 'Reason is TBD'))
        elif reason == EMPTY:
            json_list.append(('reason', ''))
        elif reason != MISSING:
            json_list.append(('reason', reason))

        # Reason-Context field
        if reason_context == EMPTY:
            json_list.append(('reason-context', ''))
        elif reason_context != MISSING:
            json_list.append(('reason-context', reason_context))

        # Merge any additional json parameters
        json_list += more_values

        # Build the json payload
        return self.build_json(json_list=json_list)

    #-----------------------------------------------------------------------
    # Method:
    #   build_req_voucher
    # Description:
    #   Build the BRSKI JSON payload needed for request voucher message
    # Input:
    #          version = Version value
    #           status = Status value (typical values are true/false)
    #           reason = Reason value
    #   reason_context = Reason-context JSON value
    #      more_values = List of 2-item tuples with (parameter, value)
    # Output:
    #   <string> - JSON payload
    #-----------------------------------------------------------------------
    def build_req_voucher(self,
                          wrapper=DEFAULT,
                          created_on=DEFAULT,
                          assertion=DEFAULT,
                          proximity_registrar_cert=DEFAULT,
                          nonce=DEFAULT,
                          more_values=None):

        # Initialize variables
        json_list = []
        if more_values is None:
            more_values = []

        # Wrapper
        if wrapper == DEFAULT:
            wrapper = 'ietf-voucher-request:voucher'

        # Created-on field
        if created_on == DEFAULT:
            timestamp = datetime.datetime.utcnow()
            created_on = timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if created_on == EMPTY:
            json_list.append(('created-on', ''))
        elif created_on != MISSING:
            json_list.append(('created-on', created_on))

        # Assertion field
        if assertion == DEFAULT:
            assertion = 'proximity'
        if assertion == EMPTY:
            json_list.append(('assertion', ''))
        elif assertion != MISSING:
            json_list.append(('assertion', assertion))

        # Nonce field
        if nonce == DEFAULT:
            nonce = binascii.hexlify(text_string(16, 'random'))
        if nonce == EMPTY:
            json_list.append(('nonce', ''))
        elif nonce != MISSING:
            json_list.append(('nonce', nonce))
            self.nonce = nonce

        # Proximity-registrar-cert field
        if proximity_registrar_cert == DEFAULT:
            try:
                proximity_registrar_cert = base64.b64encode(dtls_obj.peer_cert)
            except:
                proximity_registrar_cert = 'Problems getting Peer Certificate'
        if created_on == EMPTY:
            json_list.append(('proximity-registrar-cert', ''))
        elif created_on != MISSING:
            json_list.append(('proximity-registrar-cert',
                              proximity_registrar_cert))

        # Merge any additional json parameters
        json_list += more_values

        # Build the json payload
        return self.build_json(wrapper=wrapper, json_list=json_list)

    #-----------------------------------------------------------------------
    # Method:
    #   parse
    # Description:
    #   Parse the BRSKI JSON payload from a BRSKI message
    # Input:
    #   payload = JSON payload
    #   wrapper = JSON wrapper where JSON values are located
    # Output:
    #   <dict> - JSON dictionary
    #-----------------------------------------------------------------------
    @staticmethod
    def parse(payload, wrapper=None):

        # FIXME: (used to put together the pinned-domain-cert, till fixed)
        text = ''
        for line in payload.splitlines():
            line = line.strip()
            if line.endswith(','):
                line += ' '
            if line.endswith('{'):
                line += ' '
            if line.endswith('}'):
                line = ' ' + line
            text += line
        payload = text

        # Parse out the JSON output
        json_dict = ast.literal_eval(payload)
        try:
            if wrapper is not None:
                json_dict = json_dict[wrapper]
        except KeyError:
            print_str = "No JSON '{}' wrapper".format(wrapper)
            print_log('ERROR', print_str)

        # Return the dictionary
        return json_dict

    #-----------------------------------------------------------------------
    # Method:
    #   extract
    # Description:
    #   Return a value from the JSON payload from a BRSKI message
    # Input:
    #   payload = JSON payload
    #       tag = JSON tag
    #   wrapper = JSON wrapper where JSON values are located
    # Output:
    #   value = JSON value
    #-----------------------------------------------------------------------
    def extract(self, payload, tag, wrapper):

        # Extract the JSON payload
        json_dict = self.parse(payload, wrapper)

        # Check if the requested tag is present
        if tag in json_dict:
            return json_dict[tag]

        # Tag not found
        print_log('ERROR', "No '{}' found in JSON payload".format(tag))
        return None


### Setup classes
udp_obj = Udp()
dtls_obj = Dtls()
coap = CoAP()
est = Est()
json_obj = Json()

### TEST CASES

# Core resource type request/response
def RESOURCE_TYPE():

    # Record test start
    test_start()

    # Build out EST CoAP GET message
    coap_msg = est.build_get(est.COAP_RESOURCE,
                             uri='/.well-known/core?rt=ace.est')

    # Send/Receive CoAP message
    if not est.tx_rx_validate_get(coap_msg, est.COAP_RESOURCE):
        return FAIL

    # Verify the CoAP resource response
    if not est.verify_resource(coap.rx_body):
        return FAIL

    # Return success
    return PASS

# Get CA Certs request/response
def GET_CACERTS(uri_path=DEFAULT, delete_options=None, path_seg=None):

    # Record test start
    test_start()

    # Remove optional options
    if delete_options is not None:
        coap.options_delete = delete_options

    # Build out EST CoAP GET message
    coap_msg = est.build_get(est.GET_CACERTS, uri=uri_path, path_seg=path_seg)

    # Send/Receive CoAP message
    if not est.tx_rx_validate_get(coap_msg, est.GET_CACERTS):
        return FAIL

    # Wait for the Certificate to begin to be received
    if not est.rx_validate_get(est.GET_CACERTS):
        return FAIL

    # Loop thru until server completes sending payload
    while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

        # Build out EST CoAP GET message
        coap_msg = est.build_cacerts()

        # Send/Receive CoAP message
        if not est.tx_rx_validate_get(coap_msg, est.GET_CACERTS):
            return FAIL

        # Check if message is complete
        if coap.done():
            break

    # Store the content payload
    if not write_file(est.CACERT_FILE, coap.rx_body, 'wb'):
        return FAIL

    # Verify the CA Cert file
    if not est.verify_certs(est.CACERT_FILE):
        return FAIL

    # Return success
    return PASS

# CSR Attributes request/response
def CSR_ATTRS(pop=NONE, payload_format='', delete_options=None, path_seg=None):

    # Record test start
    test_start()

    # Remove optional options
    if delete_options is not None:
        coap.options_delete = delete_options

    # Build out EST CoAP GET message
    coap_msg = est.build_get(est.CSR_ATTRS, path_seg=path_seg)

    # Send/Receive CoAP message
    if not est.tx_rx_validate_get(coap_msg, est.CSR_ATTRS):
        return FAIL

    # Wait for the CSR attributes to begin to be received
    if not est.rx_validate_get(est.CSR_ATTRS):
        return FAIL

    # Loop thru until server completes sending payload
    while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

        # Build out EST CoAP GET message
        coap_msg = est.build_csrattrs()

        # Send/Receive CoAP message
        if not est.tx_rx_validate_get(coap_msg, est.CSR_ATTRS):
            return FAIL

        # Check if message is complete
        if coap.done():
            break

    # Store the content payload
    if not write_file(est.CSR_FILE, coap.rx_body, 'wb'):
        return FAIL

    # Verify the CSR Attribute file
    if not est.verify_csrattrs(est.CSR_FILE, pop):
        return FAIL

    # Print CSR payload
    if payload_format == 'Base64':
        print_log('INFO', 'Payload(Base64): ' + base64.b64encode(coap.rx_body))

    # Return success
    return PASS

# Simple Enroll request/response
def SIMPLE_ENROLL(message_id=DEFAULT_NUM,
                  payload=DEFAULT,
                  delete_options=None,
                  path_seg=None):

    # Record test start
    test_start()
    payload = est.update_csr_payload(payload)

    # Loop until entire Simple-Enroll CSR POST has been transmitted
    coap.set_message_id(message_id)
    while True:

        # Remove optional options
        if delete_options is not None:
            coap.options_delete = delete_options

        # Build the EST Simple Enroll
        coap_msg = est.build_post(est.SIMPLE_ENROLL, payload, path_seg=path_seg)

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.SIMPLE_ENROLL):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done(CLIENT):
            break

    # Wait for the Certificate to begin to be received
    if not est.rx_validate_post(est.SIMPLE_ENROLL):
        return FAIL

    # Loop until entire Simple-Enroll Certificate has been received
    while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

        # Build the EST Simple Enroll
        coap_msg = est.build_enroll()

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.SIMPLE_ENROLL):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done():
            break

    # Store the content payload
    if not write_file(est.CERT_FILE, coap.rx_body, 'wb'):
        return FAIL

    # Verify the enroll certificate file
    if not est.verify_certs(est.CERT_FILE):
        return FAIL

    # Return success
    return PASS

# Simple Re-enroll request/response
def SIMPLE_REENROLL(delete_options=None, path_seg=None):

    # Record test start
    test_start()

    # Loop until entire Simple-Reenroll CSR POST has been transmitted
    while True:

        # Remove optional options
        if delete_options is not None:
            coap.options_delete = delete_options

        # Build the EST Simple Re-enroll
        coap_msg = est.build_post(est.SIMPLE_REENROLL,
                                  est.CSR_PAYLOAD,
                                  path_seg=path_seg)

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.SIMPLE_REENROLL):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done(CLIENT):
            break

    # Wait for the Certificate to begin to be received
    if not est.rx_validate_post(est.SIMPLE_REENROLL):
        return FAIL

    # Loop until entire Simple-Reenroll Certificate has been received
    while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

        # Build the EST Simple Re-enroll
        coap_msg = est.build_reenroll()

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.SIMPLE_REENROLL):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done():
            break

    # Store the content payload
    if not write_file(est.CERT_FILE, coap.rx_body, 'wb'):
        return FAIL

    # Verify the re-enroll certificate file
    if not est.verify_certs(est.CERT_FILE):
        return FAIL

    # Return success
    return PASS

# Server-Side KeyGen request/response
def SERVER_KEYGEN(path_seg=None):

    # Server-side KeyGen responses may take longer than default timeout
    global READ_TIMEOUT
    READ_TIMEOUT = 30

    # Record test start
    test_start()

    # Loop until entire Server-Side KeyGen CSR POST has been transmitted
    while True:

        # Build the EST Server-Side KeyGen POST
        coap_msg = est.build_post(est.SERVER_KEYGEN,
                                  est.CSR_PAYLOAD,
                                  path_seg=path_seg)

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.SERVER_KEYGEN):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done(CLIENT):
            break

    # Wait for the Certificate/Private Key to begin to be received
    if not est.rx_validate_post(est.SERVER_KEYGEN):
        return FAIL

    # Loop until entire Server-Side KeyGen Cert/Private Key have been received
    while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

        # Build the EST Server-Side KeyGen response
        coap_msg = est.build_server_keygen()

        if not est.tx_rx_validate_post(coap_msg, est.SERVER_KEYGEN):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done():
            break

    # Parse the payload into a key/cert
    cert_payload, key_payload = est.parse_server_keygen_rsp(coap.rx_body)
    if cert_payload == '':
        return FAIL

    # Store the content payload
    if not write_file(est.CERT_FILE, cert_payload, 'wb'):
        return FAIL
    if not write_file(est.KEY_FILE, key_payload, 'wb'):
        return FAIL

    # Verify the server-side keygen files
    if not est.verify_server_keygen(est.CERT_FILE, est.KEY_FILE):
        return FAIL

    # Return success
    return PASS

# BRSKI Request Voucher
#FIXME: This can't be tested until we have a completed Registrar/MASA solution
def REQ_VOUCHER(path_seg=None, payload=DEFAULT):

    # Record test start
    test_start()

    # Build the Request Voucher
    if payload == DEFAULT:
        payload = json_obj.build_req_voucher()

    # Loop until entire Request Voucher has been sent
    while True:

        # Build the BRSKI Request Voucher message
        coap_msg = est.build_post(est.REQ_VOUCHER, payload, path_seg=path_seg)

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.REQ_VOUCHER):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done(CLIENT):
            break

    # Wait for the Registrar response to begin to be received
    if not est.rx_validate_post(est.REQ_VOUCHER):
        return FAIL

    # Loop until entire Registrar response has been received
    while coap.get_option_value(coap.BLOCK2, 'mbit') == 1:

        # Build the BRSKI Request Voucher
        coap_msg = est.build_req_voucher()

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.REQ_VOUCHER):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done():
            break

    json_payload = pkcs7_unsign(est.rx_body, arg.masa_cert, arg.masa_cacert)

    # Extract the pinned-domain-cert
    pinned_domain_cert = json_obj.extract(json_payload,
                                          'pinned-domain-cert',
                                          'ietf-voucher:voucher',)
    if pinned_domain_cert is None:
        return FAIL

    # Store the content payload
    if not write_file(est.CERT_FILE, pinned_domain_cert):
        return FAIL

    # Verify the certificate file
    if not est.verify_certs(est.CERT_FILE):
        return FAIL

    # Return success
    return PASS

# BRSKI Voucher Status
def VOUCHER_STATUS(path_seg=None, payload=DEFAULT):

    # Record test start
    test_start()

    # Build the Voucher Status
    if payload == DEFAULT:
        payload = json_obj.build_brski_status()

    # Loop until entire Voucher Status has been sent
    while True:

        # Build the BRSKI Voucher Status message
        coap_msg = est.build_post(est.VOUCHER_STATUS,
                                  payload,
                                  path_seg=path_seg)

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.VOUCHER_STATUS):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done(CLIENT):
            break

    # Wait for the BRSKI response to be received
    if not est.rx_validate_post(est.VOUCHER_STATUS):
        return FAIL

    # No more messages expected
    if not coap.done():
        return FAIL

    # Return success
    return PASS

# BRSKI Enroll Status
def ENROLL_STATUS(path_seg=None, payload=DEFAULT):

    # Record test start
    test_start()

    # Build the Enroll Status
    if payload == DEFAULT:
        payload = json_obj.build_brski_status()

    # Loop until entire Enroll Status has been sent
    while True:

        # Build the BRSKI Enroll Status message
        coap_msg = est.build_post(est.ENROLL_STATUS, payload, path_seg=path_seg)

        # Send/Receive/Validate message
        if not est.tx_rx_validate_post(coap_msg, est.ENROLL_STATUS):
            return FAIL

        # Update fields for next message
        coap.next_msg()

        # No more messages to send
        if coap.done(CLIENT):
            break

    # Wait for the BRSKI response to be received
    if not est.rx_validate_post(est.ENROLL_STATUS):
        return FAIL

    # No more messages expected
    if not coap.done():
        return FAIL

    # Return success
    return PASS

# Simple Enroll with unsupported CONTENT-FORMAT values
def CONTENT_FORMAT(content_format):

    # Record test start
    test_start('Content format = {}'.format(content_format))

    # Determine the content-format number
    content_number = coap.get_content_format_number(content_format,
                                                    error_flag=False,)
    if content_number is None:
        return FAIL

    # Build out CoAP options
    coap.options_delete = [coap.CONTENT_FORMAT,]
    coap.options_add = coap.build_options(content_format=content_number)

    # Build the EST Simple Enroll (with a wrong Content-Format value)
    coap_msg = est.build_post(est.SIMPLE_ENROLL, est.CSR_PAYLOAD)

    # Send EST POST message
    if not coap.send(coap_msg):
        return FAIL

    # Wait for the Server to respond with an error
    error_type = coap.BAD_REQ
    if content_number > 65535:
        error_type = coap.BAD_OPTION
    if not coap.rx_error(error_type, coap.ACK, empty_flag=False):
        return FAIL

    # Return success
    return PASS

# Simple Enroll with unsupported ACCEPT values
def ACCEPT(content_format):

    # Record test start
    test_start('Content format = {}'.format(content_format))

    # Determine the content-format number
    content_number = coap.get_content_format_number(content_format,
                                                    error_flag=False,)
    if content_number is None:
        return FAIL

    # Build out CoAP options
    coap.options_delete = [coap.ACCEPT,]
    coap.options_add = coap.build_options(accept=content_number)

    # Build the EST Simple Enroll (with a wrong Accept option value)
    coap_msg = est.build_post(est.SIMPLE_ENROLL, est.CSR_PAYLOAD)

    # Send EST POST message
    if not coap.send(coap_msg):
        return FAIL

    # Wait for the Server to respond with an error
    error_type = coap.NOT_ACCEPTABLE
    if content_number > 65535:
        error_type = coap.BAD_OPTION
    if not coap.rx_error(error_type, coap.ACK, empty_flag=False):
        return FAIL

    # Return success
    return PASS

# Get CA Certs terminated with Reset in middle of server transmission
def TC5712():

    # Record test start
    test_start()

    # Build out EST CoAP GET message
    coap_msg = est.build_get(est.GET_CACERTS)

    # Send/Receive CoAP message
    if not est.tx_rx_validate_get(coap_msg, est.GET_CACERTS):
        return FAIL

    # Wait for the Certificate to begin to be received
    if not est.rx_validate_get(est.GET_CACERTS):
        return FAIL

    # Make sure multiple blocks are expected from the server
    if coap.get_option_value(coap.BLOCK2, 'mbit') != 1:
        print_log('ERROR', 'Server payload is TOO small for this test')
        return FAIL

    # Build out EST CoAP GET message
    coap_msg = est.build_cacerts()

    # Send/Receive CoAP message
    if not est.tx_rx_validate_get(coap_msg, est.GET_CACERTS):
        return FAIL

    # Build/Send Reset message
    coap_msg = coap.build_reset(coap.REQ_ENTITY_TOO_LARGE)
    if not coap.send(coap_msg):
        return FAIL

    # Return success
    return PASS


### MAIN PROGRAM

# Print out command line options
print_log('ARGV', " ".join(sys.argv[1:]))

# Setup to catch any termination signals
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
INTERRUPT_FLAG = False

# Build out the full test case name
testcase_name = case_name()

# Build out the DTLS protocol version
dtls_obj.protocol_version()

# Pull in CA Certs file name (if not already defined)
if arg.cacert_file is None:
    try:
        arg.cacert_file = os.environ['EST_OPENSSL_CACERT']
    except KeyError:
        arg.cacert_file = os.path.join(os.path.dirname(__file__),
                                       '..', 'CA', 'estCA', 'cacert.crt')

# Print out cert/key information
if arg.debug:
    print('{}: Certificate and keys used:'.format(SCRIPT_NAME,))
    print('    certfile = {}'.format(arg.cert_file,))
    print('     keyfile = {}'.format(arg.key_file,))
    print('    ca_certs = {}'.format(arg.cacert_file,))
    print('     csrfile = {}'.format(arg.csr_file,))

# Load EST CSR needed for Simple Enroll/Re-Enroll/Server-Side KeyGen testing
if arg.csr_file is not None:
    csr_payload = est.parse_csr_file(arg.csr_file)
    if csr_payload == ERROR:
        print_log('WARNING', "Using script default payload for 'CSR'")
    else:
        est.CSR_PAYLOAD = csr_payload

# DTLS needs to run under OpenSSL 1.0.2.  So, the environment variables
# LD_LIBRARY_PATH & PATH must point to same supported version of openssl.
# LD_LIBRARY_PATH must be updated before running the emulator.
# PATH can either be updated before running the emulator or
# by using the environment variable 'OPENSSL_PYTHON_BIN'.
try:
    os.environ['PATH'] = \
      os.environ['OPENSSL_PYTHON_BIN'] + ':' + os.environ['PATH']
except KeyError:
    pass

# Remove OpenSSL FIPS environment variable
try:
    del os.environ['OPENSSL_FIPS']
except KeyError:
    pass

# How much of a time offset allowed before calling a test a FAIL (seconds)
time_threshold = 2

# Initialize return state
exit_status = NOT_RUN

# Patch in DTLS support
do_patch()

# Build socket arguments
client_args = udp_obj.server_parameters(arg.inet)

# Initialize socket objects
client_conn_list = udp_obj.socket_objects(arg.inet, arg.iterations)
client_conn = client_conn_list[0]

# Setup UDP/SSL connection to the server
udp_obj.setup(client_args, client_conn)
dtls_obj.setup(client_conn)

# Execute the test
try:
    if arg.value is not None:
        if arg.string is not None:
            exit_status = globals()[testcase_name](arg.value, arg.string)
        else:
            exit_status = globals()[testcase_name](arg.value)
    else:
        if arg.string is not None:
            exit_status = globals()[testcase_name](arg.string)
        else:
            exit_status = globals()[testcase_name]()

    # Print timestamp
    if arg.timestamp:
        print_msg = 'End timestamp {}'.format(datetime.datetime.now(),)
        print_log('INFO', print_msg, testcase_name)

    # Ignore errors that occurred due to user interrupt during stress/load test
    if INTERRUPT_FLAG:
        exit_status = PASS

    # Print test results
    if exit_status == PASS:
        print_log('PASS', title=testcase_name)
    else:
        print_log('FAIL', title=testcase_name)

except:
    # Ignore errors that occurred due to user interrupt during stress/load test
    if INTERRUPT_FLAG:
        exit_status = PASS
    else:
        exit_status = FAIL
        traceback.print_exc()

# Teardown the SSL connection
dtls_obj.teardown('BOTH', client_conn)

# Remove any test output files
if (arg.debug == 0) or ((arg.debug == 1) and (not exit_status)) :
    delete_file(est.CACERT_FILE)
    delete_file(est.CACERT_PEM)
    delete_file(est.CERT_FILE)
    delete_file(est.CERT_PEM)
    delete_file(est.CSR_FILE)
    delete_file(est.KEY_FILE)
    delete_file(est.KEY_PEM)

# Return results (0 = SUCCESS, 1 = FAIL)
exit_program(exit_status)

