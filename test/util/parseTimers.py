#!python

import sys
import re
with open(sys.argv[1],'r') as logs:
    s = logs.read()
    matches = re.finditer(r'(?:\*\*\*EST \[TIMER\]\[)(\w+):(\d+)\]--> (.*) => (\d+\.\d+) seconds',s,)
    with open(sys.argv[2], 'w') as out_csv:
        out_csv.write("{},{},{},{}\n".format('Tag','Function','Line Number','Time(sec)'))
        for match in matches:
            (function_name, line_num, entry_tag, sec) = match.groups()
            out_csv.write("{},{},{},{}\n".format(entry_tag, function_name, line_num, sec))