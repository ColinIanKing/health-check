#! /usr/bin/python
#
#
# Copyright (C) 2013-2014 Canonical
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
#
# Syntax:
# 	health-check-test-pid.py pid
#
# The process name is resolved and the tool will use a `procname`.threshold file
# to compare against.  If this file does not exist, default.threshold is used.
#
import sys, os, json, psutil

#
# Processes we don't want to run health-check on
#
ignore_procs = [ 'health-check', 'sh', 'init', 'cat', 'vi', 'emacs', 'getty', 'csh', 'bash' ]

#
# Default test run durations in seconds
#
default_duration = 60

#
# Parse thresholds file:
#    lines starting with '#' are comments
#    format is: key value, e.g.
#       health-check.cpu-load.cpu-load-total.total-cpu-percent  0.5
#       health-check.cpu-load.cpu-load-total.user-cpu-percent   0.5
#       health-check.cpu-load.cpu-load-total.system-cpu-percent 0.5
#
def read_threshold(procname):
	filename = procname + ".threshold"
	thresholds = { }
	n = 0

	try:
		with open(filename) as file:
			for line in file:
				n = n + 1
				if len(line) > 1 and not line.startswith("#"):
					tmp = line.split()
					if len(tmp) == 2:
						thresholds[tmp[0]] = tmp[1]
						#sys.stderr.write(tmp[0] + " : " + tmp[1] + "\n")
					else:
						sys.stderr.write("Threshold file " + filename + " line " + str(n) + " format error.\n")
	except:
		pass
		#sys.stderr.write("Cannot process threshold file " + filename + "\n");

	return thresholds

#
#  Locate a threshold in the JSON data, compare it to the given threshold
#
def check_threshold(data, key, fullkey, threshold):
	try:
		d = data[key[0]]
	except:
		sys.stderr.write("health-check JSON data does not have key " + fullkey + "\n")
		return (True, "Attribute not found and ignored")

	key = key[1:]
	if len(key) > 0:
		return check_threshold(d, key, fullkey, threshold)
	else:
		val = float(d)
		if threshold >= val:
			cmp = str(threshold) + " >= " + str(val) 
			return (True, cmp)
		else:	
			cmp = str(threshold) + " < " + str(val) 
			return (False, cmp)

def check_thresholds(procname, data, thresholds):
	print "process: " + procname
	failed = False
	for key in thresholds.keys():
		if key.startswith("health-check"):
			(ret, str) = check_threshold(data, key.split('.'), key, float(thresholds[key]))
			if ret:
				msg = "PASSED"
			else:
				msg = "FAILED"
				failed = True

			sys.stderr.write(msg + ": " + str + ": " + key + "\n")

	return failed

#
#  run health-check on a given process
#
def health_check(pid, procname):
	thresholds = read_threshold(procname)
	#
	#  Can't test without thresholds
	#	
	if len(thresholds) == 0:
		thresholds = read_threshold("default")
		if len(thresholds) == 0:
			sys.stderr.write("No thresholds for process " + procname + "\n")
		else:
			sys.stderr.write("Using default thresholds for process " + procname + "\n")

	duration = default_duration

	if 'duration' in thresholds:
		duration = int(thresholds['duration'])

	filename = "/tmp/health-check-" + str(pid) + ".log"
	cmd = "health-check -c -f -d " + str(duration) + " -w -W -r -p " + str(pid) + " -o " + filename + " > /dev/null"

	try:
		os.system(cmd)
	except:
		sys.stderr.write("Failed to run " + cmd + "\n");
		os._exit(1)

	try:
		f = open(filename, 'r')
		data = json.load(f)
		f.close()
	except:
		sys.syderr.write("Failed to open JSON file " + filename + "\n");
		os._exit(1)
		
	check_thresholds(procname, data, thresholds)



#
#  Start here!
#
if len(sys.argv) < 2:
	sys.stderr.write("Usage: " + sys.argv[0] + " PID\n")
	os._exit(1)

pid = int(sys.argv[1])

try:
	p = psutil.Process(pid)
except:
	sys.stderr.write("Cannot find process with PID " + str(pid) + "\n")
	os._exit(1)

try:
	pgid =  os.getpgid(pid)
except:
	sys.stderr.write("Cannot find pgid on process with PID " + str(pid)  + "\n")
	os._exit(1)

if pgid == 0:
	sys.stderr.write("Cannot run health-check on kernel task with PID " + str(pid) + "\n")
	os._exit(1)

try:
	procname = os.path.basename(p.name)
	if p.name in ignore_procs:
		sys.stderr.write("Cannot run health-check on process " + procname + "\n")
		os._exit(1)
	else:
		#
		#  Did it fail?
		#
		if (health_check(pid, procname)):
			os._exit(1)
		else:
			os._exit(0)
except:
	sys.stderr.write("An execption occurred, failed to test on PID " + str(pid) + "\n")
	sys.exit(1)
