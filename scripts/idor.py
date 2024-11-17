# !/usr/bin/env python3

import argparse, urllib.parse

def is_numeric(value):
	success = True
	try:
		float(value)
	except Exception:
		success = False
	return success

def json(name, v1, v2):
	name = f"\"{name}\":"
	idors = [
		f"{name}\"{v1},{v2}\"",
		f"{name}\"{v1} {v2}\"",
		f"{name}\"{v1}\",{name}\"{v2}\""
	]
	if is_numeric(v1) and is_numeric(v2):
		idors.append(f"{name}{v1},{name}{v2}")
	if is_numeric(v1):
		idors.append(f"{name}{v1},{name}\"{v2}\"")
	if is_numeric(v2):
		idors.append(f"{name}\"{v1}\",{name}{v2}")
	for idor in idors:
		print(idor)
	return idors

def json_brackets(name, v1, v2):
	name = f"\"{name}\":"
	idors = []
	for placeholder in ["(X)", "[X]", "{X}"]:
		idors.append(name + placeholder.replace("X", f"\"{v1}\",\"{v2}\""))
		if is_numeric(v1) and is_numeric(v2):
			idors.append(name + placeholder.replace("X", f"{v1},{v2}"))
		if is_numeric(v1):
			idors.append(name + placeholder.replace("X", f"{v1},\"{v2}\""))
		if is_numeric(v2):
			idors.append(name + placeholder.replace("X", f"\"{v1}\",{v2}"))
	for idor in idors:
		print(idor)
	return idors

def quote(value):
	return urllib.parse.quote_plus(value)

def query_string(name, v1, v2):
	idors = [
		f"{name}={quote(v1)},{quote(v2)}",
		f"{name}={quote(v1)}%20{quote(v2)}",
		f"{name}={quote(v1)}&{name}={quote(v2)}",
		f"{name}[]={quote(v1)}&{name}[]={quote(v2)}"
	]
	for idor in idors:
		print(idor)
	return idors

def write_file(out, results):
	with open(out, "w") as stream:
		for entry in results:
			stream.write(f"{entry}\n")
	print(f"Results have been saved to '{out}'")

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-n", "--parameter-name", required = True, type = str, default = "")
	parser.add_argument("-i", "--initial-value", required = True, type = str, default = "")
	parser.add_argument("-t", "--target-value", required = True, type = str, default = "")
	parser.add_argument("-s", "--scope", required = False, type = str.lower, default = "all", choices = ["qs", "json", "all"])
	parser.add_argument("-o", "--out", required = False, type = str, default = "")
	args = parser.parse_args()

	name = args.parameter_name
	initial = args.initial_value
	target = args.target_value
	scope = args.scope
	out = args.out

	results = []

	if scope in ["json", "all"]:
		results.extend(json(name, target, initial))
		results.extend(json(name, initial, target))

		results.extend(json_brackets(name, target, initial))
		results.extend(json_brackets(name, initial, target))

	if scope in ["qs", "all"]:
		results.extend(query_string(name, target, initial))
		results.extend(query_string(name, initial, target))

	if out:
		write_file(out, results)
