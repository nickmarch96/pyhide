#!/usr/bin/env python3

import PySimpleGUI as sg
import pyhide
import os

sg.theme("Light Grey 1")


error_len = 30
BAD_CHARS = "/\\<>:\"|?*"

def gen_layout():
	title_text = sg.Text("PyHide GUI Wrapper for PyHide {}".format(pyhide.VERSION))

	path_text = sg.Text("Target")
	target_path = sg.InputText(key="target_path", enable_events=True, tooltip="File or folder to be encrypted.")
	browse = sg.FileBrowse(target="target_path")

	path_error = sg.Text(size=(error_len, 1), text_color="red", key="path_error", visible=False)

	password_text = sg.Text("Password")
	password = sg.InputText(key="password", password_char="*", tooltip="Password to encrypt with.")

	password_error = sg.Text(size=(error_len, 1), text_color="red", key="password_error", visible=False)

	con_password_text = sg.Text("Confirm Password")
	confirm_password = sg.InputText(key="confirm_password", password_char="*", tooltip="Safety Mechanism ;)")

	con_password_error = sg.Text(size=(error_len, 1), text_color="red", key="con_password_error", visible=False)

	filename_text = sg.Text("Filename")
	fname_override_check = sg.Checkbox("Override", key="fname_override_check", enable_events=True)
	fname_override = sg.InputText(key="fname_override", disabled=True, tooltip="The name of the file upon delivery and decryption.")

	fname_error = sg.Text(size=(error_len, 1), text_color="red", key="fname_error", visible=False)

	payload_text = sg.Text("Filename")
	payload_name = sg.InputText("payload.py", key="payload_name", tooltip="The name of the encrypted python script.")

	payload_error = sg.Text(size=(error_len, 1), text_color="red", key="payload_error", visible=False)

	sec_store = sg.Checkbox("Secure Storage", key="sec_store", tooltip="Deletes the unencrypted original.")

	encrypt = sg.Button("Encrypt", key="encrypt")

	status = sg.Text("Status: Waiting for user input...", key="status")

	return [
		[title_text],
		[path_text],
		[target_path, browse],
		[path_error],
		[password_text],
		[password],
		[password_error],
		[con_password_text],
		[confirm_password],
		[con_password_error],
		[filename_text],
		[fname_override, fname_override_check],
		[fname_error],
		[payload_text],
		[payload_name],
		[payload_error],
		[sec_store],
		[encrypt],
		[status]
		]

def set_error(elem, err):
	elem.Update(value=err)
	elem.Update(visible=True)

def clear_error(elem):
	elem.Update(visible=False)


def check_errors(w):
	target_file = w["target_path"].Get()
	password = w["password"].Get()
	confirm_password = w["confirm_password"].Get()
	fname = w["fname_override"].Get()
	fname_override = w["fname_override_check"].Get()
	payload = w["payload_name"].Get()
	sec_store = w["sec_store"].Get()

	if target_file == "":
		set_error(w["path_error"], "No target path set!")
		return True

	elif not os.path.exists(target_file):
		set_error(w["path_error"], "Target file does not exist!")
		return True
	else:
		clear_error(w["path_error"])

	if password == "":
		set_error(w["password_error"], "No password supplied!")
		return True
	else:
		clear_error(w["password_error"])

	if password != confirm_password:
		set_error(w["con_password_error"], "Passwords do not match!")
		return True
	else:
		clear_error(w["con_password_error"])

	if fname_override:
		for c in BAD_CHARS:
			if c in fname:
				set_error(w["fname_error"], "Invalid Character '{}' in filename!".format(c))
				return True
		clear_error(w["fname_error"])

	for c in BAD_CHARS:
		if c in payload:
			set_error(w["payload_error"], "Invalid Character '{}' in payload!".format(c))
			return True
	clear_error(w["payload_error"])

	return False



w = sg.Window(title="Howdy", layout=gen_layout())

while True:
	event, val = w.Read()

	if event == "fname_override_check":
		if val["fname_override_check"]:
			w["fname_override"].Update(disabled=False)
		else:
			filename = os.path.basename(os.path.normpath(val["target_path"]))
			w["fname_override"].Update(disabled=True)
			w["fname_override"].Update(value=filename)
		w.Refresh()

	elif event == "target_path":
		filename = os.path.basename(os.path.normpath(val["target_path"]))
		w["fname_override"].Update(value=filename)

	elif event == "encrypt":
		target_file = w["target_path"].Get()
		pwd = w["password"].Get()
		fname = w["fname_override"].Get()
		payload = w["payload_name"].Get()
		sec_store = w["sec_store"].Get()

		w["status"].Update(value="Status: Validating inputs...")
		if check_errors(w):
			w["status"].Update(value="Status: Waiting for user input...")
			continue

		w["status"].Update(value="Status: Generating Keys...")
		e = pyhide.PyHide(pwd)

		w["status"].Update(value="Status: Encrypting File...")
		script = e.create(target_file, fname)

		w["status"].Update(value="Status: Saving File...")
		with open(payload, "w") as o:
			o.write(script)

		if sec_store:
			w["status"].Update(value="Status: Deleting Original...")
			os.remove(target_file)

		w["status"].Update(value="Status: Done.")

	elif event == sg.WIN_CLOSED:
		break

	else:
		print(event, val)
w.close()