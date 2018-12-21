#!/usr/bin/env python3

'''Get LAPS password for AD Computers'''
# #################################################################
# This script will allow an admin user with
# the proper domain crednetials to get a LAPS
# password from Active Directory.
# ##################################################################
# Original script by barteardon
# https://github.com/bartreardon/macscripts/blob/master/lapssearch
# Updated script using pyObjC:
# Joshua D. Miller - josh@psu.edu
# The Pennsylvania State University - September 18, 2017
# Updated script for GUI:
# Mike Donovan mike.donovan@killeenisd.org - Killeen ISD - September 28, 2018
# Original UI elements from Bryson Tyrrell's "Craft your own GUI's with Python and Tkinter"
# PSU MacAdmins 2016
# #################################################################

from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute, KERBEROS, MODIFY_REPLACE
import gssapi
import ldap3
import tkinter as tk
import datetime
from os import system
import os
import json

#Path to config File
CWD = os.getcwd()
JSON_CONFIG_FILE_PATH = '%s/%s' % (CWD, 'ad_config.json')

# Dictionary to store ad_config values
CONFIG_PROPERTITIES = {}

# Open ad_config.json, parse values and store in a Dictionary
try:
    with open(JSON_CONFIG_FILE_PATH) as data_file:
        CONFIG_PROPERTITIES = json.load(data_file)
except IOError as e:
    print(e)

# Function for Searching for Computers by Name
def ad_search_for_computers_by_name(computer_name):

    #Load Local AD Config File
    DC_Root = CONFIG_PROPERTITIES['DC_Root']
    DC_Child = CONFIG_PROPERTITIES['DC_Child']
    Path_Root = CONFIG_PROPERTITIES['Path_Root']
    Path_Child = CONFIG_PROPERTITIES['Path_Child']

    srch_base = Path_Child
    cmpPW = ""
    chkStatus = ""
    counter = 1
    while chkStatus == "" and counter < 3:
        #Var for AD Filter
        adFltr = "(&(objectclass=computer)(cn=" + computer_name  + "*))"

        # AD Server
        ms_ad_server = Server(DC_Child, get_info=ALL)

        # AD Connection
        ms_ad_conn = Connection(ms_ad_server, sasl_credentials=(True,), authentication=SASL, sasl_mechanism=KERBEROS)

        if ms_ad_conn.bind():
            ms_ad_conn.search(search_base=srch_base, search_filter=adFltr, search_scope=SUBTREE, attributes=['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'], size_limit=0)
            if ms_ad_conn.entries:
                cmpPW = ms_ad_conn.entries[0]['ms-Mcs-AdmPwd']
                #Check for password value
                if cmpPW:
                    cmpPWExp = str(ms_ad_conn.entries[0]['ms-Mcs-AdmPwdExpirationTime'])
                    dateExp = convertTime(cmpPWExp)
                    chkStatus = "Success"
                else:
                    chkStatus = "No Value"
            else:
                srch_base = Path_Root

            ms_ad_conn.unbind()
            counter += 1
        else:
            chkStatus = "AD bind Fail"

    if chkStatus == "Success":
        return [cmpPW, dateExp]
    else:
        return chkStatus


def expire_AmdPwdExpirationTime(computer_name):

    #Load Local AD Config File
    DC_Root = CONFIG_PROPERTITIES['DC_Root']
    DC_Child = CONFIG_PROPERTITIES['DC_Child']
    Path_Root = CONFIG_PROPERTITIES['Path_Root']
    Path_Child = CONFIG_PROPERTITIES['Path_Child']

    srch_base = Path_Child
    chkStatus = ""
    counter = 1
    while chkStatus == "" and counter < 3:

		#Var for AD Filter
        adFltr = "(&(objectclass=computer)(cn=" + computer_name  + "*))"

		# AD Server
        ms_ad_server = Server(DC_Root, get_info=ALL)

		# AD Connection
		# Perform a reverse DNS lookup to determine the hostname to authenticate against.
        ms_ad_conn = Connection(ms_ad_server, sasl_credentials=(True,), authentication=SASL, sasl_mechanism=KERBEROS)

		# Connect to AD
        if ms_ad_conn.bind():
			#Search AD
            ms_ad_conn.search(search_base=srch_base,
	                         	search_filter=adFltr,
	                         	search_scope=SUBTREE,
	                         	attributes = ALL_ATTRIBUTES,
	                         	size_limit=0)

            if ms_ad_conn.entries:
                ms_ad_dn = ms_ad_conn.entries[0]['distinguishedName']
                chkStatus = "Success"
            else:
                srch_base = Path_Root

            ms_ad_conn.modify(str(ms_ad_dn),{'ms-Mcs-AdmPwdExpirationTime': (MODIFY_REPLACE, ['126227988000000000'])})
            modify_result = ms_ad_conn.result['description']

			#Unbind connection to AD
            ms_ad_conn.unbind()
            counter += 1
        else:
            chkStatus = "Fail"

        if modify_result == 'success':
            return True
        else:
            return False

def update_pref_file(dR, dC, pR, pC):

    #Path to config File
    CWD = os.getcwd()
    JSON_CONFIG_FILE_PATH = '%s/%s' % (CWD, 'ad_config.json')

    # Set new data to original file data
    data = CONFIG_PROPERTITIES

    # Update data with new values
    data['DC_Root'] = dR
    data['DC_Child'] = dC
    data['Path_Root'] = pR
    data['Path_Child'] = pC

    # Open ad_config.json, parse values and store in a Dictionary
    try:
        with open(JSON_CONFIG_FILE_PATH, 'w') as outfile:
            json.dump(data, outfile)
    except IOError as e:
        print(e)

def preferences_edit():

    def call_update():
        dRoot = dc_root_input.get()
        dChild = dc_child_input.get()
        pRoot = path_root_input.get()
        pChild = path_child_input.get()

        update_pref_file(dRoot, dChild, pRoot, pChild)
        preferences.destroy()

    preferences = tk.Tk()
    width_of_window = 350
    height_of_window = 300

    screen_width = preferences.winfo_screenwidth()
    screen_height = preferences.winfo_screenheight()

    x_coordinate = (screen_width/2) - (width_of_window/2)
    y_coordinate = (screen_height/2) - (height_of_window/2)

    preferences.geometry("%dx%d+%d+%d" % (width_of_window, height_of_window, x_coordinate, y_coordinate))

    preferences.wm_title("macOSLAPS preferences")

    dialog_frame = tk.Frame(preferences)
    dialog_frame.pack(padx=20, pady=15, anchor='w')

    tk.Label(dialog_frame, text='DC Root').grid(row=0, column=0, sticky='w')
    dc_root_input = tk.Entry(dialog_frame, background='white', width=24)
    dc_root_input.grid(row=1, column=0, sticky='w')
    dc_root_input.insert(0, CONFIG_PROPERTITIES['DC_Root'])

    tk.Label(dialog_frame, text='DC Child').grid(row=2, column=0, sticky='w')
    dc_child_input = tk.Entry(dialog_frame, background='white', width=24)
    dc_child_input.grid(row=3, column=0, sticky='w')
    dc_child_input.insert(0, CONFIG_PROPERTITIES['DC_Child'])

    tk.Label(dialog_frame, text='Path Root').grid(row=4, column=0, sticky='w')
    path_root_input = tk.Entry(dialog_frame, background='white', width=24)
    path_root_input.grid(row=5, column=0, sticky='w')
    path_root_input.insert(0, CONFIG_PROPERTITIES['Path_Root'])

    tk.Label(dialog_frame, text='Path Child').grid(row=6, column=0, sticky='w')
    path_child_input = tk.Entry(dialog_frame, background='white', width=24)
    path_child_input.grid(row=7, column=0, sticky='w')
    path_child_input.insert(0, CONFIG_PROPERTITIES['Path_Child'])

    button_frame = tk.Frame(preferences)
    button_frame.pack(padx=20, pady=15, anchor='e')

    update_btn = tk.Button(button_frame, text="Update", command = lambda: call_update()).grid(row=0, column=0, sticky='e')

    ok_btn = tk.Button(button_frame, text="Okay", command = preferences.destroy).grid(row=0, column=1, sticky='e')

    preferences.mainloop()


def about_dialog():
    root.tk.call('tk::mac::standardAboutPanel')


def popupAlert(msg):
    popup = tk.Tk()
    width_of_window = 350
    height_of_window = 180

    screen_width = popup.winfo_screenwidth()
    screen_height = popup.winfo_screenheight()

    x_coordinate = (screen_width/2) - (width_of_window/2)
    y_coordinate = (screen_height/2) - (height_of_window/2)

    popup.geometry("%dx%d+%d+%d" % (width_of_window, height_of_window, x_coordinate, y_coordinate))

    popup.wm_title("macOSLAPS")
    laps = tk.Label(popup, text=msg, font='System 14 bold')
    laps.pack(side="top", fill="x", pady=10)
    B1 = tk.Button(popup, text="Okay", command = popup.destroy)
    B1.pack()
    popup.geometry("350x150")
    popup.mainloop()

def convertTime(winTime):
    # This portion from a larger script from:
    # Author: Joakim Svendsen, "joakimbs" using Google's mail services.
    # Copyright (c) 2013. Svendsen Tech. All rights reserved.
    # BSD 3-clause license.
    seconds = int(winTime) / 10000000
    epoch = seconds - 11644473600

    dt = datetime.datetime(2000, 1, 1, 0, 0, 0)
    expDate = dt.fromtimestamp(epoch)
    return expDate

def update_statusbar(self, msg_txt):
    self.messageVar.set(msg_txt)
    self.messageLabel.update()


class lapsUI(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.pack()
        self.master.title("macOSLAPS UI")
        self.master.resizable(False, False)
        self.master.tk_setPalette(background='#ececec')

        self.master.protocol('WM_DELETE_WINDOW', self.click_exit)
        self.master.bind('<Return>', self.click_search)
        self.master.bind('<Escape>', self.click_exit)

        width_of_window = 350
        height_of_window = 270

        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()

        x_coordinate = (screen_width/2) - (width_of_window/2)
        y_coordinate = (screen_height/2) - (height_of_window/2)

        self.master.geometry("%dx%d+%d+%d" % (width_of_window, height_of_window, x_coordinate, y_coordinate))
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)

        # Use application about info not Tkinter
        self.master.createcommand('tkAboutDialog', about_dialog)

        # Use custom preferences popup
        self.master.createcommand('tk::mac::ShowPreferences', preferences_edit)

        dialog_frame = tk.Frame(self)
        dialog_frame.pack(padx=20, pady=15, anchor='w')

        tk.Label(dialog_frame, text='ComputerName').grid(row=0, column=0, sticky='w')
        self.cmp_input = tk.Entry(dialog_frame, background='white', width=24)
        self.cmp_input.grid(row=1, column=0, sticky='w')
        self.cmp_input.focus_set()

        self.srch_btn = tk.Button(dialog_frame, text='Search', height=2, width=6, command=self.click_search)
        self.srch_btn.grid(row=1, column=1, sticky='w')

        tk.Label(dialog_frame, text='Password').grid(row=3, column=0, sticky='w')
        self.pwd_display = tk.Entry(dialog_frame, background='#ececec', width=24)
        self.pwd_display.grid(row=4, column=0, sticky='w')

        tk.Label(dialog_frame, text='Password Expires').grid(row=6, column=0, sticky='w')
        self.exp_display = tk.Entry(dialog_frame, background='#ececec', width=24)
        self.exp_display.grid(row=7, column=0, sticky='w')

        tk.Button(dialog_frame, text='Expire', height=2, width=6, command=self.click_expire).grid(row=7, column=1, sticky='w')

        button_frame = tk.Frame(self)
        button_frame.pack(padx=20, pady=(0, 15), anchor='e')

        tk.Button(button_frame, text='Exit', height=2, width=6, command=self.click_exit).grid(row=0, column=1, sticky='w')

        status_frame = tk.Frame(self)
        status_frame.pack(side='left', anchor='e')

        # These variables are for the message line in our GUI that changes both text
        # and color based upon success or error messages
        self.messageColor = tk.StringVar()
        self.messageColor.set("red")

        self.messageVar = tk.StringVar()
        self.messageVar.set("")

        self.messageLabel = tk.Label(status_frame, textvariable=self.messageVar, font=("Helvetica Neue", 14, "italic"), fg=self.messageColor.get())
        self.messageLabel.config(height=3)
        self.messageLabel.place(x=status_frame.winfo_width()/2, y=status_frame.winfo_height()/2, anchor="center")
        self.messageLabel.pack()


    def click_search(self, event=None):

        computer_name = self.cmp_input.get()
        if computer_name == "":
            update_statusbar(self, "Missing ComputerName")
        else:
            self.pwd_display.delete(0, tk.END)
            self.exp_display.delete(0, tk.END)

            result = ad_search_for_computers_by_name(computer_name)

            if result == "":
                update_statusbar(self, "Computer Not Found")
            elif result == "AD bind Fail":
                update_statusbar(self, "AD connection Failure")
            elif result == "No Value":
                update_statusbar(self, "No Password Value Found")
            else:
                update_statusbar(self, "")
                self.pwd_display.insert(0, result[0])
                self.exp_display.insert(0, result[1])


    def click_expire(self, event=None):

        computer_name = self.cmp_input.get()
        if computer_name == "":

            update_statusbar(self, "Missing ComputerName")
        else:
            if expire_AmdPwdExpirationTime(computer_name):
                popupAlert("\nForce Expire time Set. Keep in mind that\nmacOSLAPS will need to run on the system\nbefore the password is changed.")
            else:
                update_statusbar(self, "Expire Attempt Failed")


    def click_exit(self, event=None):
        self.master.destroy()


if __name__ == '__main__':

    root = tk.Tk()
    app = lapsUI(root)
    app.mainloop()
