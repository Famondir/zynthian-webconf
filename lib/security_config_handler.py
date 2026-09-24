# -*- coding: utf-8 -*-
# ********************************************************************
# ZYNTHIAN PROJECT: Zynthian Web Configurator
#
# Security Configuration Handler
#
# Copyright (C) 2017 Fernando Moyano <jofemodo@zynthian.org>
#
# ********************************************************************
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# For a full copy of the GNU General Public License see the LICENSE.txt file.
#
# ********************************************************************

import os
import re
import logging
import tornado.web
from subprocess import check_output

from lib.zynthian_config_handler import ZynthianConfigHandler

# ------------------------------------------------------------------------------
# System Menu
# ------------------------------------------------------------------------------


class SecurityConfigHandler(ZynthianConfigHandler):

    @staticmethod
    def get_host_name():
        with open("/etc/hostname") as f:
            return f.readline()

    @staticmethod
    def get_public_key():
        try:
            with open("/etc/ssh/ssh_host_rsa_key.pub") as f:
                return f.readline()
        except:
            # Handle missing file
            return None

    @tornado.web.authenticated
    def get(self, errors=None):
        # Get Hostname
        config = {
            'CURRENT_PASSWORD': {
                'type': 'password',
                'title': 'Current password',
                'value': '*'
            },
            'PASSWORD': {
                'type': 'password',
                'title': 'Password',
                'value': '*'
            },
            'REPEAT_PASSWORD': {
                'type': 'password',
                'title': 'Repeat password',
                'value': '*'
            },
            'HOSTNAME': {
                'type': 'text',
                'title': 'Hostname',
                'value': SecurityConfigHandler.get_host_name(),
                'advanced': True
            },
            'REGENERATE_KEYS': {
                'type': 'button',
                'title': 'Regenerate Keys',
                'script_file': 'regenerate_keys.js',
                'button_type': 'button',
                'class': 'btn-warning btn-block',
                'advanced': True
            },
            """
            'PUBLIC_KEY': {
                'type': 'text',
                'title': 'Public Key',
                'value': SecurityConfigHandler.get_public_key(),
                'advanced': True,
                'disabled': True
            },
            """
            '_command': {
                'type': 'hidden',
                'value': ''
            }
        }
        super().get("Security/Access", config, errors)

    @tornado.web.authenticated
    def post(self):
        params = tornado.escape.recursive_unicode(self.request.arguments)
        logging.debug(f"COMMAND: {params['_command'][0]}")
        if params['_command'][0] == "REGENERATE_KEYS":
            cmd = os.environ.get('ZYNTHIAN_SYS_DIR') + "/sbin/regenerate_keys.sh"
            check_output(cmd, shell=True)
            self.redirect('/sys-reboot')
        else:
            errors = self.update_system_config(params)
            self.get(errors)

    def update_system_config(self, config):
        # Desktop-port variant: upstream re-authenticates via PAM against the
        # system root password here, then also rewrites the VNC/WIFI-hotspot/
        # filebrowser passwords and the system account password - none of
        # which apply to the desktop dev container/native install (no PAM
        # root account in play, no WIFI hotspot, no guaranteed filebrowser
        # service). The session is already `@tornado.web.authenticated`, so
        # skip the redundant re-auth and simply refuse password changes here;
        # the login password is set via ZYNTHIAN_WEBCONF_PASSWORD by whatever
        # launched this process instead.
        if len(config['PASSWORD'][0]) > 0:
            return {'PASSWORD': "Password changes aren't supported in this environment - set ZYNTHIAN_WEBCONF_PASSWORD instead"}

        # Update Hostname
        newHostname = config['HOSTNAME'][0]

        try:
            with open("/etc/hostname", 'r') as f:
                previousHostname = f.readline()
                f.close()
        except:
            previousHostname = ''

        if previousHostname != newHostname:
            with open("/etc/hostname", 'w') as f:
                f.write(newHostname)
                f.close()

            with open("/etc/hosts", "r+") as f:
                contents = f.read()
                # contents = contents.replace(previousHostname, newHostname)
                contents = re.sub(r"127\.0\.1\.1.*$", "127.0.1.1\t{}".format(newHostname), contents)
                f.seek(0)
                f.truncate()
                f.write(contents)
                f.close()

            check_output(["hostnamectl", "set-hostname", newHostname])

            try:
                check_output(f"nmcli con modify zynthian-ap wifi.ssid \"{newHostname}\"", shell=True)
            except Exception as e:
                logging.error(f"Can't set WIFI HotSpot name! => {e}")
                return {'HOSTNAME': "Can't set WIFI HotSpot name!"}

            # self.reboot_flag=True
