# -*- coding: utf-8 -*-
# ********************************************************************
# ZYNTHIAN PROJECT: Zynthian Web Configurator
#
# Login Handler
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
import hmac
import logging
import tornado.web

# ------------------------------------------------------------------------------
# Login Handler
# ------------------------------------------------------------------------------
#
# Desktop-port variant: upstream authenticates via PAM against the *system*
# root account, which assumes webconf runs as root on real Zynthian hardware.
# In the desktop Docker image and the desktop native install, the process
# deliberately does not run as root, so PAM auth against root's password
# isn't available (and wouldn't be desirable - that'd be the host machine's
# real root password). Authenticate against ZYNTHIAN_WEBCONF_PASSWORD
# instead, set by whatever launches this process. If that env var isn't
# set, login is refused outright rather than silently accepting any/no
# password.


class LoginHandler(tornado.web.RequestHandler):

    def get(self, errors=None):
        self.render("config.html", info={}, body="login_block.html",
                    title="Login", config=None, errors=errors)

    def post(self):
        expected_password = os.environ.get("ZYNTHIAN_WEBCONF_PASSWORD")
        supplied_password = self.get_argument("PASSWORD", "")
        if expected_password and hmac.compare_digest(supplied_password, expected_password):
            self.set_secure_cookie("user", "root", expires_days=3650)
            if self.get_argument("next", ""):
                self.redirect(self.get_argument("next"))
            else:
                self.redirect("/")
        else:
            logging.info("Incorrect password")
            self.get({"PASSWORD": "Incorrect Password"})


class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_cookie('user')
        self.redirect(self.get_argument('next', '/'))
