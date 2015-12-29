#!/usr/bin/env python2.7
# -*-coding=utf-8 -*-

__author__ = 'yin'

import os
import ConfigParser
import logging


class Configure():
    def __init__(self, fn=0, ini_file='function.ini'):
        self._function = fn
        self._ini_file = ini_file

    def read_config(self):
        if not os.path.exists(self._ini_file):
            logging.error('config %s does not exsit' % self._ini_file)
            return

        cf = ConfigParser.ConfigParser()
        cf.read(self._ini_file)
        secs = cf.sections()

        for sec in secs:
            opts = cf.options(sec)
            if self._function in opts:
                return sec
        return ''

    def get_port(self):
        section = self.read_config()
        if section == 'erp':
            return 25377
        elif section == 'app':
            return 3050
        elif section == 'box':
            return 58849
        else:
            return 3050