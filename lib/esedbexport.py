'''
        .1111...          | Title: esedbextract.py
    .10000000000011.   .. | Author: Oliver Morton
 .00              000...  | Email: grimhacker@grimhacker.com
1                  01..   | Description:
                    ..    | executes a esedb as a subprocess
                   ..     |
GrimHacker        ..      |
                 ..       |
grimhacker.com  ..        |
@_grimhacker   ..         |
--------------------------------------------------------------------------------
Created on 5 Mar 2014
@author: GrimHacker
Part of esedbxtract.
esedbxtract extracting hashes from ntds.dit and system files.
    Copyright (C) 2014  Oliver Morton

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import logging
import os
from subprocess import DEVNULL, STDOUT, check_call
from command import Command


# TODO: Lots more exception handling.

class Error(Exception):
    """Base class for errors in this module."""


class SubprocessError(Error):
    """Subprocess Error"""
    def __init__(self, msg):
        """Exception raised for errors in subprocesses.

        Attributes:
            msg - explanation of error
        """


class ESEDBExport(object):
    """Execute ESEDBExtract as a subprocess to retrieve datatable and linktable."""
    def __init__(self, ntds, datatable=None, linktable=None, exe="esedbexport", workdir="."):
        """Initialise ESEDBExtract object."""
        self.log = logging.getLogger(__name__)
        self._ntds = ntds
        self._exe = exe
        self._datatable = datatable
        self._linktable = linktable
        self._workdir = workdir

    class ExportTable(Command):
        """Execute ESEDBExtract as subprocess to retrieve a table."""
        def __init__(self, ntds, table, exe="esedbexport", workdir="."):
            """Initialise"""
            try:
                super(ESEDBExport.ExportTable, self).__init__()
            except Exception as e:
                err = "Error initialising parent class of Export Table. {0}".format(e)
                raise Exception(err)  # TODO: handle here
            self.log = logging.getLogger(__name__)
            self._ntds = ntds
            self._exe = exe
            self._table = table
            self._table_name = None
            self._workdir = workdir
            self.log.debug("end of ExportTable init")

        def _get_ntds(self):
            """Return ntds.dit file name."""
            return self._ntds

        def _get_exe(self):
            """Return esedbexport executable filename."""
            return self._exe

        def _get_table(self):
            """Return table to extract."""
            return self._table

        def _get_table_name(self):
            """Return table filename."""
            return self._table_name

        def _get_workdir(self):
            """Return working directory."""
            return self._workdir

        def _stdout(self, out):
            """Filter output of esedbexport. Overrides Command._stdout()"""
            if not out.endswith("\n"):
                out.append("\n")
            for line in out.split("\n"):
                if line == "":
                    pass  # don't print blank lines
                else:
                    self.log.debug("{0} extraction: {1}".format(self._get_table(), line))
                    if "Exporting" in line:
                        num = int(line.split(" ")[2]) - 1  # need to check this works consistently.
                                                           # (filename ends in this number but it seems to be
                                                           # 1 less than the table number in stdout.
                        self._table_name = os.path.join(self._get_workdir(),
                                                        "{0}.export".format(self._get_table()),
                                                        "{0}.{1}".format(self._get_table(),
                                                                         num))
                        #table_name = "{workdir}/{table}.export/{table}.{num}".format(workdir=self._get_workdir(), table=self._table, num=num)
                        self.log.debug("{0} extraction: table_name: {1}".format(self._get_table(), self._get_table_name()))

        def _build_cmd(self, exe, table, source):
            """Build command"""
            self.log.debug("building command")
            directory = os.path.join("{0}".format(self._get_workdir()), table)
            cmd = ["/usr/local/bin/esedbexport", "-t", "./"+table, "-T", table, source]
            cmd = ' '.join(cmd)+' > /dev/null 2>&1'
            #cmd = ' '.join(cmd)
            return cmd

        def run(self):
            """Run extraction"""
            cmd = self._build_cmd(source=self._get_ntds(),
                                  table=self._get_table(),
                                  exe=self._get_exe())
            try:
                #print("[+] Executing command : "+str(cmd))
                os.system( cmd )
                success = True
                return (success, self._get_table_name())
            except Exception as e:
                self.log.critical("Failed to execute command. {0}".format(e))
                raise  # see if higher level can deal with it

    def _get_ntds(self):
        """Return ntds.dit file name."""
        return self._ntds

    def _get_exe(self):
        """Return esedbexport executable filename."""
        return self._exe

    def _get_workdir(self):
        """Return working directory."""
        return self._workdir

    def get_datatable(self):
        """Return datatable"""
        return self._datatable

    def get_linktable(self):
        """Return linktable"""
        return self._linktable

    def extract(self):
        """Extract tables"""
        if self.get_datatable() is None:
            self.log.debug("setting up datatable extractor")
            datatable_extractor = self.ExportTable(ntds=self._get_ntds(),
                                                   table="datatable",
                                                   exe=self._get_exe(),
                                                   workdir=self._get_workdir())
            self.log.debug("running datatable extractor")
            status, self._datatable = datatable_extractor.run()
            self.log.debug("datatable extractor exit status: {0} table: {1}".format(status, self.get_datatable()))
            if status:
                self.log.debug("datatable extracted to {0}".format(self.get_datatable()))
            else:
                raise SubprocessError("Failed to export datatable.")

        if self.get_linktable() is None:
            self.log.debug("setting up link_table extractor")
            linktable_extractor = self.ExportTable(ntds=self._get_ntds(),
                                                   table="link_table",
                                                   exe=self._get_exe(),
                                                   workdir=self._get_workdir())
            self.log.debug("running link_table extractor")
            status, self._linktable = linktable_extractor.run()
            self.log.debug("linktable extractor exit status: {0} table: {1}".format(status, self.get_linktable()))
            if status:
                self.log.debug("linktable extracted to {0}".format(self.get_linktable()))
            else:
                raise SubprocessError("Failed to export linktable.")

        self.log.debug("extract() finished")


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s", level=logging.DEBUG)
    logger = logging.getLogger("")
    e = ESEDBExport(ntds=r"/home/pi/dshashes/ntds.dit", exe=r"/home/pi/libesedb-20120102/esedbtools/esedbexport")
    e.extract()
    logger.info("exiting")
