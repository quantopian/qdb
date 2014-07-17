#
# Copyright 2014 Quantopian, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
import os
from textwrap import dedent
from unittest import TestCase

from qdb import Qdb
from qdb.comm import NopCmdManager


class QdbFileCacheTester(TestCase):
    def test_file_cache_from_string(self):
        contents = dedent(
            """\
            line 1
            line 2
            line 3
            line 4
            """
        )
        db = Qdb(cmd_manager=NopCmdManager)
        db.cache_file('file', contents=contents)

        # Check the whole string.
        self.assertEquals(db.get_file('file'), contents[:-1])  # drop '\n'

        for n in xrange(1, 5):
            # Check all the lines.
            self.assertEquals('line %d' % n, db.get_line('file', n))

    def test_file_cache_from_disk(self):
        """
        We must use a file that we know exists, so we will use this one.
        """
        filename = os.path.abspath(__file__)
        db = Qdb(cmd_manager=NopCmdManager)
        db.cache_file(filename)

        with open(filename) as f:
            contents = f.read()[:-1]  # drop '\n'

            # Assert that querying the file works.
            self.assertEquals(db.get_file(filename), contents)

            def infinite_list():
                """
                Generator that yields [1..]
                """
                n = 1
                while True:
                    yield n
                    n += 1

            for n, line in zip(infinite_list(), contents.splitlines()):
                # Iterate over all the lines of the file, asserting that we
                # have saved them correctly.
                self.assertEquals(db.get_line(filename, n), line)
