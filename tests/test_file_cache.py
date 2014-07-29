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
from itertools import count, izip
from textwrap import dedent
from unittest import TestCase

from qdb import Qdb
from qdb.comm import NopCommandManager

from tests import fix_filename


class QdbFileCacheTester(TestCase):
    def test_file_cache_from_string(self):
        """
        Asserts that manual caching from a string works.
        """
        contents = dedent(
            """\
            line 1
            line 2
            line 3
            line 4
            """
        )
        db = Qdb(cmd_manager=NopCommandManager)
        db.cache_file('file', contents=contents)

        # Check the whole 'file'.
        self.assertEquals(db.get_file('file'), contents[:-1])  # drop '\n'

        for n in xrange(1, 5):
            # Check all the lines.
            self.assertEquals('line %d' % n, db.get_line('file', n))

    def test_file_cache_from_disk(self):
        """
        Asserts that the disk caching works.
        """
        # We will use this file, as it is the only file we know that exists.
        # The first time this is run after a change, __file__ will point to
        # the source code file; however, if we run this twice in a row, it
        # points to the byte-compiled file.
        filename = fix_filename(__file__)
        db = Qdb(cmd_manager=NopCommandManager)
        db.cache_file(filename)

        with open(filename) as f:
            contents = f.read()[:-1]  # Drop the last newline.

            # Assert that querying the entire file works.
            self.assertEquals(db.get_file(filename), contents)

            for n, line in izip(count(start=1), contents.splitlines()):
                # Iterate over all the lines of the file, asserting that we
                # have saved them correctly. This also asserts that the line
                # indexing is working as intended.
                self.assertEquals(db.get_line(filename, n), line)
