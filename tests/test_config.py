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
# limitations under the License.
import os
from tempfile import mkdtemp, NamedTemporaryFile
from textwrap import dedent
from unittest import TestCase

from qdb.config import QdbConfig


class QdbConfigTester(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contents = dedent(
            """\
            # FOR TESTING PURPOSES
            config = QdbConfig(**{
                'host': 'user-set',
                'port': 'user-set',
                'auth_msg': 'user-set',
                'default_file': 'user-set',
                'default_namespace': 'user-set',
                'eval_fn': 'user-set',
                'exception_serializer': 'user-set',
                'skip_fn': 'user-set',
                'pause_signal': 'user-set',
                'redirect_output': 'user-set',
                'retry_attepts': 'user-set',
                'uuid': 'user-set',
                'cmd_manager': 'user-set',
                'green': 'user-set',
                'repr_fn': 'user-set',
                'log_file': 'user-set',
                'execution_timeout': 'user-set',
            })
            """
        )
        cls.old_home = os.environ['HOME']
        cls.home = mkdtemp()
        os.environ['HOME'] = cls.home
        cls.profile_path = os.path.join(cls.home, '.qdb')
        cls.profile = open(cls.profile_path, 'w+')
        cls.profile.write(cls.contents)
        cls.profile.flush()

        cls.expected = QdbConfig(
            **{k: 'user-set' for k in QdbConfig.DEFAULT_OPTIONS}
        )

    @classmethod
    def teardown(cls):
        cls.profile.close()
        os.remove(cls.profile_path)
        os.rmdir(cls.home)
        os.environ['HOME'] = cls.old_home

    def _test_file(self, files=None, use_local=False, use_profile=False):
        """
        Tests reading a local file.
        """
        config = QdbConfig.get_config(
            files=files, use_local=use_local, use_profile=use_profile,
        )

        self.assertEqual(self.expected._asdict(), config._asdict())

    def test_local(self):
        """
        Tests reading the local file.
        """
        cwd = os.getcwd()
        os.chdir(self.home)
        try:
            self._test_file(use_local=True)
        finally:
            os.chdir(cwd)

    def test_profile(self):
        """
        Tests reading the profile file.
        """
        self._test_file(use_profile=True)

    def test_extra(self):
        """
        Tests reading an extra config file.
        """
        with NamedTemporaryFile(dir=self.home) as t:
            t.write(self.contents.encode('utf-8'))
            t.flush()

            self._test_file(files=(t.name,))

    def test_extra_arg(self):
        """
        Tests that passing an extra argument gets caught.
        """
        extra_arg = 'extra'
        while extra_arg in QdbConfig.DEFAULT_OPTIONS:
            # Assert athat extra_arg is NOT a valid option.
            extra_arg += '_'

        with self.assertRaisesRegexp(TypeError, extra_arg):
            QdbConfig.get_config({extra_arg: None})
